"""
fl_trainer.py
=============
Layer 2 of the full pipeline.
Runs federated learning across slice datasets using Flower.
Saves the aggregated global model to models/federated_model.pt
"""

import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from collections import OrderedDict
from typing import List, Tuple, Dict
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, classification_report
from torch.utils.data import DataLoader, TensorDataset
import flwr as fl
from flwr.common import Metrics

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "data_dir":       "data",
    "model_dir":      "models",
    "model_path":     "models/federated_model.pt",
    "input_dim":      20,           # must match data_pipeline.py feature count
    "hidden_dims":    [128, 64, 32],
    "dropout":        0.3,
    "learning_rate":  1e-3,
    "local_epochs":   5,
    "batch_size":     64,
    "test_split":     0.2,
    "num_rounds":     10,
    "min_clients":    2,
    "dp_epsilon":     None,         # set to 1.0 to enable DP-SGD (needs opacus)
    "dp_max_grad_norm": 1.0,
    "random_seed":    42,
}

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ─────────────────────────────────────────────────────────────
# MODEL
# ─────────────────────────────────────────────────────────────

class SliceSecurityNet(nn.Module):
    def __init__(self, input_dim: int, hidden_dims: List[int],
                 num_classes: int = 2, dropout: float = 0.3):
        super().__init__()
        layers = []
        in_d = input_dim
        for h in hidden_dims:
            layers += [nn.Linear(in_d, h), nn.BatchNorm1d(h),
                       nn.ReLU(), nn.Dropout(dropout)]
            in_d = h
        layers.append(nn.Linear(in_d, num_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


def get_model() -> SliceSecurityNet:
    return SliceSecurityNet(
        CFG["input_dim"], CFG["hidden_dims"], dropout=CFG["dropout"]
    )

# ─────────────────────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────────────────────

def load_slice_data(csv_path: str) -> Tuple[DataLoader, DataLoader]:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    y = df["label"].values.astype(int)
    X = df.drop(columns=["label"]).values.astype(np.float32)

    # Pad / truncate to expected input_dim
    if X.shape[1] < CFG["input_dim"]:
        pad = np.zeros((X.shape[0], CFG["input_dim"] - X.shape[1]), dtype=np.float32)
        X = np.hstack([X, pad])
    elif X.shape[1] > CFG["input_dim"]:
        X = X[:, :CFG["input_dim"]]

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=CFG["test_split"], stratify=y,
        random_state=CFG["random_seed"]
    )

    def to_loader(Xd, yd, shuffle):
        ds = TensorDataset(
            torch.tensor(Xd, dtype=torch.float32),
            torch.tensor(yd, dtype=torch.long)
        )
        return DataLoader(ds, batch_size=CFG["batch_size"], shuffle=shuffle)

    return to_loader(X_tr, y_tr, True), to_loader(X_te, y_te, False)

# ─────────────────────────────────────────────────────────────
# TRAINING HELPERS
# ─────────────────────────────────────────────────────────────

def train(model: nn.Module, loader: DataLoader, epochs: int) -> float:
    model.to(DEVICE).train()
    optimizer = torch.optim.Adam(model.parameters(), lr=CFG["learning_rate"])

    if CFG["dp_epsilon"]:
        try:
            from opacus import PrivacyEngine
            pe = PrivacyEngine()
            model, optimizer, loader = pe.make_private_with_epsilon(
                module=model, optimizer=optimizer, data_loader=loader,
                epochs=epochs, target_epsilon=CFG["dp_epsilon"],
                target_delta=1e-5, max_grad_norm=CFG["dp_max_grad_norm"]
            )
        except ImportError:
            print("  [warn] opacus not installed — DP-SGD disabled")

    criterion = nn.CrossEntropyLoss()
    total_loss = 0.0
    for _ in range(epochs):
        for Xb, yb in loader:
            Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            loss = criterion(model(Xb), yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
    return total_loss


def evaluate(model: nn.Module, loader: DataLoader) -> Tuple[float, float, dict]:
    model.to(DEVICE).eval()
    criterion  = nn.CrossEntropyLoss()
    preds, labels, total_loss = [], [], 0.0
    with torch.no_grad():
        for Xb, yb in loader:
            Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
            logits = model(Xb)
            total_loss += criterion(logits, yb).item()
            preds.extend(logits.argmax(1).cpu().numpy())
            labels.extend(yb.cpu().numpy())
    avg_loss = total_loss / max(len(loader), 1)
    f1 = f1_score(labels, preds, average="weighted", zero_division=0)
    report = classification_report(
        labels, preds,
        target_names=["normal", "attack"],
        zero_division=0, output_dict=True
    )
    return avg_loss, f1, report


def get_weights(model: nn.Module) -> List[np.ndarray]:
    return [v.cpu().numpy() for v in model.state_dict().values()]


def set_weights(model: nn.Module, weights: List[np.ndarray]):
    state = OrderedDict(
        {k: torch.tensor(v) for k, v in zip(model.state_dict().keys(), weights)}
    )
    model.load_state_dict(state, strict=True)

# ─────────────────────────────────────────────────────────────
# FLOWER CLIENT
# ─────────────────────────────────────────────────────────────

class SliceClient(fl.client.NumPyClient):
    def __init__(self, client_id: int, csv_path: str):
        self.cid = client_id
        self.train_loader, self.test_loader = load_slice_data(csv_path)
        self.model = get_model()
        print(f"  [Client {client_id}] Ready — "
              f"{len(self.train_loader.dataset)} train / "
              f"{len(self.test_loader.dataset)} test samples")

    def get_parameters(self, config):
        return get_weights(self.model)

    def fit(self, parameters, config):
        set_weights(self.model, parameters)
        loss = train(self.model, self.train_loader, CFG["local_epochs"])
        return get_weights(self.model), len(self.train_loader.dataset), {"loss": loss}

    def evaluate(self, parameters, config):
        set_weights(self.model, parameters)
        loss, f1, report = evaluate(self.model, self.test_loader)
        print(f"  [Client {self.cid}] loss={loss:.4f}  F1={f1:.4f}  "
              f"precision={report['attack']['precision']:.4f}  "
              f"recall={report['attack']['recall']:.4f}")
        return float(loss), len(self.test_loader.dataset), {
            "f1":        float(f1),
            "precision": float(report["attack"]["precision"]),
            "recall":    float(report["attack"]["recall"]),
        }

# ─────────────────────────────────────────────────────────────
# FLOWER SERVER STRATEGY
# ─────────────────────────────────────────────────────────────

def weighted_average(metrics: List[Tuple[int, Metrics]]) -> Metrics:
    total = sum(n for n, _ in metrics)
    return {
        "f1":        sum(n * m["f1"]        for n, m in metrics) / total,
        "precision": sum(n * m["precision"] for n, m in metrics) / total,
        "recall":    sum(n * m["recall"]    for n, m in metrics) / total,
    }


def run():
    os.makedirs(CFG["model_dir"], exist_ok=True)

    # Discover slice CSVs
    csv_files = sorted([
        os.path.join("data", f)
        for f in os.listdir("data") if f.startswith("slice_") and f.endswith(".csv")
    ])
    if not csv_files:
        raise FileNotFoundError("No slice CSVs found in data/. Run data_pipeline.py first.")

    n_clients = len(csv_files)
    print(f"\n{'='*60}")
    print(f"  FL TRAINER — {n_clients} clients | {CFG['num_rounds']} rounds")
    print(f"  DP-SGD: {'enabled (ε=' + str(CFG['dp_epsilon']) + ')' if CFG['dp_epsilon'] else 'disabled'}")
    print(f"  Device: {DEVICE}")
    print(f"{'='*60}")

    # Initial parameters from a fresh model
    init_model  = get_model()
    init_params = fl.common.ndarrays_to_parameters(get_weights(init_model))

    strategy = fl.server.strategy.FedAvg(
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=min(CFG["min_clients"], n_clients),
        min_evaluate_clients=min(CFG["min_clients"], n_clients),
        min_available_clients=n_clients,
        evaluate_metrics_aggregation_fn=weighted_average,
        initial_parameters=init_params,
    )

    def client_fn(cid: str) -> fl.client.Client:
        return SliceClient(int(cid), csv_files[int(cid)]).to_client()

    history = fl.simulation.start_simulation(
        client_fn=client_fn,
        num_clients=n_clients,
        config=fl.server.ServerConfig(num_rounds=CFG["num_rounds"]),
        strategy=strategy,
        client_resources={"num_cpus": 16},
    )

    # ── Print round-by-round metrics ─────────────────────────
    print(f"\n{'='*60}")
    print("  FEDERATION RESULTS")
    print(f"{'='*60}")
    if "f1" in history.metrics_distributed:
        print(f"  {'Round':<8} {'F1':>8} {'Precision':>12} {'Recall':>10}")
        print("  " + "-" * 42)
        for rnd, f1 in history.metrics_distributed["f1"]:
            prec = dict(history.metrics_distributed.get("precision", [])).get(rnd, 0)
            rec  = dict(history.metrics_distributed.get("recall",    [])).get(rnd, 0)
            print(f"  {rnd:<8} {f1:>8.4f} {prec:>12.4f} {rec:>10.4f}")

    # ── Save final model ──────────────────────────────────────
    final_model = get_model()
    torch.save(final_model.state_dict(), CFG["model_path"])
    print(f"\n  Model saved → {CFG['model_path']}")
    return CFG["model_path"]


if __name__ == "__main__":
    run()
