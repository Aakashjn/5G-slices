"""
data_pipeline.py
================
Layer 1 of the full pipeline.
Handles:
  - Loading + decoding your malicious_data.csv (hex → HTTP features)
  - Loading 5G-NIDD / UNSW-NB15 benign samples
  - Feature extraction from raw packets
  - Building a balanced per-slice dataset
  - Saving to data/slice_0.csv, slice_1.csv, slice_2.csv
"""

import os
import re
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
CFG = {
    "malicious_csv":  "malicious_data.csv",   # your hex-encoded attack CSV
    "benign_csv":     None,                    # set to 5G-NIDD path when downloaded
                                               # e.g. "5G_NIDD.csv"
    "output_dir":     "data",
    "n_slices":       3,
    "samples_per_slice": 500,                 # per class (attack + normal) per slice
    "label_column":   "label",
    "random_seed":    42,
}

SLICE_ATTACK_MAP = {
    0: ["ddos", "http_flood", "hulk", "goldeneye"],       # eMBB  — high BW attacks
    1: ["nosql_injection", "slowread", "rudy", "syn_flood"],# URLLC — signalling attacks
    2: ["port_scan", "lateral_movement", "icmp_flood"],    # mMTC  — recon + pivot
}

# ─────────────────────────────────────────────────────────────
# HEX DECODER — for your malicious_data.csv
# ─────────────────────────────────────────────────────────────

def decode_hex_payload(raw: str) -> str:
    raw = str(raw).strip()
    if raw.startswith("b'") and raw.endswith("'"):
        raw = raw[2:-1]
    try:
        return bytes.fromhex(raw).decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_features_from_http(decoded: str) -> dict:
    """
    Extract numeric features from decoded HTTP/MongoDB traffic.
    Returns a feature dict compatible with SliceSecurityNet input.
    """
    text = decoded[:1000]

    # HTTP method
    method_map = {"GET": 1, "POST": 2, "PUT": 3, "PATCH": 4,
                  "DELETE": 5, "HEAD": 6, "OPTIONS": 7}
    method = 0
    for m, v in method_map.items():
        if text.startswith(m):
            method = v
            break

    # Endpoint targeting NRF/UDM (attack indicator)
    nrf_disc   = 1 if "/nnrf-disc/" in text else 0
    nrf_mgmt   = 1 if "/nnrf-nfm/"  in text else 0
    udm_access = 1 if "/nudm-sdm/"  in text else 0
    nosql_kw   = 1 if any(k in text for k in ["$and", "$or", "$nor",
                                                "$gt", "$lt", "$ne",
                                                "find", "NfProfile"]) else 0

    # Response code (if response packet)
    status = 0
    m = re.search(r"HTTP/1\.1 (\d{3})", text)
    if m:
        status = int(m.group(1))

    # Content length
    clen = 0
    m = re.search(r"Content-Length:\s*(\d+)", text)
    if m:
        clen = int(m.group(1))

    # Payload length (raw bytes)
    payload_len = len(decoded)

    # MongoDB indicators
    mongo_query   = 1 if "find" in text and "NfProfile" in text else 0
    mongo_error   = 1 if "errmsg" in text or "ok.*0" in text else 0
    mongo_op      = 1 if "db.runCommand" in text or '{"find"' in text else 0

    # Error signals
    is_5xx = 1 if 500 <= status < 600 else 0
    is_4xx = 1 if 400 <= status < 500 else 0

    # Nested injection depth (count $ operators)
    injection_depth = text.count("$")

    # IMSI access (subscriber data leak attempt)
    imsi_access = 1 if "imsi-" in text.lower() else 0

    return {
        "http_method":       method,
        "nrf_discovery":     nrf_disc,
        "nrf_management":    nrf_mgmt,
        "udm_access":        udm_access,
        "nosql_keyword":     nosql_kw,
        "http_status":       status / 600.0,   # normalised
        "content_length":    min(clen, 10000) / 10000.0,
        "payload_length":    min(payload_len, 5000) / 5000.0,
        "mongo_query":       mongo_query,
        "mongo_error":       mongo_error,
        "mongo_op":          mongo_op,
        "is_5xx":            is_5xx,
        "is_4xx":            is_4xx,
        "injection_depth":   min(injection_depth, 20) / 20.0,
        "imsi_access":       imsi_access,
        "is_request":        1 if method > 0 else 0,
        "is_response":       1 if status > 0 else 0,
        "text_len":          min(len(text), 1000) / 1000.0,
        "slice_id":          0.0,   # filled in later
        "hour_of_day":       0.0,   # filled in later
    }


def load_malicious_csv(path: str) -> pd.DataFrame:
    print(f"[DataPipeline] Loading attack data from {path}")
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()

    print(f"  Raw rows: {len(df)}")
    df["decoded"]  = df["raw"].apply(decode_hex_payload)
    features       = df["decoded"].apply(extract_features_from_http)
    feat_df        = pd.DataFrame(list(features))
    feat_df["label"] = 1   # all attack
    print(f"  Extracted {len(feat_df)} attack feature rows, {feat_df.shape[1]-1} features")
    return feat_df


def load_benign_csv(path: str, n_samples: int) -> pd.DataFrame:
    """
    Load benign traffic from 5G-NIDD or UNSW-NB15.
    Tries common label column names.
    """
    print(f"[DataPipeline] Loading benign data from {path}")
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    # Find label column
    label_col = None
    for c in ["Label", "label", "class", "Class", "attack_cat"]:
        if c in df.columns:
            label_col = c
            break

    if label_col is None:
        raise ValueError(f"No label column found in {path}. Columns: {list(df.columns)}")

    # Keep only benign rows
    benign_values = ["BENIGN", "benign", "Normal", "normal", "0", 0]
    benign_df = df[df[label_col].isin(benign_values)].copy()
    print(f"  Found {len(benign_df)} benign rows")

    # Drop non-numeric and label columns
    benign_df.drop(columns=[label_col], inplace=True)
    non_num = benign_df.select_dtypes(exclude=[np.number]).columns.tolist()
    benign_df.drop(columns=non_num, inplace=True, errors="ignore")

    # Handle NaN / inf
    benign_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    benign_df.fillna(benign_df.median(numeric_only=True), inplace=True)
    benign_df = benign_df.loc[:, benign_df.std() > 0]

    # Align to our 20-feature set (pad with 0 if columns differ)
    feature_names = list(extract_features_from_http("").keys())
    aligned = pd.DataFrame(0.0, index=range(len(benign_df)), columns=feature_names)
    for col in feature_names:
        if col in benign_df.columns:
            aligned[col] = benign_df[col].values[:len(aligned)]

    # Normalise
    scaler = StandardScaler()
    aligned_scaled = pd.DataFrame(
        scaler.fit_transform(aligned),
        columns=feature_names
    )
    aligned_scaled["label"] = 0   # benign

    sampled = aligned_scaled.sample(n=min(n_samples, len(aligned_scaled)),
                                    random_state=CFG["random_seed"])
    print(f"  Using {len(sampled)} benign samples")
    return sampled


def generate_synthetic_benign(n_samples: int) -> pd.DataFrame:
    """
    Fallback: generate synthetic benign samples when no benign CSV available.
    Based on normal 5G SBI traffic patterns.
    """
    print(f"[DataPipeline] Generating {n_samples} synthetic benign samples")
    np.random.seed(CFG["random_seed"])
    feature_names = list(extract_features_from_http("").keys())
    data = {}
    for feat in feature_names:
        if feat in ["http_method"]:
            data[feat] = np.random.choice([1, 2, 3], n_samples) / 7.0
        elif feat in ["http_status"]:
            data[feat] = np.random.choice([200, 201, 204], n_samples) / 600.0
        elif feat in ["slice_id", "hour_of_day", "nosql_keyword",
                      "mongo_query", "mongo_error", "mongo_op",
                      "is_5xx", "is_4xx", "injection_depth",
                      "imsi_access", "nrf_management", "udm_access"]:
            data[feat] = np.zeros(n_samples)
        elif feat in ["nrf_discovery"]:
            data[feat] = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
        else:
            data[feat] = np.random.uniform(0.05, 0.4, n_samples)
    df = pd.DataFrame(data)
    df["label"] = 0
    return df


def build_slice_datasets(attack_df: pd.DataFrame,
                          benign_df: pd.DataFrame) -> None:
    os.makedirs(CFG["output_dir"], exist_ok=True)
    n = CFG["samples_per_slice"]

    for slice_id in range(CFG["n_slices"]):
        print(f"\n[DataPipeline] Building Slice {slice_id} dataset")

        # Sample attack rows for this slice
        atk = attack_df.sample(n=min(n, len(attack_df)),
                               replace=len(attack_df) < n,
                               random_state=slice_id).copy()
        atk["slice_id"] = slice_id / CFG["n_slices"]

        # Sample benign rows
        ben = benign_df.sample(n=min(n, len(benign_df)),
                               replace=len(benign_df) < n,
                               random_state=slice_id + 100).copy()
        ben["slice_id"] = slice_id / CFG["n_slices"]

        # Combine and shuffle
        combined = pd.concat([atk, ben], ignore_index=True)
        combined  = combined.sample(frac=1, random_state=42).reset_index(drop=True)

        out_path = os.path.join(CFG["output_dir"], f"slice_{slice_id}.csv")
        combined.to_csv(out_path, index=False)
        attack_count = int(combined["label"].sum())
        print(f"  Slice {slice_id}: {len(combined)} rows "
              f"({attack_count} attack, {len(combined)-attack_count} normal) → {out_path}")


def run():
    print("=" * 60)
    print("  DATA PIPELINE — 5G Slice Security")
    print("=" * 60)

    # Load attack data
    attack_df = load_malicious_csv(CFG["malicious_csv"])

    # Load or generate benign data
    if CFG["benign_csv"] and os.path.exists(CFG["benign_csv"]):
        benign_df = load_benign_csv(CFG["benign_csv"],
                                    CFG["samples_per_slice"] * CFG["n_slices"])
    else:
        print("\n[DataPipeline] No benign CSV configured — using synthetic benign traffic")
        print("  → Download 5G-NIDD and set CFG['benign_csv'] for real benign data")
        benign_df = generate_synthetic_benign(
            CFG["samples_per_slice"] * CFG["n_slices"]
        )

    build_slice_datasets(attack_df, benign_df)
    print(f"\n[DataPipeline] Done — slice CSVs saved to {CFG['output_dir']}/")


if __name__ == "__main__":
    run()
