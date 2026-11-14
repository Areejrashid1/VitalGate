"""VitalGate feature builder (v3) — the single place where model inputs are defined.

v3 = 27 base features of the current 2 s window
   + the same 27 features for the previous 2 windows of the same host (lag1, lag2)
   + time since the host's previous window (gap_s) and the gap before that (gap_lag1)
   = 83 features.

Missing history (a host's first windows) is left as NaN: XGBoost handles it natively.
Neural / linear models must call fill_for_nn() first. Deployment must send NaN, never 0, to XGBoost.
History never crosses a partition of `part_col` (train / val / test, site, campaign) during experiments;
in deployment call add_history(df, part_col=None).
"""
import numpy as np
import pandas as pd

ML_23_MS = ["out_pkts", "out_bytes", "in_pkts", "in_bytes", "mean_pkt", "std_pkt", "mean_iat_ms", "std_iat_ms",
            "syn", "rst", "fin", "n_dst_ports", "n_src_ports", "assoc_rq", "assoc_ac", "assoc_rj", "abort", "release",
            "pdata_pkts", "n_called_ae", "n_calling_ae", "bad_first_pdu", "big_pdu_len"]
RATIO_FEATS = ["bytes_per_pkt", "out_in_byte_ratio", "assoc_accept_ratio", "rst_syn_ratio"]
BASE27 = ML_23_MS + RATIO_FEATS
LAGS = (1, 2)
LAG_FEATS = [f"{c}_lag{L}" for L in LAGS for c in BASE27]
GAP_FEATS = ["gap_s", "gap_lag1"]
FEATURES_V3 = BASE27 + LAG_FEATS + GAP_FEATS
GAP_CAP_S = 3600.0
FEATURE_VERSION = "v3"


def add_base(df):
    """Add IAT in ms and the 4 ratio features if missing (raw features.parquet input)."""
    f = df.copy()
    if "mean_iat_ms" not in f: f["mean_iat_ms"] = f["mean_iat"] * 1000.0
    if "std_iat_ms" not in f: f["std_iat_ms"] = f["std_iat"] * 1000.0
    if "bytes_per_pkt" not in f:
        f["bytes_per_pkt"] = (f["out_bytes"] + f["in_bytes"]) / (f["out_pkts"] + f["in_pkts"] + 1e-6)
    if "out_in_byte_ratio" not in f: f["out_in_byte_ratio"] = f["out_bytes"] / (f["in_bytes"] + 1.0)
    if "assoc_accept_ratio" not in f: f["assoc_accept_ratio"] = f["assoc_ac"] / (f["assoc_rq"] + 1e-6)
    if "rst_syn_ratio" not in f: f["rst_syn_ratio"] = f["rst"] / (f["syn"] + 1e-6)
    return f


def add_history(df, part_col="split_run"):
    """Add lag1/lag2 of the 27 base features and the two time gaps, per host, causally.
    Returns a copy in the original row order. part_col=None -> history per host only (deployment)."""
    f = add_base(df)
    order = f.index
    keys = [part_col, "client_ip"] if part_col else ["client_ip"]
    s = f.sort_values(keys + ["window_start"])
    g = s.groupby(keys, sort=False)
    hist = pd.DataFrame(index=s.index)
    hist["gap_s"] = g["window_start"].diff().clip(0, GAP_CAP_S)
    hist["gap_lag1"] = hist.groupby([s[k] for k in keys], sort=False)["gap_s"].shift(1)
    for L in LAGS:
        sh = g[BASE27].shift(L)
        sh.columns = [f"{c}_lag{L}" for c in BASE27]
        hist = hist.join(sh)
    s = pd.concat([s.drop(columns=[c for c in hist.columns if c in s.columns]), hist], axis=1)
    return s.loc[order]


def fill_for_nn(X):
    """For MLP / logistic regression only: missing history = no traffic (0), missing gap = long silence."""
    X = pd.DataFrame(X).copy()
    for c in X.columns:
        if c in GAP_FEATS: X[c] = X[c].fillna(GAP_CAP_S)
        elif c.endswith(("_lag1", "_lag2")): X[c] = X[c].fillna(0.0)
    return X


def feature_group_of(name, groups):
    """Map a v3 feature (incl. lags) to its explanation group: a lag belongs to its base feature's group."""
    base = name.rsplit("_lag", 1)[0] if name.endswith(("_lag1", "_lag2")) else name
    for g, members in groups.items():
        if base in members or name in members:
            return g
    return None