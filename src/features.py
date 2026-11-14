"""VitalGate feature builder (v4) — the single place where model inputs are defined.

v3 = 27 base features of the current 2 s window
   + the same 27 features for the previous 2 windows of the same host (lag1, lag2)
   + time since the host's previous window (gap_s) and the gap before that (gap_lag1)
   = 83 features.
v4 = v3
   + long context per host: sums of out/in bytes, out packets, P-DATA packets and association requests
     over the last 60 s and 300 s, plus the long-window out/in byte balance                     (12)
   = 95 features. Notebook 02: test macro-F1 0.954 -> 0.957, unseen site 0.951 -> 0.955,
     split_time 0.901 -> 0.939 (false alarms 3.8 -> 0.4 /h), campaign 1->2 0.854 -> 0.901;
     weaker on campaign 2->1 (0.919 -> 0.827) - reported as a limitation.
   Rejected: per-host benign baseline (its gain came from attacker hosts having no benign history);
   DICOM command counts (DICOM_FEATS, kept for experiments only: +0.004 on split_run but campaign 1->2
   collapsed to 0.683 with exfiltration and ransomware F1 = 0 -> they memorise campaign-specific behaviour).

Missing short history (a host's first windows) is left as NaN: XGBoost handles it natively.
Neural / linear models must call fill_for_nn() first. Deployment must send NaN, never 0, to XGBoost
for missing lags; long-context sums and DICOM counts are never missing (no command = 0).
History never crosses a partition of `part_col` (train / val / test, site, campaign) during experiments;
in deployment call add_history(df, part_col=None, dicom=<live command counts>).
AE titles and client_ip are never features (generator artefacts / host identity).
"""
from pathlib import Path
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

LC_BASE = ["out_bytes", "in_bytes", "out_pkts", "pdata_pkts", "assoc_rq"]
LC_SPANS = ("60s", "300s")
LONG_FEATS = [f"{c}_sum{sp}" for sp in LC_SPANS for c in LC_BASE] + [f"out_in_ratio_sum{sp}" for sp in LC_SPANS]
DICOM_BASE = ["cmd_store_out", "cmd_store_in", "cmd_find", "find_matches", "cmd_get", "cmd_move", "cmd_echo", "cmd_fail"]
DICOM_FEATS = DICOM_BASE + [f"{c}_sum60s" for c in DICOM_BASE]
FEATURES_V4 = FEATURES_V3 + LONG_FEATS            # 95 (DICOM_FEATS deliberately excluded)
FEATURE_VERSION = "v4"
DICOM_FILE = Path(__file__).resolve().parents[1] / "data" / "processed" / "dicom_cmds.parquet"

# explanation groups: new features join the group of the base feature they summarise
_ALIAS = {**{f"out_in_ratio_sum{sp}": "out_in_byte_ratio" for sp in LC_SPANS},
          **{c: "pdata_pkts" for c in DICOM_BASE if c != "cmd_fail"}, "cmd_fail": "assoc_rj"}


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


def add_dicom(df, dicom=None):
    """Join per-window DICOM command counts (client_ip, window_start). Windows without commands get 0.
    dicom: DataFrame, path, or None (= data/processed/dicom_cmds.parquet). Skipped if the columns exist."""
    if all(c in df for c in DICOM_BASE): return df
    if dicom is None or isinstance(dicom, (str, Path)):
        path = Path(dicom) if dicom is not None else DICOM_FILE
        if not path.exists():
            raise FileNotFoundError(f"{path} not found - run: python scripts/extract_dicom.py <pcap folder> data/processed")
        dicom = pd.read_parquet(path)
    dc = dicom[["client_ip", "window_start"] + DICOM_BASE].copy()
    dc["_w"] = np.round(dc["window_start"].astype(float)).astype("int64")
    dc = dc.drop(columns="window_start").groupby(["client_ip", "_w"], as_index=False).sum()
    f = df.copy(); f["_w"] = np.round(f["window_start"].astype(float)).astype("int64")
    f = f.join(dc.set_index(["client_ip", "_w"]), on=["client_ip", "_w"])          # keeps df's index and order
    f[DICOM_BASE] = f[DICOM_BASE].fillna(0.0)
    return f.drop(columns="_w")


def _rolling_sums(s, keys, cols, spans):
    """Causal time-window sums per host (current + past windows only). s must be sorted by keys + time."""
    t = pd.to_datetime(s["window_start"].astype(float), unit="s")
    out = {f"{c}_sum{sp}": np.empty(len(s)) for sp in spans for c in cols}
    pos = 0
    for _, idx in s.groupby(keys, sort=False).indices.items():
        g = s.iloc[idx][cols].set_axis(t.iloc[idx].values)
        for sp in spans:
            r = g.rolling(sp).sum().to_numpy()
            for j, c in enumerate(cols): out[f"{c}_sum{sp}"][idx] = r[:, j]
    return pd.DataFrame(out, index=s.index)


def add_history(df, part_col="split_run", dicom=None, with_dicom=False):
    """v4: lag1/lag2 of the 27 base features + time gaps and long-context sums, per host, causally.
    with_dicom=True also adds the (experimental, not in FEATURES_V4) DICOM command features.
    Returns a copy in the original row order. part_col=None -> per host only (deployment)."""
    f = add_base(df)
    if with_dicom: f = add_dicom(f, dicom)
    order = f.index
    keys = [part_col, "client_ip"] if part_col else ["client_ip"]
    s = f.sort_values(keys + ["window_start"], kind="stable")
    g = s.groupby(keys, sort=False)
    hist = pd.DataFrame(index=s.index)
    hist["gap_s"] = g["window_start"].diff().clip(0, GAP_CAP_S)
    hist["gap_lag1"] = hist.groupby([s[k] for k in keys], sort=False)["gap_s"].shift(1)
    for L in LAGS:
        sh = g[BASE27].shift(L)
        sh.columns = [f"{c}_lag{L}" for c in BASE27]
        hist = hist.join(sh)
    hist = hist.join(_rolling_sums(s, keys, LC_BASE, LC_SPANS))
    for sp in LC_SPANS:
        hist[f"out_in_ratio_sum{sp}"] = np.log1p(hist[f"out_bytes_sum{sp}"]) - np.log1p(hist[f"in_bytes_sum{sp}"])
    if with_dicom: hist = hist.join(_rolling_sums(s, keys, DICOM_BASE, ("60s",)))
    s = pd.concat([s.drop(columns=[c for c in hist.columns if c in s.columns]), hist], axis=1)
    return s.loc[order]


def fill_for_nn(X):
    """For MLP / logistic regression only: missing history = no traffic (0), missing gap = long silence."""
    X = pd.DataFrame(X).copy()
    for c in X.columns:
        if c in GAP_FEATS: X[c] = X[c].fillna(GAP_CAP_S)
        elif c.endswith(("_lag1", "_lag2")) or c in LONG_FEATS or c in DICOM_FEATS: X[c] = X[c].fillna(0.0)
    return X


def feature_group_of(name, groups):
    """Map a feature to its explanation group: lags, long-context sums and DICOM counts join the group of
    the base feature they summarise (DICOM commands -> the group holding pdata_pkts, failures -> assoc_rj)."""
    base = name.rsplit("_lag", 1)[0] if name.endswith(("_lag1", "_lag2")) else name
    if base in _ALIAS: base = _ALIAS[base]
    elif base.endswith(tuple(f"_sum{sp}" for sp in LC_SPANS)):
        base = base.rsplit("_sum", 1)[0]
        base = _ALIAS.get(base, base)
    for g, members in groups.items():
        if base in members or name in members:
            return g
    return None
