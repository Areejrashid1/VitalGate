"""Layer 1b: window rows -> model vector (v3, 83 features), online, per host.
Must match src/features.py add_base() + add_history(part_col=None): lag1/lag2 = the host's previous 1st/2nd
*emitted window row* (not the previous 2 s slot), gap_s = seconds since that row (clipped to [0, 3600]),
gap_lag1 = previous gap_s. Missing history stays NaN (XGBoost handles it; never fill with 0)."""
import math
from collections import deque

ML_23_MS = ["out_pkts", "out_bytes", "in_pkts", "in_bytes", "mean_pkt", "std_pkt", "mean_iat_ms", "std_iat_ms",
            "syn", "rst", "fin", "n_dst_ports", "n_src_ports", "assoc_rq", "assoc_ac", "assoc_rj", "abort", "release",
            "pdata_pkts", "n_called_ae", "n_calling_ae", "bad_first_pdu", "big_pdu_len"]
RATIO_FEATS = ["bytes_per_pkt", "out_in_byte_ratio", "assoc_accept_ratio", "rst_syn_ratio"]
BASE27 = ML_23_MS + RATIO_FEATS
LAGS = (1, 2)
GAP_CAP_S = 3600.0
FEATURES_V3 = BASE27 + [f"{c}_lag{L}" for L in LAGS for c in BASE27] + ["gap_s", "gap_lag1"]
NAN = float("nan")


def base27(row):
    f = dict(row)
    f["mean_iat_ms"] = f["mean_iat"] * 1000.0
    f["std_iat_ms"] = f["std_iat"] * 1000.0
    f["bytes_per_pkt"] = (f["out_bytes"] + f["in_bytes"]) / (f["out_pkts"] + f["in_pkts"] + 1e-6)
    f["out_in_byte_ratio"] = f["out_bytes"] / (f["in_bytes"] + 1.0)
    f["assoc_accept_ratio"] = f["assoc_ac"] / (f["assoc_rq"] + 1e-6)
    f["rst_syn_ratio"] = f["rst"] / (f["syn"] + 1e-6)
    return [float(f[c]) for c in BASE27]


class OnlineHistory:
    def __init__(self, idle_forget_s=None):
        self.hist = {}                    # client_ip -> (deque of last 2 base vectors, last window_start, last gap)
        self.idle_forget_s = idle_forget_s

    def vector(self, row):
        """row = a WindowBuilder dict. Rows of one host must arrive in window order. Returns list of 83 floats."""
        b = base27(row)
        ip, w = row["client_ip"], row["window_start"]
        prev = self.hist.get(ip)
        if prev is None:
            q, gap, gap1 = deque(maxlen=2), NAN, NAN
        else:
            q, last_w, last_gap = prev
            gap = min(max(w - last_w, 0.0), GAP_CAP_S)
            gap1 = last_gap
        lag1 = q[-1] if len(q) >= 1 else [NAN] * 27
        lag2 = q[-2] if len(q) >= 2 else [NAN] * 27
        q.append(b)
        self.hist[ip] = (q, w, gap)
        return b + lag1 + lag2 + [gap, gap1]
