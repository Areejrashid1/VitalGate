"""Feature parity: product sensor (vitalgate.sensor) vs the training table (features.csv).
Usage: python tests/test_parity.py --data "<dataset folder>" --site A --files 6
Reads the first N pcaps of a site (as one stream, like the training extractor) and compares every window that is
final before the cut. Then checks the online 83-feature history against src/features.py-style batch history."""
import argparse, glob, math, os, sys, time
import numpy as np, pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from vitalgate.sensor.pcapio import read_pcap
from vitalgate.sensor.windows import WindowBuilder
from vitalgate.sensor.history import OnlineHistory, FEATURES_V3, BASE27, base27

PACS = {"A": ("10.77.1.10", 4242), "B": ("10.77.2.10", 11112), "C": ("10.77.3.10", 4243)}
COLS = ["out_pkts", "out_bytes", "in_pkts", "in_bytes", "mean_pkt", "std_pkt", "mean_iat", "std_iat", "syn", "rst",
        "fin", "n_dst_ports", "n_src_ports", "assoc_rq", "assoc_ac", "assoc_rj", "abort", "release", "pdata_pkts",
        "n_called_ae", "n_calling_ae", "bad_first_pdu", "big_pdu_len", "http_post", "preamble_exec"]

p = argparse.ArgumentParser()
p.add_argument("--data", required=True); p.add_argument("--ref", default=None, help="reference table (csv); default <data>/features.csv"); p.add_argument("--site", default="A"); p.add_argument("--files", type=int, default=6); p.add_argument("--gro", action="store_true", help="put the software-GRO normaliser in front of the sensor")
a = p.parse_args()
files = sorted(glob.glob(os.path.join(a.data, "pcap", f"site{a.site}_*.pcap")))[:a.files]
wb = WindowBuilder(a.site, *PACS[a.site], flush_lag=10.0)
rows, t0, last = [], time.time(), None
from vitalgate.sensor.gro import Coalescer
co = Coalescer() if a.gro else None
for f in files:
    for t, ip in read_pcap(f):
        last = t
        for tt, pp in (co.feed(t, ip) if co else [(t, ip)]):
            rows += wb.feed(tt, pp)
if co:
    for tt, pp in co.flush_all(): rows += wb.feed(tt, pp)
    print("gro:", co.stats)
rows += wb.flush_all()
print(f"sensor: {len(files)} pcaps, {len(rows)} windows in {time.time() - t0:.1f}s")
mine = pd.DataFrame(rows)
cut = int((last - 10) // 2) * 2                       # windows after this may be incomplete (next pcap not read)
mine = mine[mine.window_start < cut]

rp = a.ref or os.path.join(a.data, "features.csv")
ref = pd.read_parquet(rp) if rp.endswith(".parquet") else pd.read_csv(rp)
COLS = [c for c in COLS if c in ref.columns]
print("reference:", rp, "| comparing", len(COLS), "columns")
ref = ref[(ref.site == a.site) & (ref.window_start >= mine.window_start.min()) & (ref.window_start < cut)]
k = ["client_ip", "window_start"]
m = mine.merge(ref, on=k, how="outer", suffixes=("_new", "_ref"), indicator=True)
print("windows: sensor", len(mine), "| training", len(ref), "|", m["_merge"].value_counts().to_dict())
both = m[m["_merge"] == "both"]
bad = {}
for c in COLS:
    d = ~np.isclose(both[c + "_new"].astype(float), both[c + "_ref"].astype(float), rtol=1e-9, atol=1e-9)
    if d.any(): bad[c] = int(d.sum())
print("column mismatches:", bad or "none")

# history parity: online vs batch (same logic as src/features.py add_history(part_col=None))
s = mine.sort_values(["client_ip", "window_start"]).reset_index(drop=True)
oh, on = OnlineHistory(), []
for _, r in s.sort_values(["window_start", "client_ip"]).iterrows():
    on.append((r.client_ip, r.window_start, oh.vector(r.to_dict())))
online = pd.DataFrame([v for *_, v in on], columns=FEATURES_V3)
online[["client_ip", "window_start"]] = [[i, w] for i, w, _ in on]
B = pd.DataFrame([base27(r) for r in s.to_dict("records")], columns=BASE27)
B[["client_ip", "window_start"]] = s[["client_ip", "window_start"]]
g = B.groupby("client_ip", sort=False)
batch = B.copy()
for L in (1, 2):
    sh = g[BASE27].shift(L); sh.columns = [f"{c}_lag{L}" for c in BASE27]; batch = batch.join(sh)
batch["gap_s"] = g["window_start"].diff().clip(0, 3600)
batch["gap_lag1"] = batch.groupby("client_ip", sort=False)["gap_s"].shift(1)
x = online.merge(batch, on=["client_ip", "window_start"], suffixes=("_o", "_b"))
hb = [c for c in FEATURES_V3 if not np.allclose(x[c + "_o"].astype(float), x[c + "_b"].astype(float), equal_nan=True)]
print("history rows", len(x), "| 83-feature mismatches:", hb or "none")
lab = ref.assign(label_class=ref.get("label_class", "unlabelled")).groupby("label_class").size().to_dict()
print("classes in this slice:", lab)
print("rule columns > 0 in benign windows:",
      {c: int((ref[ref.get("label_class", pd.Series("benign", index=ref.index)) == "benign"][c] > 0).sum()) for c in ["bad_first_pdu", "big_pdu_len", "preamble_exec"]})
