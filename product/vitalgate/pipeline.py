"""Layers 1-3 chained for offline use: pcaps -> software GRO -> 2 s windows -> 83 features -> calibrated model + rule."""
import numpy as np
from .sensor.pcapio import read_pcap
from .sensor.windows import WindowBuilder
from .sensor.gro import Coalescer
from .sensor.history import OnlineHistory


def windows_from_pcaps(files, pacs_ip, dicom_port, http_port=8042, site="TB", gro=True, ignore=()):
    wb = WindowBuilder(site, pacs_ip, dicom_port, http_port, flush_lag=10.0, ignore=ignore); co = Coalescer() if gro else None
    rows = []
    for f in files:
        for t, ip in read_pcap(f):
            for tt, pp in (co.feed(t, ip) if co else [(t, ip)]):
                rows += wb.feed(tt, pp)
    if co:
        for tt, pp in co.flush_all(): rows += wb.feed(tt, pp)
    rows += wb.flush_all()
    rows.sort(key=lambda r: (r["window_start"], r["client_ip"]))
    return rows


def featurize(rows):
    oh = OnlineHistory()
    return np.array([oh.vector(r) for r in rows], np.float32)


def load_truth(truth_csv):
    """truth.csv + truth_recovered.csv + interrupted runs from truth_started.csv (same rules as eval/offline_eval.py)."""
    import csv
    from pathlib import Path
    p = Path(truth_csv); out = []
    if p.exists():
        out += [dict(r, status="complete") for r in csv.DictReader(open(p, encoding="utf-8-sig"))]
    if (p.parent / "truth_recovered.csv").exists():
        out += [dict(r, status="recovered") for r in csv.DictReader(open(p.parent / "truth_recovered.csv", encoding="utf-8-sig"))]
    if (p.parent / "truth_started.csv").exists():
        done = {(r["run_id"], r["src_ip"], round(float(r["start_ts"]))) for r in out}
        for r in csv.DictReader(open(p.parent / "truth_started.csv", encoding="utf-8-sig")):
            if (r["run_id"], r["src_ip"], round(float(r["start_ts"]))) not in done:
                out.append(dict(r, end_ts=r["planned_end_ts"], status="interrupted"))
    for r in out: r["start_ts"], r["end_ts"] = float(r["start_ts"]), float(r["end_ts"])
    return sorted(out, key=lambda r: r["start_ts"])


def truth_lookup(truth):
    by_ip = {}
    for r in truth: by_ip.setdefault(r["src_ip"], []).append(r)
    def f(ip, t):
        for r in by_ip.get(ip, ()):
            if t + 2 > r["start_ts"] and t <= r["end_ts"]:
                return f"{r['label_class']}/{r['variant']}" + (" (novel)" if str(r.get("novel")) == "1" else "")
        return "benign"
    return f
