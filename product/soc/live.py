"""Live VitalGate pipeline for one site: follows the capture as tcpdump writes it and updates the SOC dashboard
within seconds. Same layers as the evaluation: software GRO -> 2 s windows -> 83 features -> frozen federated model
(+ DPI rule) -> CUSUM -> L0-L4 ladder -> incidents with explanations. Gateway commands are rendered, not executed
(the enforcement service comes next).
Usage (from product/, with the test bed running):   python soc/live.py      then  python soc/server.py
  --bundle bundle (frozen) | bundle_local-labelled (site D personalised) ...  --flush-lag 4 (s)"""
import argparse, json, os, sys, time
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.sensor.follow import PcapFollower
from vitalgate.sensor.gro import Coalescer
from vitalgate.sensor.windows import WindowBuilder
from vitalgate.sensor.history import OnlineHistory
from vitalgate.model.bundle import Bundle
from vitalgate.response.engine import ResponseEngine, Inventory
from vitalgate.response.incidents import IncidentTracker
from vitalgate.explain.explainer import Explainer
from vitalgate.pipeline import load_truth, truth_lookup
from vitalgate.response.pep_controller import PepController

p = argparse.ArgumentParser()
p.add_argument("--pcap-dir", default="testbed/out/pcap"); p.add_argument("--inventory", default="testbed/inventory.json")
p.add_argument("--bundle", default="bundle"); p.add_argument("--pacs-ip", default="172.28.1.20")
p.add_argument("--dicom-port", type=int, default=104); p.add_argument("--out", default="soc/data/incidents.json")
p.add_argument("--flush-lag", type=float, default=4.0, help="seconds a window waits for late packets before it is scored")
p.add_argument("--truth", default="testbed/out/truth.csv", help="test bed only: ground truth for evaluation mode")
p.add_argument("--pep-dir", default="testbed/out/pep", help="enforce through the test-bed PEP agent (pep-a); 'none' = show commands only")
p.add_argument("--start", default="newest", help="newest (default) | oldest | a capture file name/prefix to catch up from, e.g. tbA_20261116_1225")
a = p.parse_args()

# one controller at a time: two would overwrite each other's gateway instructions and dashboard file
LOCK = Path(a.out).with_name("live.lock")
try:
    other = json.loads(LOCK.read_text())
    if time.time() - other.get("beat", 0) < 15:
        sys.exit(f"another live.py (pid {other.get('pid')}) is already running - stop it first (Ctrl+C in its window)")
except (FileNotFoundError, ValueError):
    pass
def heartbeat():
    try: LOCK.write_text(json.dumps(dict(pid=os.getpid(), beat=time.time())))
    except OSError: pass
heartbeat()
b = Bundle(a.bundle); ex = Explainer(b); inv = Inventory.load(a.inventory)
eng = ResponseEngine(b.policy, inv, "ladder")
truth_file = Path(a.truth)
def truth_of(ip, t, _cache={"m": 0, "f": None}):              # re-read the attack log when it changes (test bed only)
    if not truth_file.exists(): return "?"
    m = max(f.stat().st_mtime for f in truth_file.parent.glob("truth*.csv"))
    if m != _cache["m"]: _cache.update(m=m, f=truth_lookup(load_truth(truth_file)))
    return _cache["f"](ip, t)
trk = IncidentTracker(inv, ex, b.policy, a.pacs_ip, a.dicom_port, truth_of=truth_of, id_prefix="INC-" + time.strftime("%d%H%M"))
fol = PcapFollower(a.pcap_dir, start=a.start); co = Coalescer()
wb = WindowBuilder("TB", a.pacs_ip, a.dicom_port, flush_lag=a.flush_lag, ignore=inv.ignore); oh = OnlineHistory()
pep = None if a.pep_dir == "none" else PepController(a.pep_dir, eng, inv, trk)
meta = dict(source="live", bundle=b.meta["frozen_at"], bundle_dir=a.bundle, model=b.meta["model"], temperature=b.T)
out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
print(f"live: following {a.pcap_dir} (starting at {fol.cur.name if fol.cur else 'next file'}) | bundle {a.bundle} -> {out}")
stats = dict(packets=0, windows=0, alarms=0, score_ms=0.0, last_packet=None, started=time.time())
last_save, last_pkt_wall = 0.0, time.time()

def handle(rows):
    for r in rows:
        trk.decay(eng.expire(r["window_start"]), r["window_start"])
        x = np.array([oh.vector(r)], np.float32); t0 = time.perf_counter()
        rule = np.array([r["preamble_exec"] > 0])
        P, s, atk = b.score(x, rule)
        al, lv = eng.step(r["client_ip"], r["window_start"], float(s[0]), atk[0], bool(rule[0]))
        ci = b.classes.index(atk[0]) if atk[0] in b.classes else None
        trk.step(r["client_ip"], r["window_start"], float(s[0]), atk[0], float(P[0, ci]) if ci is not None else 1.0,
                 al, lv, x[0], bool(rule[0]), r)
        stats["windows"] += 1; stats["alarms"] += int(al)
        stats["score_ms"] = 0.9 * stats["score_ms"] + 0.1 * (time.perf_counter() - t0) * 1000

while True:
    pk = fol.poll(); rows = []
    for t, ip in pk:
        for tt, pp in co.feed(t, ip): rows += wb.feed(tt, pp)
        stats["last_packet"] = t
    if pk: last_pkt_wall = time.time()
    stats["packets"] += len(pk)
    now = stats["last_packet"]
    if now is not None:
        if not pk: now += time.time() - last_pkt_wall          # no packets: let the data clock run with the wall clock
        for tt, pp in co._expire(now): rows += wb.feed(tt, pp)
        rows += wb.tick(now)
    rows.sort(key=lambda r: (r["window_start"], r["client_ip"]))
    handle(rows)
    if time.time() - last_save > 1.0 and now is not None:
        trk.now = max(trk.now or now, now); trk.decay(eng.expire(now), now); trk.refresh_health(now)
        if pep:
            pep.write(now); trk.enforced(pep.new_events())
        trk.system = dict(mode="live",
                          sensor=dict(file=fol.cur.name if fol.cur else None, packets=stats["packets"], last_packet=stats["last_packet"],
                                      packet_age_s=round(time.time() - last_pkt_wall, 1), windows=stats["windows"], late=wb.late,
                                      gro_merged=co.stats["merged"], flush_lag_s=a.flush_lag),
                          model=dict(bundle=b.meta["frozen_at"], bundle_dir=a.bundle, updates=b.meta["n_updates"], features=b.F,
                                     temperature=b.T, score_ms=round(stats["score_ms"], 1)),
                          response=dict(detector="CUSUM", kref=b.policy["detector"]["kref"], h=b.policy["detector"]["h"],
                                        ttl_s=b.policy["ladder"]["ttl_s"], active=len(trk.open), alarms=stats["alarms"]),
                          pep=pep.state() if pep else dict(mode="simulated - commands rendered, not executed"))
        trk.save(out, meta); last_save = time.time(); heartbeat()
    if not pk: time.sleep(0.5)
