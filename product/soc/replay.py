"""Feed the SOC dashboard by replaying captured test-bed traffic through the frozen pipeline (sensor -> model ->
CUSUM -> ladder -> incidents with explanations). The live detector will write the same incidents.json.

Usage (from product/):
  python soc/replay.py --pcap-dir testbed/out/pcap --speed 30          # stream at 30x real time (demo)
  python soc/replay.py --pcap-dir testbed/out/pcap --instant           # process everything, write once
  options: --from / --to (unix time or HH:MM local), --onboard-until auto (per-host CUSUM k from the pre-attack hour)"""
import argparse, sys, time
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.pipeline import windows_from_pcaps, featurize, load_truth, truth_lookup
from vitalgate.model.bundle import Bundle
from vitalgate.response.engine import ResponseEngine, Inventory
from vitalgate.response.incidents import IncidentTracker
from vitalgate.explain.explainer import Explainer
from vitalgate import evaluation as E

p = argparse.ArgumentParser()
p.add_argument("--pcap-dir", default="testbed/out/pcap"); p.add_argument("--truth", default="testbed/out/truth.csv")
p.add_argument("--inventory", default="testbed/inventory.json"); p.add_argument("--bundle", default="bundle")
p.add_argument("--pacs-ip", default="172.28.1.20"); p.add_argument("--dicom-port", type=int, default=104)
p.add_argument("--out", default="soc/data/incidents.json")
p.add_argument("--speed", type=float, default=30.0); p.add_argument("--instant", action="store_true")
p.add_argument("--from", dest="t_from", type=float, default=None); p.add_argument("--to", dest="t_to", type=float, default=None)
p.add_argument("--onboard-until", default=None)
a = p.parse_args()

files = sorted(Path(a.pcap_dir).glob("*.pcap"))
print(f"reading {len(files)} pcaps ..."); t0 = time.time()
rows = windows_from_pcaps(files, a.pacs_ip, a.dicom_port, ignore=Inventory.load(a.inventory).ignore)
X = featurize(rows)
b = Bundle(a.bundle); ex = Explainer(b)
rule = np.array([r["preamble_exec"] > 0 for r in rows])
P, score, atk = b.score(X, rule)
ip = np.array([r["client_ip"] for r in rows]); t = np.array([r["window_start"] for r in rows], float)
truth = load_truth(a.truth)
if a.onboard_until:
    cut = min(r["start_ts"] for r in truth) if a.onboard_until == "auto" else float(a.onboard_until)
    k0 = float(b.policy["detector"]["kref"])
    b.policy["detector"]["per_host_k"] = {str(x): round(max(k0, float(np.quantile(score[(ip == x) & (t + 2 <= cut)], 0.99))), 4)
                                          for x in set(ip) if ((ip == x) & (t + 2 <= cut)).sum() >= 30}
print(f"{len(rows):,} windows scored in {time.time()-t0:.0f}s")

inv = Inventory.load(a.inventory)
eng = ResponseEngine(b.policy, inv, "ladder")
trk = IncidentTracker(inv, ex, b.policy, a.pacs_ip, a.dicom_port, truth_of=truth_lookup(truth))
meta = dict(source="replay", bundle=b.meta["frozen_at"], model=b.meta["model"], temperature=b.T,
            detector=dict(b.policy["detector"], per_host_k=b.policy["detector"].get("per_host_k", {})),
            onboarding=bool(a.onboard_until), pcaps=len(files))
out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
sel = np.where(((t >= a.t_from) if a.t_from else True) & ((t <= a.t_to) if a.t_to else True))[0] if (a.t_from or a.t_to) else np.arange(len(t))
prev_t, last_save = None, 0.0
for i in sel:                                         # global time order; each host's windows stay in order
    trk.decay(eng.expire(t[i]), t[i])                 # clock-driven timeouts first (a host may have been silent)
    al, lv = eng.step(ip[i], t[i], float(score[i]), atk[i], bool(rule[i]))
    ci = b.classes.index(atk[i]) if atk[i] in b.classes else None
    trk.step(ip[i], t[i], float(score[i]), atk[i], float(P[i, ci]) if ci is not None else 1.0, al, lv, X[i], bool(rule[i]), rows[i])
    trk.refresh_health(t[i])
    trk.system = dict(mode="replay", sensor=dict(last_packet=float(t[i]), windows=int(i) + 1, pcaps=len(files)),
                      model=dict(bundle=b.meta["frozen_at"], updates=b.meta["n_updates"], features=b.F, temperature=b.T),
                      response=dict(detector="CUSUM", kref=b.policy["detector"]["kref"], h=b.policy["detector"]["h"],
                                    ttl_s=b.policy["ladder"]["ttl_s"], active=len(trk.open)),
                      pep=dict(mode="simulated - commands rendered, not executed"))
    if not a.instant:
        step = 0.0 if prev_t is None else min(max(t[i] - prev_t, 0.0), 10.0)   # silent periods (capture off) are skipped
        prev_t = t[i]
        if step > 0:
            if time.time() - last_save > 0.5:
                trk.save(out, meta); last_save = time.time()
            time.sleep(step / a.speed)
trk.save(out, meta)
n = len(trk.all); act = sum(i["status"] == "active" for i in trk.all)
print(f"done: {n} incidents ({act} still active) -> {out}")
