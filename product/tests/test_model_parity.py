"""Check the product's model + response layers reproduce the notebooks on the lab dataset (split_run test).
Expected (notebooks 05/06): federated macro-F1 0.9531; ECE 0.0041 / log-loss 0.0758 at T=0.75;
CUSUM 126/126 runs, 0.027 false episodes/h, median TTD 4 s; ladder vs binary clinical blocked 0 vs 0.10 min/h.
Usage (from product/): python tests/test_model_parity.py --features ../../dicom-lab/out/features_v2.csv
                                                        --hosts ../data/processed/hosts.csv"""
import argparse, csv, sys, time
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.sensor.history import OnlineHistory
from vitalgate.model.bundle import Bundle
from vitalgate.response.engine import ResponseEngine, Inventory
from vitalgate import evaluation as E

p = argparse.ArgumentParser()
p.add_argument("--features", required=True); p.add_argument("--hosts", required=True); p.add_argument("--bundle", default="bundle")
a = p.parse_args()
t0 = time.time()
rows = list(csv.DictReader(open(a.features, encoding="utf-8-sig", newline="")))
NUM = lambda r: {k: (float(v) if v not in ("", None) and k not in ("site", "client_ip", "label_class", "split_run", "attack_run", "run_id", "scenario_id", "intensity", "campaign", "src_kind", "split_block", "split_time", "split_site") else v) for k, v in r.items()}
rows = [NUM(r) for r in rows]
rows.sort(key=lambda r: (r["split_run"], r["client_ip"], r["window_start"]))
oh = OnlineHistory()                                   # history partitioned by split_run, like add_history(d, "split_run")
X = np.array([oh.vector(dict(r, client_ip=r["split_run"] + "|" + r["client_ip"])) for r in rows], np.float32)
te = np.array([r["split_run"] == "test" for r in rows])
rows = [r for r, k in zip(rows, te) if k]; X = X[te]
ip = np.array([r["client_ip"] for r in rows]); t = np.array([r["window_start"] for r in rows], float)
lbl = np.array([r["label_class"] for r in rows]); run = np.array([r.get("attack_run") or "" for r in rows])
rule = np.array([float(r.get("preamble_exec") or 0) > 0 for r in rows])
print(f"{len(rows):,} test windows, features in {time.time()-t0:.0f}s")

b = Bundle(a.bundle)
t1 = time.time(); M = b.margin(X); print(f"scored in {time.time()-t1:.1f}s")
ml = lbl != b.rule_class
yi = np.array([b.classes.index(c) if c in b.classes else -1 for c in lbl])
f1, _ = E.macro_f1(yi[ml], M[ml].argmax(1), list(range(b.K)))
P = b.proba(X[ml]); conf, hit = P.max(1), P.argmax(1) == yi[ml]
ece = sum(((conf > lo) & (conf <= lo + 1/15)).mean() * abs(hit[(conf > lo) & (conf <= lo + 1/15)].mean() - conf[(conf > lo) & (conf <= lo + 1/15)].mean())
          for lo in np.linspace(0, 1, 16)[:-1] if ((conf > lo) & (conf <= lo + 1/15)).any())
ll = -np.log(np.clip(P[np.arange(len(P)), yi[ml]], 1e-12, 1)).mean()
print(f"macro-F1 {f1:.4f} (nb05 0.9531) | ECE {ece:.4f} (nb06 0.0041) | log-loss {ll:.4f} (nb06 0.0758)")

_, score, atk = b.score(X, rule)
inv = Inventory.load(a.hosts)
def role(x):
    r = inv.role(x)
    return r if r != "unknown" else ("PACS server" if x.endswith(".10") else "attacker (outside host)" if x.endswith(".99") else "unknown")
inv.roles = {x: role(x) for x in set(ip)}
crit = np.array([inv.criticality(x) for x in ip])
hours = E.wallclock_hours(ip, t)
for mode in ("ladder", "binary"):
    eng = ResponseEngine(b.policy, inv, mode); alarm = np.zeros(len(ip), bool); level = np.zeros(len(ip), int)
    for i in E.host_order(ip, t):
        alarm[i], level[i] = eng.step(ip[i], t[i], float(score[i]), atk[i], bool(rule[i]))
    if mode == "ladder":
        d, _ = E.detection_metrics(ip, t, lbl, run, alarm, hours)
        print(f"CUSUM: {d['hit']}/{d['runs']} runs, false episodes/h {d['false_episodes_per_h']:.3f}, median TTD {d['median_s']} s, p90 {d['p90_s']} s"
              "   (nb06: 126/126, 0.027, 4, 14)")
    r, _ = E.response_metrics(ip, t, lbl, run, level, crit, b.policy["ladder"]["severity"], hours)
    print(f"{mode:6s}: contained {r['hit']}/{r['runs']}, median TTC {r['median_s']} s, p90 {r['p90_s']} s, benign restricted {r['benign_min_restricted_per_h']:.3f} min/h, "
          f"clinical blocked {r['clinical_min_blocked_per_h']:.3f} min/h, false actions {r['false_actions_per_h']:.3f}/h")
print("nb06: binary 126/126, 4, 14, 0.101, 0.101, 0.027 | ladder 126/126, 4, 14, 0.117, 0.000, 0.027")
