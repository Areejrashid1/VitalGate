"""Offline evaluation of the frozen VitalGate pipeline on test-bed captures (traffic the model never saw).
pcaps -> sensor (windows, 83 features) -> frozen federated model (calibrated) + DPI rule -> CUSUM -> L0-L4 ladder,
scored against the attack log truth.csv. Nothing here is tuned on test-bed traffic.

Usage (from product/):
  python eval/offline_eval.py --pcap-dir testbed/out/pcap --truth testbed/out/truth.csv --out eval/results/tb_0001
Outputs in --out: summary.json, report.md, runs.csv (one row per attack run), windows.csv (every scored window)."""
import argparse, csv, json, sys, time
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.sensor.pcapio import read_pcap
from vitalgate.sensor.windows import WindowBuilder
from vitalgate.sensor.history import OnlineHistory
from vitalgate.model.bundle import Bundle
from vitalgate.response.engine import ResponseEngine, Inventory
from vitalgate import evaluation as E

p = argparse.ArgumentParser()
p.add_argument("--pcap-dir", default="testbed/out/pcap"); p.add_argument("--pattern", default="*.pcap")
p.add_argument("--truth", default="testbed/out/truth.csv"); p.add_argument("--inventory", default="testbed/inventory.json")
p.add_argument("--bundle", default="bundle"); p.add_argument("--out", default="eval/results/latest")
p.add_argument("--site", default="TB"); p.add_argument("--pacs-ip", default="172.28.1.20")
p.add_argument("--dicom-port", type=int, default=104); p.add_argument("--http-port", type=int, default=8042)
p.add_argument("--run-id", default=None, help="only attack runs of this campaign id (truth.csv run_id)")
p.add_argument("--exclude-before", type=float, default=None, help="drop windows before this unix time (e.g. warm-up)")
a = p.parse_args()
out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
T0 = time.time()

# 1 · sensor: pcaps -> 2 s windows per client of the PACS (same code as the training extractor)
files = sorted(Path(a.pcap_dir).glob(a.pattern))
if not files: sys.exit(f"no pcaps in {a.pcap_dir}")
wb = WindowBuilder(a.site, a.pacs_ip, a.dicom_port, a.http_port, flush_lag=10.0)
rows, npkt = [], 0
for f in files:
    for t, ip in read_pcap(f):
        rows += wb.feed(t, ip); npkt += 1
rows += wb.flush_all()
if a.exclude_before: rows = [r for r in rows if r["window_start"] >= a.exclude_before]
print(f"sensor: {len(files)} pcaps, {npkt:,} packets -> {len(rows):,} windows, {wb.late} late packets ({time.time()-T0:.0f}s)")
if not rows: sys.exit("no PACS traffic found: check --pacs-ip / capture point")

# 2 · features (online history per host, as deployed) + model + rule
rows.sort(key=lambda r: (r["window_start"], r["client_ip"]))
oh = OnlineHistory()
X = np.array([oh.vector(r) for r in rows], np.float32)
b = Bundle(a.bundle)
rule = np.array([r["preamble_exec"] > 0 for r in rows])
P, score, atk = b.score(X, rule)
ip = np.array([r["client_ip"] for r in rows]); t = np.array([r["window_start"] for r in rows], float)

# 3 · ground truth: a window belongs to an attack run if it is the run's source host and overlaps its time span
truth = list(csv.DictReader(open(a.truth, encoding="utf-8-sig"))) if Path(a.truth).exists() else []
if a.run_id: truth = [r for r in truth if r["run_id"] == a.run_id]
for k, r in enumerate(truth):
    r["key"] = f"{k:03d}|{r['label_class']}|{r['variant']}|{r['src_ip']}"
    r["start_ts"], r["end_ts"] = float(r["start_ts"]), float(r["end_ts"])
lbl = np.array(["benign"] * len(rows), dtype=object); run = np.array([""] * len(rows), dtype=object)
by_ip = defaultdict(list)
for r in truth: by_ip[r["src_ip"]].append(r)
for i in range(len(rows)):
    for r in by_ip.get(ip[i], ()):
        if t[i] + 2 > r["start_ts"] and t[i] <= r["end_ts"]:
            lbl[i], run[i] = r["label_class"], r["key"]; break
lbl, run = lbl.astype(str), run.astype(str)
span = (t.min(), t.max() + 2)
out_of_scope = [r for r in truth if not (span[0] <= r["start_ts"] <= span[1])]
truth = [r for r in truth if span[0] <= r["start_ts"] <= span[1]]
if out_of_scope: print(f"note: {len(out_of_scope)} attack runs started outside the captured time span - excluded")
T_START = {r["key"]: r["start_ts"] for r in truth}
TR = {r["key"]: r for r in truth}

# 4 · response: CUSUM + ladder (and binary blocking as the baseline), host by host in time order
inv = Inventory.load(a.inventory)
unknown = sorted({x for x in ip if x not in inv.roles})
crit = np.array([inv.criticality(x) for x in ip])
hours = E.wallclock_hours(ip, t)
sev = b.policy["ladder"]["severity"]
res, alarm, level = {}, {}, {}
for mode in ("ladder", "binary"):
    eng = ResponseEngine(b.policy, inv, mode)
    al, lv = np.zeros(len(ip), bool), np.zeros(len(ip), int)
    for i in E.host_order(ip, t):
        al[i], lv[i] = eng.step(ip[i], t[i], float(score[i]), atk[i], bool(rule[i]))
    alarm[mode], level[mode] = al, lv
    res[mode] = E.response_metrics(ip, t, lbl, run, lv, crit, sev, hours, t_start=T_START)
det, det_runs = E.detection_metrics(ip, t, lbl, run, alarm["ladder"], hours, t_start=T_START)
_, cont_runs = res["ladder"]

# 5 · per-run table (runs the sensor never saw count as missed)
RUNS = []
for r in truth:
    k = r["key"]; d = det_runs.get(k); c = cont_runs.get(k)
    m = run == k
    before = (ip == r["src_ip"]) & (t < r["start_ts"]) & (t >= r["start_ts"] - 600)
    lvl0 = int(level["ladder"][before][np.argmax(t[before])]) if before.any() else 0
    RUNS.append(dict(run=k, label_class=r["label_class"], variant=r["variant"], novel=int(r["novel"]), intensity=r["intensity"],
                     src_ip=r["src_ip"], src_role=inv.role(r["src_ip"]), duration_s=round(r["end_ts"] - r["start_ts"], 1),
                     windows=int(m.sum()), seen=bool(m.any()), detected=bool(d and d["hit"]),
                     ttd_s=round(d["delay"], 1) if d and d["hit"] else "", contained=bool(c and c["hit"]),
                     ttc_s=round(c["delay"], 1) if c and c["hit"] else "", max_level=c["max_level"] if c else 0, level_at_start=lvl0,
                     class_correct_share=round(float((atk[m & alarm["ladder"]] == r["label_class"]).mean()), 3) if (m & alarm["ladder"]).any() else "",
                     top_predicted=Counter(atk[m & alarm["ladder"]]).most_common(1)[0][0] if (m & alarm["ladder"]).any() else "",
                     mean_score=round(float(score[m].mean()), 3) if m.any() else ""))
with open(out / "runs.csv", "w", newline="", encoding="utf-8") as f:
    if RUNS:
        w = csv.DictWriter(f, fieldnames=list(RUNS[0])); w.writeheader(); w.writerows(RUNS)

def group(key):
    g = defaultdict(list)
    for r in RUNS: g[key(r)].append(r)
    rows_ = []
    for k, rs in sorted(g.items(), key=lambda kv: str(kv[0])):
        dd = [r["ttd_s"] for r in rs if r["detected"]]; cc = [r["ttc_s"] for r in rs if r["contained"]]
        lo, hi = E.clopper(sum(r["detected"] for r in rs), len(rs))
        rows_.append(dict(group=k, runs=len(rs), detected=sum(r["detected"] for r in rs), ci95=f"[{lo*100:.0f}, {hi*100:.0f}]",
                          contained=sum(r["contained"] for r in rs),
                          median_TTD_s=float(np.median(dd)) if dd else None, median_TTC_s=float(np.median(cc)) if cc else None,
                          class_correct=round(float(np.mean([r["class_correct_share"] for r in rs if r["class_correct_share"] != ""])), 3)
                          if any(r["class_correct_share"] != "" for r in rs) else None))
    return rows_

# 6 · window level (binary score >= 0.5) on benign vs attack windows
ben = lbl == "benign"
win_level = dict(benign_windows=int(ben.sum()), attack_windows=int((~ben).sum()),
                 benign_flagged_share=round(float((score[ben] >= 0.5).mean()), 4) if ben.any() else None,
                 attack_flagged_share=round(float((score[~ben] >= 0.5).mean()), 4) if (~ben).any() else None)
ben_hosts = {x: dict(role=inv.role(x), windows=int(((ip == x) & ben).sum()),
                     flagged_share=round(float((score[(ip == x) & ben] >= 0.5).mean()), 4),
                     alarm_windows=int((alarm["ladder"] & (ip == x) & ben).sum()),
                     max_level=int(level["ladder"][(ip == x) & ben].max()))
             for x in sorted(set(ip[ben]))}

S = dict(created=time.strftime("%Y-%m-%d %H:%M:%S"), bundle=b.meta["frozen_at"], pcaps=len(files), packets=npkt,
         windows=len(rows), host_hours=round(hours, 2), hosts_not_in_inventory=unknown, attack_runs=len(RUNS), runs_outside_capture=len(out_of_scope),
         runs_already_restricted_at_start=sum(r["level_at_start"] > 0 for r in RUNS),
         runs_not_seen_by_sensor=sum(not r["seen"] for r in RUNS),
         detection=dict(runs=len(RUNS), detected=sum(r["detected"] for r in RUNS), false_episodes_per_h=round(det["false_episodes_per_h"], 4),
                        median_TTD_s=float(np.median([r["ttd_s"] for r in RUNS if r["detected"]])) if any(r["detected"] for r in RUNS) else None),
         response={m: dict(contained=sum(1 for r in RUNS if (res[m][1].get(r["run"]) or {}).get("hit")), runs=len(RUNS),
                           median_TTC_s=round(res[m][0]["median_s"], 1) if res[m][0]["runs"] else None,
                           benign_min_restricted_per_h=round(res[m][0]["benign_min_restricted_per_h"], 4),
                           clinical_min_blocked_per_h=round(res[m][0]["clinical_min_blocked_per_h"], 4),
                           false_actions_per_h=round(res[m][0]["false_actions_per_h"], 4)) for m in res},
         window_level=win_level, by_novelty=group(lambda r: "novel" if r["novel"] else "known"),
         by_class=group(lambda r: r["label_class"]), by_variant=group(lambda r: f"{r['label_class']}/{r['variant']}{' (novel)' if r['novel'] else ''}"),
         by_intensity=group(lambda r: r["intensity"]), by_source=group(lambda r: r["src_role"]), benign_hosts=ben_hosts)
(out / "summary.json").write_text(json.dumps(S, indent=1, default=str), encoding="utf-8")

with open(out / "windows.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["client_ip", "window_start", "label", "run", "score", "pred_attack", "rule", "alarm", "level_ladder", "level_binary"])
    for i in E.host_order(ip, t):
        w.writerow([ip[i], int(t[i]), lbl[i], run[i], round(float(score[i]), 4), atk[i], int(rule[i]), int(alarm["ladder"][i]),
                    level["ladder"][i], level["binary"][i]])

def md(rows_, cols):
    s = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    return s + "".join("| " + " | ".join("" if r[c] is None else str(r[c]) for c in cols) + " |\n" for r in rows_)
G = ["group", "runs", "detected", "ci95", "contained", "median_TTD_s", "median_TTC_s", "class_correct"]
rep = [f"# VitalGate test-bed evaluation\n\nFrozen bundle {b.meta['frozen_at']} | {len(files)} pcaps | {len(rows):,} windows | "
       f"{hours:.1f} host-hours | {len(RUNS)} attack runs ({S['runs_not_seen_by_sensor']} not seen by the sensor)\n",
       "## Detection and response\n", md([dict(policy=m, **S["response"][m]) for m in S["response"]],
       ["policy", "contained", "runs", "median_TTC_s", "benign_min_restricted_per_h", "clinical_min_blocked_per_h", "false_actions_per_h"]),
       f"\nDetected {S['detection']['detected']}/{len(RUNS)} runs, median time to detect {S['detection']['median_TTD_s']} s "
       f"(from the attack's real start), false alarm episodes {S['detection']['false_episodes_per_h']} per host-hour.\n",
       "\n## Known vs novel techniques\n", md(S["by_novelty"], G), "\n## By class\n", md(S["by_class"], G),
       "\n## By variant\n", md(S["by_variant"], G), "\n## By intensity\n", md(S["by_intensity"], G),
       "\n## By attack source\n", md(S["by_source"], G),
       "\n## Benign hosts\n", md([dict(host=k, **v) for k, v in ben_hosts.items()], ["host", "role", "windows", "flagged_share", "alarm_windows", "max_level"]),
       f"\n{S['runs_already_restricted_at_start']} runs started while their host was still under an earlier action (level_at_start > 0 in runs.csv): "
       "their containment time can be shorter than their detection time.\n"
       "\n`class_correct` = share of alarmed windows whose predicted attack class equals the true class (novel variants are judged against their parent class).\n"]
(out / "report.md").write_text("".join(rep), encoding="utf-8")
print("".join(rep[:3]) + rep[3] + "\n" + "".join(rep[4:6]))
print(f"saved to {out} ({time.time()-T0:.0f}s)")
