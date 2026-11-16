"""Federated adaptation: the test-bed hospital (site D) joins the federation with its own normal traffic.

Starts from the frozen deployed model (bundle/: prior + 48 accepted updates) and runs more FedXgbBagging rounds
with 4 clients - the 3 lab sites (their split_run train windows) and site D (benign windows captured 09:53-12:55 on
2026-11-16, before any tb_0003 attack existed). Same protocol as notebooks 03-05: every client grows LOCAL_TREES trees
per round on top of the current global model, every update passes the k-of-n peer-validation gate (f = 1: with 4
sites, 2 of the 3 peers must not get worse on their own validation windows), accepted updates are added with equal
scale 1/n. Early stopping on the pooled validation macro-F1 of all 4 sites. Temperature, CUSUM and ladder unchanged.
Nothing from tb_0003 is used. Output: ../models_adapt/ (same layout as ../models), then freeze it with
  python scripts/freeze_bundle.py --models ../models_adapt --out bundle_adapt
Usage (from product/, needs xgboost - run on the training laptop):
  python adapt/fed_adapt.py [--lab-csv ../../dicom-lab/out/features_v2.csv] [--threads 2] [--dry-run]"""
import argparse, csv, json, os, shutil, sys, time
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.sensor.history import OnlineHistory
from vitalgate.pipeline import windows_from_pcaps, featurize, load_truth
from vitalgate.model.bundle import Bundle
from vitalgate import evaluation as E

p = argparse.ArgumentParser()
p.add_argument("--lab-csv", default="../../dicom-lab/out/features_v2.csv")
p.add_argument("--pcap-dir", default="testbed/out/pcap"); p.add_argument("--truth", default="testbed/out/truth.csv")
p.add_argument("--d-first", default="tbA_20261116_045300.pcap"); p.add_argument("--d-last", default="tbA_20261116_075520.pcap")
p.add_argument("--pacs-ip", default="172.28.1.20"); p.add_argument("--dicom-port", type=int, default=104)
p.add_argument("--bundle", default="bundle"); p.add_argument("--models", default="../models")
p.add_argument("--out", default=None, help="default ../models_adapt_<mode>"); p.add_argument("--rounds", type=int, default=40)
p.add_argument("--patience", type=int, default=6); p.add_argument("--seed", type=int, default=0)
p.add_argument("--threads", type=int, default=2, help="keep low while the test bed runs"); p.add_argument("--dry-run", action="store_true")
p.add_argument("--mode", default="fed-benign", choices=["fed-benign", "fed-labelled", "local-labelled"],
               help="fed-benign: site D sends trees trained on its benign onboarding traffic through the gate | "
                    "fed-labelled: site D also has SOC-labelled history (tb_0001/tb_0002 windows labelled from truth.csv) | "
                    "local-labelled: same data, but site D's trees stay local (personalised model, no gate, not shared)")
a = p.parse_args()
T0 = time.time()
a.out = a.out or f"../models_adapt_{a.mode}"
b = Bundle(a.bundle); FEAT, CLS, K = b.features, b.classes, b.K; BEN = CLS.index("benign")
FED = json.loads((Path(a.models) / "fed_config.json").read_text(encoding="utf-8"))
LT, TOL, F_ASSUMED = FED["local_trees"], FED.get("defence", {}).get("tol", 0.002), FED.get("defence", {}).get("f_assumed", 1)

# ---- lab sites A, B, C: same rows and features as notebook 05 (polyglot excluded, history per split_run)
STR = {"site", "client_ip", "label_class", "split_run", "attack_run", "run_id", "scenario_id", "intensity", "campaign",
       "src_kind", "split_block", "split_time", "split_site"}
rows = [{k: (float(v) if v not in ("", None) and k not in STR else v) for k, v in r.items()}
        for r in csv.DictReader(open(a.lab_csv, encoding="utf-8-sig", newline=""))]
rows = [r for r in rows if r["label_class"] != b.rule_class]
rows.sort(key=lambda r: (r["split_run"], r["client_ip"], r["window_start"]))
oh = OnlineHistory()
XL = np.array([oh.vector(dict(r, client_ip=r["split_run"] + "|" + r["client_ip"])) for r in rows], np.float32)
yL = np.array([CLS.index(r["label_class"]) for r in rows]); site = np.array([r["site"] for r in rows])
part = np.array([r["split_run"] for r in rows])
print(f"lab: {len(rows):,} windows ({time.time()-T0:.0f}s)")

# ---- site D: the test-bed hospital's benign onboarding period
files = [f for f in sorted(Path(a.pcap_dir).glob("*.pcap")) if a.d_first <= f.name <= a.d_last]
drows = windows_from_pcaps(files, a.pacs_ip, a.dicom_port)
XD = featurize(drows); tD = np.array([r["window_start"] for r in drows], float)
truth = load_truth(a.truth)
clash = [r for r in truth if r["start_ts"] <= tD.max() + 2 and r["end_ts"] >= tD.min()]
if clash: sys.exit(f"attack runs overlap the onboarding period: {[(r['run_id'], r['variant']) for r in clash]}")
yD = np.full(len(drows), BEN)
if a.mode == "fed-benign":
    trD = tD < np.quantile(tD, 0.8)                          # by time: first 80 % train, last 20 % validation
else:
    # SOC-labelled history: every captured window before the onboarding period, labelled from the attack log
    # (what analysts would have confirmed / dismissed on the dashboard). Polyglot windows go to the DPI rule, not ML.
    from vitalgate.pipeline import truth_lookup
    hfiles = [f for f in sorted(Path(a.pcap_dir).glob("*.pcap")) if f.name < a.d_first]
    hrows = windows_from_pcaps(hfiles, a.pacs_ip, a.dicom_port)
    lab_of = truth_lookup([r for r in truth if r["run_id"] in ("tb_0001", "tb_0002")])
    hl = [lab_of(r["client_ip"], r["window_start"]).split("/")[0] for r in hrows]
    keep = [i for i, c in enumerate(hl) if c != b.rule_class]
    XH = featurize(hrows)[keep]; yH = np.array([CLS.index(hl[i]) for i in keep]); tH = np.array([hrows[i]["window_start"] for i in keep], float)
    XD, yD, tD = np.concatenate([XH, XD]), np.concatenate([yH, yD]), np.concatenate([tH, tD])
    rng = np.random.default_rng(a.seed); blk = (tD // 600).astype(np.int64)  # 10-minute blocks, 20 % of blocks -> validation
    ub = np.unique(blk); vb = set(rng.choice(ub, max(1, int(0.2 * len(ub))), replace=False).tolist())
    trD = ~np.isin(blk, list(vb))
    print(f"site D labelled history: {len(hfiles)} pcaps -> {len(keep):,} windows, attack windows {int((yH != BEN).sum())}")
print(f"site D: {len(files)} onboarding pcaps -> {len(drows):,} benign windows | site D total train {int(trD.sum())} / val {int((~trD).sum())}"
      f" | mode {a.mode}")

clients = [(XL[(site == s) & (part == "train")], yL[(site == s) & (part == "train")]) for s in ("A", "B", "C")] + [(XD[trD], yD[trD])]
cvals = [(XL[(site == s) & (part == "val")], yL[(site == s) & (part == "val")]) for s in ("A", "B", "C")] + [(XD[~trD], yD[~trD])]
NAMES = ["A", "B", "C", "D"]; n = len(clients)
XLte, yLte = XL[part == "test"], yL[part == "test"]
print("clients:", {nm: len(c[1]) for nm, c in zip(NAMES, clients)}, "| val:", {nm: len(c[1]) for nm, c in zip(NAMES, cvals)})
if a.dry_run:
    m0 = b.margin(XLte); f0, _ = E.macro_f1(yLte, m0.argmax(1), list(range(K)))
    pD = b.proba(cvals[3][0]); print(f"dry run ok | frozen: lab test macro-F1 {f0:.4f} | site D val windows flagged {(1 - pD[:, BEN] >= 0.5).mean():.3f}")
    sys.exit(0)

import xgboost as xgb
def dmat(Xa, ya=None, w=None, margin=None):
    try: return xgb.DMatrix(Xa, label=ya, weight=w, base_margin=margin)
    except Exception: return xgb.DMatrix(Xa, label=ya, weight=w, base_margin=None if margin is None else margin.ravel())
def contrib(bst, Xa):
    return bst.predict(dmat(Xa, margin=np.zeros((len(Xa), K), np.float32)), output_margin=True).reshape(len(Xa), K)
def softmax(m):
    e = np.exp(m - m.max(1, keepdims=True)); return e / e.sum(1, keepdims=True)
def bal_logloss(yv, P):
    p_ = np.clip(P[np.arange(len(yv)), yv], 1e-7, 1); return float(np.mean([-np.log(p_[yv == c]).mean() for c in np.unique(yv)]))
def params(seed):
    return dict(objective="multi:softprob", num_class=K, max_depth=FED["xgb"]["max_depth"], eta=FED["xgb"]["eta"],
                subsample=0.8, colsample_bytree=0.8, tree_method="hist", seed=int(seed), nthread=a.threads)

counts = sum(np.bincount(yc, minlength=K) for _, yc in clients)
w_cls = (counts.max() / np.maximum(counts, 1)) ** 0.5 if FED["xgb"]["class_weights"] == "sqrt" else np.ones(K)
# start from the frozen global model (its margins), exactly where notebook 05 stopped
m_tr = [b.margin(Xc).astype(np.float32) for Xc, _ in clients]; m_cv = [b.margin(Xv) for Xv, _ in cvals]
Xva = np.concatenate([c[0] for c in cvals]); yva = np.concatenate([c[1] for c in cvals]); m_va = b.margin(Xva); m_te = b.margin(XLte)
def val_f1(m): return E.macro_f1(yva, m.argmax(1), list(range(K)))[0]
f_start = val_f1(m_va); NEW, best, since, log = [], dict(f1=f_start, round=0, k=0), 0, []
offered = np.zeros(n); rejected = np.zeros(n)
print(f"start (frozen model): pooled val macro-F1 {f_start:.4f}")
LOCAL = a.mode == "local-labelled"
if LOCAL:
    Xva, yva, m_va = cvals[3][0], cvals[3][1], m_cv[3].copy()
    f_start = val_f1(m_va); best = dict(f1=f_start, round=0, k=0)
    print(f"local mode: only site D trains; start site D val macro-F1 {f_start:.4f}")
for t in range(1, a.rounds + 1):
    for i, (Xc, yc) in enumerate(clients):
        if LOCAL and i != 3: continue
        bst = xgb.train(params(a.seed * 1000 + 500 + t * 10 + i), dmat(Xc, yc, w_cls[yc], m_tr[i]), LT)
        dv = [contrib(bst, cvals[j][0]) for j in range(n)]
        deltas = [bal_logloss(cvals[j][1], softmax(m_cv[j] + dv[j] / n)) - bal_logloss(cvals[j][1], softmax(m_cv[j])) for j in range(n) if j != i]
        offered[i] += 1
        if not LOCAL and np.sum(np.array(deltas) <= TOL) < max(1, (n - 1) - F_ASSUMED):
            rejected[i] += 1; continue
        NEW.append(dict(round=t, client=NAMES[i], booster=bst, scale=1.0 / n))
        for k_, (Xk, _) in enumerate(clients): m_tr[k_] += contrib(bst, Xk) / n
        for k_ in range(n): m_cv[k_] += dv[k_] / n
        m_va += (dv[3] if LOCAL else contrib(bst, Xva)) / n; m_te += contrib(bst, XLte) / n
    f1 = val_f1(m_va); benD = cvals[3][1] == BEN
    fpD = float((1 - softmax(m_cv[3] / b.T)[benD, BEN] >= 0.5).mean())
    log.append(dict(round=t, val_macro_F1=round(f1, 4), siteD_val_flagged=round(fpD, 4), accepted=len(NEW)))
    print(f"round {t:2d} | val macro-F1 {f1:.4f} | site D val flagged {fpD:.3f} | accepted updates {len(NEW)} ({time.time()-T0:.0f}s)")
    if f1 > best["f1"] + 1e-4: best, since = dict(f1=f1, round=t, k=len(NEW)), 0
    else:
        since += 1
        if since >= a.patience: break
NEW = NEW[:best["k"]]
print(f"best round {best['round']} | {len(NEW)} new updates kept | rejected per site {dict(zip(NAMES, [int(v) for v in rejected]))}")

# ---- write ../models_adapt (same layout as ../models), with the new updates appended to the frozen ones
src, out = Path(a.models), Path(a.out)
(out / "fed_xgb").mkdir(parents=True, exist_ok=True)
man = json.loads((Path(a.bundle) / "fed_xgb" / "manifest.json").read_text(encoding="utf-8"))
for u in man["updates"]: shutil.copy2(Path(a.bundle) / "fed_xgb" / u["file"], out / "fed_xgb" / u["file"])
for j, u in enumerate(NEW):
    fn = f"update_adapt_{j:03d}.json"; u["booster"].save_model(str(out / "fed_xgb" / fn))
    man["updates"].append(dict(file=fn, round=f"adapt-{u['round']}", client=u["client"], scale=u["scale"]))
man["adaptation"] = dict(mode=a.mode, scope="site D only (personalised)" if LOCAL else "shared global model",
                         note="site D = test-bed hospital; data before tb_0003 only (onboarding + SOC-labelled tb_0001/tb_0002 if labelled)",
                         onboarding_pcaps=[a.d_first, a.d_last], best_round=best["round"], new_updates=len(NEW),
                         rejected_per_site=dict(zip(NAMES, [int(v) for v in rejected])), log=log)
(out / "fed_xgb" / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
for f in ["response_policy.json", "xai_config.json", "xgb_config.json"]:
    shutil.copy2(src / f, out / f)
FED["adaptation"] = man["adaptation"]; (out / "fed_config.json").write_text(json.dumps(FED, indent=2), encoding="utf-8")

# ---- before / after on data that was not used for training
m_frozen_te = b.margin(XLte)
rep = dict(lab_test_macroF1_frozen=round(E.macro_f1(yLte, m_frozen_te.argmax(1), list(range(K)))[0], 4),
           lab_test_macroF1_adapted=round(E.macro_f1(yLte, m_te.argmax(1), list(range(K)))[0], 4),
           siteD_val_flagged_frozen=round(float((1 - b.proba(cvals[3][0])[cvals[3][1] == BEN, BEN] >= 0.5).mean()), 4),
           siteD_val_flagged_adapted=log[best["round"] - 1]["siteD_val_flagged"] if best["round"] else None,
           new_updates=len(NEW), best_round=best["round"], minutes=round((time.time() - T0) / 60, 1))
(out / "adapt_report.json").write_text(json.dumps(rep, indent=1), encoding="utf-8")
print(json.dumps(rep, indent=1)); print(f"saved {out.resolve()}  ->  next: python scripts/freeze_bundle.py --models {a.out} --out bundle_{a.mode}")
