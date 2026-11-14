"""Upgrade notebooks 02-05 from feature set v2 (32 features) to v3 (83 features: lag1/lag2 of all 27 + time gaps).

Run from the repo root:      python scripts/upgrade_to_v3.py
- Backs up each notebook as <name>.v2.ipynb before editing (only once).
- Applies exact text replacements inside code cells; prints every edit as applied / already applied / NOT FOUND.
- Needs src/features.py in place.
"""
import json, shutil, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NB = REPO 
TARGETS = {"02": "02_baseline.ipynb", "03": "03_federated.ipynb", "04": "04_fl_robustness.ipynb", "05": "05_explainability.ipynb"}
PATCHES = json.loads(r"""{"02": [["ROLL_FEATS = [f\"{b}_roll3\" for b in ROLL_BASE]\nFEATURES   = schema[\"ML_23_MS\"] + schema[\"RATIO_FEATS\"] + ROLL_FEATS          # 32\nNN_FEATURES = [f for f in FEATURES if f != \"n_calling_ae\"]                    # r≈0.998 with n_called_ae\nSIZE_FEATS = [\"mean_pkt\", \"std_pkt\", \"out_bytes\", \"in_bytes\", \"bytes_per_pkt\", \"out_in_byte_ratio\", \"out_bytes_roll3\"]", "ROLL_FEATS = [f\"{b}_roll3\" for b in ROLL_BASE]\nimport features as FV                                                      # v3 feature builder (src/features.py)\nFEATURES   = FV.FEATURES_V3                                                # 83 = 27 base + lag1/lag2 of all 27 + 2 time gaps\nNN_FEATURES = [f for f in FEATURES if not f.startswith(\"n_calling_ae\")]   # r≈0.998 with n_called_ae\nSIZE_FEATS = [f for f in FEATURES if f.split(\"_lag\")[0] in (\"mean_pkt\", \"std_pkt\", \"out_bytes\", \"in_bytes\", \"bytes_per_pkt\", \"out_in_byte_ratio\")]"], ["def add_rolling(frame, part_col):\n    # causal 3-window mean per client, never crossing a partition of part_col\n    f = frame.sort_values([\"client_ip\", \"window_start\"]).copy()\n    g = f.groupby([part_col, \"client_ip\"], sort=False)\n    for b, r in zip(ROLL_BASE, ROLL_FEATS):\n        f[r] = g[b].transform(lambda s: s.rolling(3, min_periods=1).mean())\n    return f.sort_index()", "def add_rolling(frame, part_col):\n    # v3: lag1/lag2 history + time gaps per client, never crossing a partition of part_col (name kept so later cells work unchanged)\n    return FV.add_history(frame, part_col)"], ["lin = RobustScaler().fit(np.log1p(d.loc[TR, NN_FEATURES]))\nL = lambda m: lin.transform(np.log1p(d.loc[m, NN_FEATURES]))\nqt = QuantileTransformer(output_distribution=\"normal\", random_state=0).fit(d.loc[TR, NN_FEATURES])\nQ = lambda m: qt.transform(d.loc[m, NN_FEATURES])", "NN = FV.fill_for_nn(d[NN_FEATURES])                                       # LogReg / MLP cannot take NaN history\nlin = RobustScaler().fit(np.log1p(NN[TR]))\nL = lambda m: lin.transform(np.log1p(NN[m]))\nqt = QuantileTransformer(output_distribution=\"normal\", random_state=0).fit(NN[TR])\nQ = lambda m: qt.transform(NN[m])"], ["config = dict(features=FEATURES, classes=CLS, best_params=BEST, tau=TAU, smoothing=\"2-of-3, 60 s gap\",", "config = dict(feature_version=FV.FEATURE_VERSION, features=FEATURES, classes=CLS, best_params=BEST, tau=TAU, smoothing=\"2-of-3, 60 s gap\","]], "03": [["def add_rolling(frame, part_col):\n    f = frame.sort_values([\"client_ip\", \"window_start\"]).copy()\n    g = f.groupby([part_col, \"client_ip\"], sort=False)\n    for b, r in zip(ROLL_BASE, ROLL_FEATS):\n        f[r] = g[b].transform(lambda s: s.rolling(3, min_periods=1).mean())\n    return f.sort_index()", "import features as FV\ndef add_rolling(frame, part_col):          # v3 history features (src/features.py)\n    return FV.add_history(frame, part_col)"], ["NN_FEATURES = [f for f in FEATURES if f != \"n_calling_ae\"]\nXn = d[NN_FEATURES].to_numpy(np.float64)", "NN_FEATURES = [f for f in FEATURES if not f.startswith(\"n_calling_ae\")]\nXn = FV.fill_for_nn(d[NN_FEATURES]).to_numpy(np.float64)"]], "04": [["d = win[win[\"label_class\"] != RULE_CLASS].reset_index(drop=True)\nd = d.sort_values([\"client_ip\", \"window_start\"])\ng = d.groupby([\"split_run\", \"client_ip\"], sort=False)\nfor b, r in zip(ROLL_BASE, ROLL_FEATS):\n    d[r] = g[b].transform(lambda s: s.rolling(3, min_periods=1).mean())\nd = d.sort_index()", "import features as FV\nd = FV.add_history(win[win[\"label_class\"] != RULE_CLASS].reset_index(drop=True), \"split_run\")   # v3"]], "05": [["d = win[win[\"label_class\"] != RULE_CLASS].reset_index(drop=True).sort_values([\"client_ip\", \"window_start\"])\ng = d.groupby([\"split_run\", \"client_ip\"], sort=False)\nfor b, r in zip(ROLL_BASE, ROLL_FEATS):\n    d[r] = g[b].transform(lambda s: s.rolling(3, min_periods=1).mean())\nd = d.sort_index()", "import features as FV\nd = FV.add_history(win[win[\"label_class\"] != RULE_CLASS].reset_index(drop=True), \"split_run\")   # v3"], ["BENIGN_MEDIAN = pd.Series(np.median(X[TR & (y == BEN)], axis=0), index=FEATURES)", "BENIGN_MEDIAN = pd.Series(np.nanmedian(X[TR & (y == BEN)], axis=0), index=FEATURES)"], ["missing = set(FEATURES) - {f for v in GROUPS.values() for f in v}", "GROUPS[\"Packet size & timing\"] = GROUPS[\"Packet size & timing\"] + [\"gap_s\", \"gap_lag1\"]\nGROUPS = {gname: [f for f in FEATURES if FV.feature_group_of(f, {gname: fs}) == gname] for gname, fs in GROUPS.items()}   # v3: lags join their base feature's group\nmissing = set(FEATURES) - {f for v in GROUPS.values() for f in v}"], ["        parts.append(f\"{GN[gi]} ({f} = {X[TE][row_te, fi]:.4g}, benign median {BENIGN_MEDIAN[f]:.4g})\")", "        fname = f.replace(\"_lag1\", \" (previous window)\").replace(\"_lag2\", \" (2 windows ago)\")\n        parts.append(f\"{GN[gi]} ({fname} = {X[TE][row_te, fi]:.4g}, benign median {BENIGN_MEDIAN[f]:.4g})\")"], ["qt = QuantileTransformer(output_distribution=\"normal\", random_state=0).fit(X[TR])\nmlp = MLPClassifier((128, 64), early_stopping=True, max_iter=200, random_state=SEED).fit(qt.transform(X[TR]), y[TR])\nprint(f\"MLP test macro-F1 {f1_score(yt, mlp.predict(qt.transform(X[TE])), average='macro'):.4f}\")\nprob_xgb = lambda Z: softmax(fed_margin(Z))\nprob_mlp = lambda Z: mlp.predict_proba(qt.transform(Z))", "nnfill = lambda Z: FV.fill_for_nn(pd.DataFrame(Z, columns=FEATURES)).to_numpy()\nqt = QuantileTransformer(output_distribution=\"normal\", random_state=0).fit(nnfill(X[TR]))\nmlp = MLPClassifier((128, 64), early_stopping=True, max_iter=200, random_state=SEED).fit(qt.transform(nnfill(X[TR])), y[TR])\nprint(f\"MLP test macro-F1 {f1_score(yt, mlp.predict(qt.transform(nnfill(X[TE]))), average='macro'):.4f}\")\nprob_xgb = lambda Z: softmax(fed_margin(Z))\nprob_mlp = lambda Z: mlp.predict_proba(qt.transform(nnfill(Z)))"]]}""")

if not (REPO / "src" / "features.py").exists():
    sys.exit("src/features.py is missing - copy it into src/ first")

problems = 0
for key, fname in TARGETS.items():
    path = NB / fname
    if not path.exists():
        print(f"[{key}] {fname}: not found - skipped"); problems += 1; continue
    backup = path.with_suffix(".v2.ipynb")
    if not backup.exists(): shutil.copy(path, backup)
    nb = json.loads(path.read_text(encoding="utf-8"))
    for i, (old, new) in enumerate(PATCHES[key], 1):
        hit = False
        for cell in nb["cells"]:
            if cell["cell_type"] != "code": continue
            src = "".join(cell["source"])
            if new in src: hit = "already"; break
            if old in src:
                src = src.replace(old, new, 1)
                lines = src.split("\n"); cell["source"] = [l + "\n" for l in lines[:-1]] + [lines[-1]]
                cell["outputs"] = []; cell["execution_count"] = None
                hit = True; break
        status = {True: "applied", "already": "already applied", False: "NOT FOUND - edit by hand (see chat)"}[hit]
        if hit is False: problems += 1
        print(f"[{key}] edit {i}/{len(PATCHES[key])}: {status}")
    path.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding="utf-8")
print("\nDone." if not problems else f"\nDone with {problems} problem(s) - see above.")
print("Backups: notebooks/*.v2.ipynb.  Next: back up reports/ and models/, then run 02 -> 03 -> 04 -> 05.")