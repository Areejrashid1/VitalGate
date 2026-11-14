"""upgrade_to_v4.py - switch notebook 02 to the v4 features (111). Run once from the repo root:
    python scripts/upgrade_to_v4.py

- backs up the notebook as 02_<name>.v3.ipynb
- FEATURES = FV.FEATURES_V4 (notebooks 03-05 read the feature list from models/xgb_config.json and build
  the features with FV.add_history, so they need no edits)
- size features for the polyglot check also cover the new long-context byte sums
- removes the two one-off feature-test cells ("# === Feature test: ..."), whose results are already saved in
  reports/baselines/feature_test_v4.csv and feature_test_dicom.csv (with v4 they would add columns twice)
Requires data/processed/dicom_cmds.parquet (scripts/extract_dicom.py).
"""
import json, shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EDITS = [
    ("FV.FEATURES_V3", "FV.FEATURES_V4"),
    ("# 83 = 27 base + lag1/lag2 of all 27 + 2 time gaps", "# 111 = v3 (83) + 12 long-context sums + 16 DICOM command counts"),
    ('f.split("_lag")[0] in ("mean_pkt"', 'f.split("_lag")[0].split("_sum")[0] in ("mean_pkt"'),
]

if not (REPO / "data" / "processed" / "dicom_cmds.parquet").exists():
    raise SystemExit("data/processed/dicom_cmds.parquet missing - run scripts/extract_dicom.py first")
nbs = [p for p in REPO.rglob("02_*.ipynb") if ".ipynb_checkpoints" not in p.parts and not p.stem.endswith((".v2", ".v3"))]
if not nbs: raise SystemExit("notebook 02_*.ipynb not found under " + str(REPO))
for nb_path in nbs:
    nb = json.loads(nb_path.read_text(encoding="utf-8"))
    src = lambda c: "".join(c["source"]) if isinstance(c["source"], list) else c["source"]
    done, removed, keep = set(), 0, []
    for c in nb["cells"]:
        if c["cell_type"] == "code" and src(c).lstrip().startswith("# === Feature test:"):
            removed += 1; continue
        if c["cell_type"] == "code":
            s = src(c); s0 = s
            for old, new in EDITS:
                if old in s: s = s.replace(old, new); done.add(old)
            if s != s0:
                c["source"] = s.splitlines(keepends=True); c["outputs"] = []; c["execution_count"] = None
        keep.append(c)
    nb["cells"] = keep
    missing = [o for o, _ in EDITS if o not in done]
    if "FV.FEATURES_V3" in missing: raise SystemExit(f"{nb_path.name}: FEATURES = FV.FEATURES_V3 not found - not changed")
    backup = nb_path.with_name(nb_path.stem + ".v3.ipynb")
    if not backup.exists(): shutil.copy2(nb_path, backup)
    nb_path.write_text(json.dumps(nb, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{nb_path.name}: {len(done)}/{len(EDITS)} edits, {removed} feature-test cell(s) removed, backup {backup.name}"
          + (f" | not found (harmless): {missing}" if missing else ""))
print("Done. Back up models/ and reports/, then Restart & Run All: 02 -> 03 -> 04 -> 05.")
