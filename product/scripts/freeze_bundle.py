"""Freeze the deployed model: copy the trained artefacts from ../models into product/bundle and record SHA-256
hashes in bundle/BUNDLE.json. The product refuses to load a bundle whose files changed (Bundle(verify=True)).
Re-run only after retraining in the notebooks (then the test-bed results must be re-run too).
Usage (from product/):  python scripts/freeze_bundle.py [--models ../models] [--out bundle]"""
import argparse, json, shutil, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vitalgate.model.bundle import sha256

p = argparse.ArgumentParser(); p.add_argument("--models", default="../models"); p.add_argument("--out", default="bundle")
a = p.parse_args()
src, out = Path(a.models), Path(a.out)
if out.exists() and (out / "BUNDLE.json").exists() and "--force" not in sys.argv:
    old = json.loads((out / "BUNDLE.json").read_text(encoding="utf-8"))
    print(f"note: replacing bundle frozen at {old.get('frozen_at')}")
(out / "fed_xgb").mkdir(parents=True, exist_ok=True)
for f in (out / "fed_xgb").glob("*.json"):
    f.unlink()
man = json.loads((src / "fed_xgb" / "manifest.json").read_text(encoding="utf-8"))
files = ["fed_xgb/manifest.json"] + [f"fed_xgb/{u['file']}" for u in man["updates"]]
for f in files:
    shutil.copy2(src / f, out / f)
for f in ["response_policy.json", "xai_config.json", "xgb_config.json", "fed_config.json"]:
    shutil.copy2(src / f, out / f); files.append(f)
pol = json.loads((out / "response_policy.json").read_text(encoding="utf-8"))
meta = dict(frozen_at=time.strftime("%Y-%m-%d %H:%M:%S"), source=str(src.resolve()),
            model="federated XGBoost (FedXgbBagging, equal 1/n scaling, k-of-n peer-validation gate)",
            n_updates=len(man["updates"]), n_features=len(man["features"]), classes=man["classes"],
            temperature=pol["model"]["temperature"], detector=pol["detector"]["name"],
            sha256={f: sha256(out / f) for f in files})
(out / "BUNDLE.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
print(f"frozen {len(files)} files -> {out.resolve()} | {meta['n_updates']} updates, {meta['n_features']} features, T={meta['temperature']}")
