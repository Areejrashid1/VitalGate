"""Log the notebook-02 results that already exist (reports/baselines/*.csv) into MLflow,
so they can be compared with every future run without re-training.

Run from the repo root:   python scripts/backfill_mlflow.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
import tracking  # noqa: E402
import mlflow    # noqa: E402

REP = REPO / "reports" / "baselines"
MODELS = REPO / "models"
EXP = "vitalgate-detection"
tracking.use_experiment(EXP)
cfg = json.loads((MODELS / "xgb_config.json").read_text(encoding="utf-8")) if (MODELS / "xgb_config.json").exists() else {}
base_tags = {"source": "backfill", "notebook": "02_baselines"}


def split_mean_std(cell):
    s = str(cell)
    if "±" in s:
        m, sd = s.split("±")
        return float(m), float(sd)
    return float(s), None


# 1 · baselines + final XGBoost on split_run test (mean ± std over seeds)
bt = pd.read_csv(REP / "baselines_test.csv", encoding="utf-8-sig").set_index("model")
for model, row in bt.iterrows():
    stage = "final" if model.startswith("XGBoost") else "baseline"
    params = {"n_features": len(cfg.get("features", [])) or 32}
    if stage == "final":
        params.update(cfg.get("best_params", {}))
    with tracking.run(model, params=params, tags={**base_tags, "stage": stage, "split": "split_run/test"}):
        mean, std = {}, {}
        for k, v in row.items():
            m, sd = split_mean_std(v)
            mean[k] = m
            if sd is not None:
                std[f"{k}_std"] = sd
        tracking.log_metrics(mean); tracking.log_metrics(std)
        if stage == "final":
            tracking.log_files(MODELS / "xgb_split_run.json", MODELS / "xgb_config.json",
                               REP / "confusion_xgb_tau.png", REP / "shap_global.png", REP / "tau_curve.png")
print("baselines:", len(bt))

# 2 · XGBoost grid on validation
grid = pd.read_csv(REP / "xgb_grid_val.csv", encoding="utf-8-sig")
for _, r in grid.iterrows():
    name = f"xgb d{int(r['depth'])} lr{r['lr']} w{r['weights']}"
    with tracking.run(name, params={"depth": int(r["depth"]), "lr": r["lr"], "weights": r["weights"]},
                      tags={**base_tags, "stage": "xgb_grid", "split": "split_run/val"}):
        tracking.log_metrics(r.drop(["depth", "lr", "weights"]).to_dict())
print("grid:", len(grid))

# 3 · robustness protocols
rob = pd.read_csv(REP / "robustness.csv", encoding="utf-8-sig", index_col=0)
for proto, r in rob.iterrows():
    with tracking.run(f"XGBoost · {proto}", params=cfg.get("best_params", {}),
                      tags={**base_tags, "stage": "robustness", "protocol": proto}):
        tracking.log_metrics(r.to_dict())
print("robustness:", len(rob))

# 4 · local-only vs centralised
loc = pd.read_csv(REP / "local_vs_central.csv", encoding="utf-8-sig", index_col=0)
for setting, r in loc.iterrows():
    with tracking.run(f"XGBoost · {setting}", params=cfg.get("best_params", {}),
                      tags={**base_tags, "stage": "local_vs_central", "setting": setting}):
        tracking.log_metrics(r.to_dict())
print("local vs central:", len(loc))

# 5 · smoothing
sm = pd.read_csv(REP / "smoothing_test.csv", encoding="utf-8-sig")
for _, r in sm.iterrows():
    det, n = r["runs_detected"].split()[0].split("/")
    with tracking.run(f"XGBoost · smoothing {r['rule']}", params={"rule": r["rule"]},
                      tags={**base_tags, "stage": "smoothing", "split": "split_run/test"}):
        tracking.log_metrics({"alert_windows_per_h": r["alert_windows_per_h"], "episodes_per_h": r["episodes_per_h"],
                              "run_recall": int(det) / int(n), "median_TTD_s": r["median_TTD_s"], "p90_TTD_s": r["p90_TTD_s"]})
print("smoothing:", len(sm))
print(f"\nDone. From the repo root run:\n  mlflow ui --backend-store-uri sqlite:///mlflow.db\nthen open http://127.0.0.1:5000")