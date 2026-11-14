"""MLflow helpers for VitalGate.

Everything is stored locally in the repo:
    mlflow.db        run metadata (params, metrics, tags)
    mlartifacts/     files logged with runs (models, plots, tables)

View:   mlflow ui --backend-store-uri sqlite:///mlflow.db      (run from the repo root)
"""
import hashlib
import math
import subprocess
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import mlflow
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
DB = REPO / "mlflow.db"
ARTIFACTS = REPO / "mlartifacts"
DATA_FILE = REPO / "data" / "processed" / "windows_v2.parquet"
SESSION = time.strftime("%Y%m%d-%H%M%S")          # one id per notebook/script execution

mlflow.set_tracking_uri(f"sqlite:///{DB.as_posix()}")


def use_experiment(name):
    """Create the experiment (artifacts inside the repo) if needed, and make it active."""
    if mlflow.get_experiment_by_name(name) is None:
        ARTIFACTS.mkdir(exist_ok=True)
        mlflow.create_experiment(name, artifact_location=(ARTIFACTS / name).as_uri())
    mlflow.set_experiment(name)


def git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "no-git"


@lru_cache(maxsize=8)
def _hash(path, mtime):
    return hashlib.md5(Path(path).read_bytes()).hexdigest()[:10]


def data_hash(path=DATA_FILE):
    p = Path(path)
    return _hash(str(p), p.stat().st_mtime) if p.exists() else "missing"


def _param(v):
    s = v if isinstance(v, str) else str(v)
    return s[:6000]


@contextmanager
def run(name, params=None, tags=None, nested=False):
    """with tracking.run("XGBoost final", params={...}, tags={"stage": "final"}): ..."""
    with mlflow.start_run(run_name=name, nested=nested) as r:
        mlflow.set_tags({"git_sha": git_sha(), "data_hash": data_hash(), "session": SESSION,
                         **{k: str(v) for k, v in (tags or {}).items()}})
        if params:
            mlflow.log_params({k: _param(v) for k, v in params.items()})
        yield r


@contextmanager
def resume(run_id):
    """Re-open an earlier run to add more metrics/artifacts to it."""
    with mlflow.start_run(run_id=run_id) as r:
        yield r


def log_metrics(d, step=None, prefix=""):
    """Log every numeric, finite value in a dict; silently skips text."""
    clean = {}
    for k, v in d.items():
        try:
            f = float(v)
        except (TypeError, ValueError):
            continue
        if math.isfinite(f):
            clean[f"{prefix}{k}"] = f
    if clean:
        mlflow.log_metrics(clean, step=step)


def log_seed_summary(rows):
    """rows = list of metric dicts (one per seed). Logs mean as <metric> and std as <metric>_std."""
    df = pd.DataFrame(rows).select_dtypes("number")
    log_metrics(df.mean().to_dict())
    log_metrics({f"{k}_std": v for k, v in df.std().fillna(0).to_dict().items()})
    mlflow.log_param("n_seeds", len(df))


def log_files(*paths):
    for p in paths:
        if p is not None and Path(p).exists():
            mlflow.log_artifact(str(p))


def log_table(df, name):
    """Save a DataFrame as CSV inside the run."""
    tmp = REPO / "reports" / ".mlflow_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    path = tmp / name
    df.to_csv(path, encoding="utf-8-sig")
    mlflow.log_artifact(str(path))


def runs(experiment, filter_string="", order_by=None):
    """All runs of an experiment as a DataFrame (for paper tables)."""
    return mlflow.search_runs(experiment_names=[experiment], filter_string=filter_string,
                              order_by=order_by or ["attributes.start_time DESC"])