"""Layer 3: the frozen deployed model. Loads product/bundle (copied from models/ by scripts/freeze_bundle.py):
federated XGBoost (prior + sum scale*update), temperature T, and the response policy.
score(X) -> calibrated probabilities, attack score (1 - P(benign)) and most likely attack class."""
import hashlib
import json
from pathlib import Path
import numpy as np
from .trees import Forest


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Bundle:
    def __init__(self, root, verify=True):
        self.root = Path(root)
        meta = json.loads((self.root / "BUNDLE.json").read_text(encoding="utf-8"))
        if verify:
            bad = [f for f, h in meta["sha256"].items() if sha256(self.root / f) != h]
            if bad:
                raise RuntimeError(f"bundle files changed since freezing: {bad[:5]}")
        self.meta = meta
        man = json.loads((self.root / "fed_xgb" / "manifest.json").read_text(encoding="utf-8"))
        self.policy = json.loads((self.root / "response_policy.json").read_text(encoding="utf-8"))
        self.features, self.classes = man["features"], man["classes"]
        self.K, self.F = len(self.classes), len(self.features)
        self.BEN = self.classes.index("benign")
        self.prior = np.asarray(man["prior"], np.float64)
        self.T = float(self.policy["model"]["temperature"])
        self.rule_class = "preamble_polyglot"
        f = Forest(self.K, self.F)
        for u in man["updates"]:
            f.add_booster(self.root / "fed_xgb" / u["file"], float(u["scale"]))
        self.forest = f.compile()

    def margin(self, X):
        return self.prior + self.forest.margin(X)

    def proba(self, X):
        z = self.margin(X) / self.T
        e = np.exp(z - z.max(1, keepdims=True))
        return e / e.sum(1, keepdims=True)

    def score(self, X, rule=None):
        """Returns P (n,K), score (n,) = 1-P(benign), atk (n,) = most likely attack class name.
        rule: bool array, preamble_exec fired -> score 1, class preamble_polyglot (DPI rule overrides the model)."""
        P = self.proba(X)
        s = 1.0 - P[:, self.BEN]
        PA = P.copy(); PA[:, self.BEN] = -1
        atk = np.array(self.classes, dtype=object)[PA.argmax(1)]
        if rule is not None:
            rule = np.asarray(rule, bool); s = np.where(rule, 1.0, s); atk[rule] = self.rule_class
        return P, s, atk
