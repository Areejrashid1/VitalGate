"""Layer 4: per-alert explanation (notebook 05 section 6). SHAP for the alerted class -> 8 operator-readable
feature groups -> top groups with the strongest feature in each, shown against the benign median of training."""
import json
import numpy as np
from .treeshap import TreeExplainer

RULE_TEXT = {"preamble_polyglot": "DICOM file with an executable (MZ/ELF) preamble uploaded - deterministic DPI rule, no ML"}


class Explainer:
    def __init__(self, bundle):
        self.b = bundle
        cfg = json.loads((bundle.root / "xai_config.json").read_text(encoding="utf-8"))
        self.groups = cfg["groups"]; self.headline = cfg["headline"]; self.expected = cfg["expected"]
        self.median = cfg["benign_median"]
        self.gidx = {g: [bundle.features.index(f) for f in fs] for g, fs in self.groups.items()}
        self.ts = TreeExplainer(bundle)

    @staticmethod
    def _pretty(f):
        return f.replace("_lag1", " (previous window)").replace("_lag2", " (2 windows ago)")

    def explain(self, x, atk, prob, k=3):
        """x: feature vector; atk: alerted class name; prob: its calibrated probability. Returns a dict."""
        if atk not in self.b.classes:                       # rule-only class (polyglot)
            return dict(cls=atk, headline="Executable hidden in a DICOM file (polyglot)", prob=1.0, source="rule",
                        sentence=RULE_TEXT.get(atk, atk), groups=[], consistent=True)
        ci = self.b.classes.index(atk)
        phi, base = self.ts.shap(x, ci)
        gv = {g: float(phi[idx].sum()) for g, idx in self.gidx.items()}
        order = sorted(gv, key=lambda g: -gv[g])[:k]
        parts, groups = [], []
        for g in order:
            if gv[g] <= 0: break
            idx = self.gidx[g]; fi = idx[int(np.argmax(phi[idx]))]; f = self.b.features[fi]
            val = float(x[fi]); med = self.median.get(f)
            groups.append(dict(group=g, shap=round(gv[g], 3), feature=f, label=self._pretty(f),
                               value=None if np.isnan(val) else round(val, 4), benign_median=None if med is None else round(med, 4)))
            parts.append(f"{g} ({self._pretty(f)} = {val:.4g}, normal {med:.4g})" if med is not None else g)
        detail = "; ".join(parts) if parts else "no single feature group stands out (weak, spread-out evidence)"
        return dict(cls=atk, headline=self.headline.get(atk, atk), prob=round(float(prob), 3), source="model",
                    sentence=f"{self.headline.get(atk, atk)} (p={prob:.2f}) - {detail}", groups=groups,
                    all_groups={g: round(v, 3) for g, v in sorted(gv.items(), key=lambda kv: -kv[1])},
                    consistent=bool(order and order[0] in self.expected.get(atk, [])))
