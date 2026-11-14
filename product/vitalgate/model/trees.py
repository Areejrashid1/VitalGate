"""Pure-numpy evaluator for XGBoost JSON boosters (gbtree, numeric splits). No xgboost needed at run time.
XGBoost rule: go left if x < split_condition (float32); missing value (NaN) follows default_left.
Prediction here = sum of leaf values only (same as xgboost predict(..., base_margin=0, output_margin=True)),
which is how the federated model was built: margin = prior + sum(scale_u * trees_u(x))."""
import json
import numpy as np


class Forest:
    def __init__(self, n_class, n_feature):
        self.K, self.F = n_class, n_feature
        self._left, self._right, self._feat, self._cond, self._defl, self._val = [], [], [], [], [], []
        self.roots, self.tree_class, self.tree_scale = [], [], []
        self._n = 0

    def add_booster(self, path, scale=1.0):
        m = json.load(open(path, encoding="utf-8"))
        L = m["learner"]; g = L["gradient_booster"]
        if g["name"] != "gbtree":
            raise ValueError(f"{path}: only gbtree is supported")
        if int(L["learner_model_param"]["num_feature"]) != self.F:
            raise ValueError(f"{path}: expects {L['learner_model_param']['num_feature']} features, bundle has {self.F}")
        for tree, cls in zip(g["model"]["trees"], g["model"]["tree_info"]):
            if any(t != 0 for t in tree.get("split_type", [])):
                raise ValueError(f"{path}: categorical splits are not supported")
            l = np.asarray(tree["left_children"], np.int64); r = np.asarray(tree["right_children"], np.int64)
            leaf = l == -1
            idx = np.arange(len(l)) + self._n
            self._left.append(np.where(leaf, idx, l + self._n)); self._right.append(np.where(leaf, idx, r + self._n))
            self._feat.append(np.where(leaf, 0, np.asarray(tree["split_indices"], np.int64)))
            cond = np.asarray(tree["split_conditions"], np.float32)
            self._cond.append(cond); self._defl.append(np.asarray(tree["default_left"], bool))
            self._val.append(np.where(leaf, cond, 0).astype(np.float64))    # leaf value is stored in split_conditions
            self.roots.append(self._n); self.tree_class.append(int(cls)); self.tree_scale.append(float(scale))
            self._n += len(l)
        return self

    def compile(self):
        cat = lambda xs: np.concatenate(xs)
        self.left, self.right, self.feat = cat(self._left), cat(self._right), cat(self._feat)
        self.cond, self.defl, self.val = cat(self._cond), cat(self._defl), cat(self._val)
        self.roots = np.asarray(self.roots, np.int64)
        T = len(self.roots)
        self.W = np.zeros((T, self.K)); self.W[np.arange(T), self.tree_class] = self.tree_scale   # tree -> class, scaled
        self.isleaf = self.left == np.arange(len(self.left))
        return self

    def margin(self, X, chunk=1024):
        """X: (n, F) float array (NaN = missing). Returns (n, K) summed scaled leaf values."""
        X = np.asarray(X, np.float32)
        out = np.zeros((len(X), self.K))
        for s in range(0, len(X), chunk):
            x = X[s:s + chunk]; n = len(x); rows = np.arange(n)[:, None]
            node = np.broadcast_to(self.roots, (n, len(self.roots))).copy()
            while True:
                active = ~self.isleaf[node]
                if not active.any():
                    break
                v = x[rows, self.feat[node]]
                go_left = np.where(np.isnan(v), self.defl[node], v < self.cond[node])
                node = np.where(active, np.where(go_left, self.left[node], self.right[node]), node)
            out[s:s + n] = self.val[node] @ self.W
        return out
