"""Exact path-dependent TreeSHAP (Lundberg et al. 2018, Algorithm 2) for the federated forest, in pure Python.
Same quantity as xgboost predict(pred_contribs=True) used in notebook 05: for class c,
margin_c(x) = prior_c + sum_f phi_c,f(x) + base_c, where base_c = sum over trees of scale * expected tree value.
Only computed for alerted windows and only for the alerted class (about 480 trees), so speed is fine."""
import math
import numpy as np


def _shap_tree(x, left, right, feat, cond, defl, cover, phi, scale):
    def extend(m, pz, po, pi):
        m = [list(e) for e in m]
        l = len(m); m.append([pi, pz, po, 1.0 if l == 0 else 0.0])
        for i in range(l - 1, -1, -1):
            m[i + 1][3] += po * m[i][3] * (i + 1) / (l + 1)
            m[i][3] = pz * m[i][3] * (l - i) / (l + 1)
        return m

    def unwind(m, i):
        m = [list(e) for e in m]
        l = len(m) - 1; n = m[l][3]; po, pz = m[i][2], m[i][1]
        for j in range(l - 1, -1, -1):
            if po != 0:
                t = m[j][3]; m[j][3] = n * (l + 1) / ((j + 1) * po); n = t - m[j][3] * pz * (l - j) / (l + 1)
            else:
                m[j][3] = m[j][3] * (l + 1) / (pz * (l - j))
        for j in range(i, l):
            m[j][0], m[j][1], m[j][2] = m[j + 1][0], m[j + 1][1], m[j + 1][2]
        return m[:-1]

    def unwound_sum(m, i):
        l = len(m) - 1; po, pz = m[i][2], m[i][1]; n = m[l][3]; tot = 0.0
        for j in range(l - 1, -1, -1):
            if po != 0:
                t = n * (l + 1) / ((j + 1) * po); tot += t; n = m[j][3] - t * pz * (l - j) / (l + 1)
            else:
                tot += m[j][3] / (pz * (l - j) / (l + 1))
        return tot

    def recurse(j, m, pz, po, pi):
        m = extend(m, pz, po, pi)
        if left[j] == -1:
            v = cond[j] * scale
            for i in range(1, len(m)):
                phi[m[i][0]] += unwound_sum(m, i) * (m[i][2] - m[i][1]) * v
            return
        xv = x[feat[j]]
        go_left = defl[j] if math.isnan(xv) else xv < cond[j]
        h, c = (left[j], right[j]) if go_left else (right[j], left[j])
        iz = io = 1.0; d = feat[j]
        for k in range(1, len(m)):
            if m[k][0] == d:
                iz, io = m[k][1], m[k][2]; m = unwind(m, k); break
        recurse(h, m, iz * cover[h] / cover[j], io, d)
        recurse(c, m, iz * cover[c] / cover[j], 0.0, d)

    recurse(0, [], 1.0, 1.0, -1)


def _expected(left, right, cond, cover, j=0):
    if left[j] == -1: return cond[j]
    return (cover[left[j]] * _expected(left, right, cond, cover, left[j]) +
            cover[right[j]] * _expected(left, right, cond, cover, right[j])) / cover[j]


class TreeExplainer:
    def __init__(self, bundle):
        self.b = bundle; self.F = bundle.F
        self.by_class = {c: [t for t in bundle.forest.trees if t[6] == c] for c in range(bundle.K)}
        self.base = np.array([bundle.prior[c] + sum(t[7] * _expected(t[0], t[1], t[3], t[5]) for t in self.by_class[c])
                              for c in range(bundle.K)])

    def shap(self, x, cls):
        """x: one feature vector (83). Returns phi (83,) for class index cls (margin space) and the base value."""
        x = [float(v) for v in np.asarray(x, np.float32)]
        phi = [0.0] * self.F
        for left, right, feat, cond, defl, cover, _, scale in self.by_class[cls]:
            _shap_tree(x, left, right, feat, cond, defl, cover, phi, scale)
        return np.array(phi), float(self.base[cls])
