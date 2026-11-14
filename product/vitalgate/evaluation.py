"""Metrics shared by the lab parity test and the test-bed evaluator. Same definitions as notebook 06.
All inputs are parallel arrays over windows: ip, t (window_start), lbl (true class or 'benign'),
run (attack run id or ''), alarm (bool), level (0-4), crit (criticality of the host)."""
import numpy as np

NEED = {1: 1, 2: 2, 3: 3}          # level an attack of this severity must reach to count as contained


def host_order(ip, t):
    return np.lexsort((t, ip))


def wallclock_hours(ip, t, cap=60.0):
    o = host_order(ip, t); ip, t = ip[o], t[o]
    d = np.diff(t, prepend=np.nan); d[np.r_[True, ip[1:] != ip[:-1]]] = 2.0
    return float(np.clip(d, None, cap).sum() / 3600.0)


def episodes(ip, t, active, gap=60.0, split_on_gap=True):
    ep = np.full(len(ip), -1); cur, prev_ip, prev_t, prev_a = -1, None, -1e18, False
    for i in host_order(ip, t):
        new = ip[i] != prev_ip or (split_on_gap and t[i] - prev_t > gap)
        if active[i]:
            if new or not prev_a: cur += 1
            ep[i] = cur
        prev_a, prev_ip, prev_t = bool(active[i]), ip[i], t[i]
    return ep


def _false_eps(ep, benign):
    eps = {}
    for e, b in zip(ep, benign):
        if e >= 0: eps[e] = eps.get(e, True) and b
    return sum(eps.values())


def clopper(k, n, a=0.05):
    from math import comb
    def cdf(x, p): return sum(comb(n, i) * p**i * (1 - p)**(n - i) for i in range(x + 1))
    def solve(f):
        lo, hi = 0.0, 1.0
        for _ in range(60):
            m = (lo + hi) / 2
            if f(m): lo = m
            else: hi = m
        return lo
    lo = 0.0 if k == 0 else solve(lambda p: 1 - cdf(k - 1, p) < a / 2)
    hi = 1.0 if k == n else solve(lambda p: cdf(k, p) > a / 2)
    return lo, hi


def per_run(ip, t, lbl, run, flag, need=None, t_start=None):
    """flag = alarm (detection) or level>=need (containment). Returns {run: dict(cls, hit, t0, t_hit, delay)}.
    t_start: optional {run: true start time} (test bed: from truth.csv) instead of the first window."""
    out = {}
    for i in np.where((run != "") & (lbl != "benign"))[0]:
        r = out.setdefault(run[i], dict(cls=lbl[i], t0=np.inf, t_hit=np.inf, max_level=0))
        r["t0"] = min(r["t0"], t[i])
        ok = flag[i] if need is None else flag[i] >= NEED[need.get(lbl[i], 1)]
        if ok: r["t_hit"] = min(r["t_hit"], t[i])
        if need is not None: r["max_level"] = max(r["max_level"], int(flag[i]))
    for k, r in out.items():
        t0 = t_start.get(k, r["t0"]) if t_start else r["t0"]
        r["hit"] = bool(np.isfinite(r["t_hit"])); r["delay"] = (r["t_hit"] - t0 + 2) if r["hit"] else np.nan
    return out


def _summ(runs):
    d = np.array([r["delay"] for r in runs.values() if r["hit"]])
    k, n = sum(r["hit"] for r in runs.values()), len(runs)
    lo, hi = clopper(k, n) if n else (np.nan, np.nan)
    return dict(runs=n, hit=k, ci=(lo, hi), median_s=float(np.median(d)) if len(d) else np.nan,
                p90_s=float(np.percentile(d, 90)) if len(d) else np.nan)


def detection_metrics(ip, t, lbl, run, alarm, hours, t_start=None):
    ep = episodes(ip, t, alarm)
    runs = per_run(ip, t, lbl, run, alarm, t_start=t_start)
    return dict(false_episodes_per_h=_false_eps(ep, lbl == "benign") / hours, **_summ(runs)), runs


def response_metrics(ip, t, lbl, run, level, crit, severity, hours, t_start=None):
    ben = lbl == "benign"; clinical = np.isin(crit, ["critical", "high"])
    out = dict(benign_min_restricted_per_h=(ben & (level >= 2)).sum() * 2 / 60 / hours,
               clinical_min_blocked_per_h=(ben & clinical & (level >= 4)).sum() * 2 / 60 / hours)
    ep = episodes(ip, t, level > 0, split_on_gap=False)
    out["false_actions_per_h"] = _false_eps(ep, ben) / hours
    runs = per_run(ip, t, lbl, run, level, need=severity, t_start=t_start)
    out.update(_summ(runs))
    return out, runs


def macro_f1(y, p, labels):
    f = []
    for c in labels:
        tp = np.sum((y == c) & (p == c)); fp = np.sum((y != c) & (p == c)); fn = np.sum((y == c) & (p != c))
        f.append(2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0)
    return float(np.mean(f)), dict(zip(labels, f))
