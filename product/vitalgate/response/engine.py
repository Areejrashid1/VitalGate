"""Layers 4-5: per-host episode detection (CUSUM) and the L0-L4 zero-trust ladder, exactly as replayed in
notebook 06 (response_policy.json). Feed each host's windows in time order: step(ip, t, score, atk, rule).
Levels: 0 allow | 1 watch | 2 restrict | 3 quarantine (DICOM to own PACS stays open) | 4 isolate.
Device criticality caps the automatic level (PACS L2, modality L3). Actions expire after ttl_s (fail-open)."""
import json

CRIT_OF_ROLE_DEFAULT = {"PACS server": "critical", "modality": "high", "workstation": "medium",
                        "attacker (outside host)": "low", "unknown": "low"}


class Inventory:
    """Asset inventory (NIST 800-207 'CDM'): ip -> role. JSON {"ip": "role", ...} or hosts.csv (ip, suggested_role)."""
    def __init__(self, roles=None, crit_of_role=None, names=None, pacs=None, ignore=None, aets=None):
        self.roles = dict(roles or {}); self.crit_of_role = crit_of_role or CRIT_OF_ROLE_DEFAULT
        self.names = dict(names or {}); self.pacs = pacs
        self.ignore = list(ignore or []); self.aets = dict(aets or {})

    @classmethod
    def load(cls, path, crit_of_role=None):
        if str(path).endswith(".json"):
            d = json.load(open(path, encoding="utf-8"))
            cr = {**CRIT_OF_ROLE_DEFAULT, **d.get("criticality", {}), **(crit_of_role or {})}
            return cls(d.get("roles", d), cr, d.get("names"), d.get("pacs"), d.get("ignore"), d.get("aets"))
        import csv
        rows = csv.DictReader(open(path, encoding="utf-8-sig"))
        return cls({r["ip"]: r["suggested_role"] for r in rows}, crit_of_role)

    def name(self, ip):
        return self.names.get(ip) or ("Unregistered device" if ip not in self.roles else self.role(ip))

    def role(self, ip):
        return self.roles.get(ip, "unknown")

    def criticality(self, ip):
        return self.crit_of_role.get(self.role(ip), "low")


class _Host:
    __slots__ = ("prev_t", "S", "cur", "last_alarm", "last_step", "ep_start", "sev", "confs")

    def __init__(self):
        self.prev_t, self.S = -1e18, 0.0
        self.cur, self.last_alarm, self.last_step, self.ep_start, self.sev, self.confs = 0, -1e18, -1e18, None, 0, []


class ResponseEngine:
    def __init__(self, policy, inventory, mode="ladder"):
        det, lad, crit = policy["detector"], policy["ladder"], policy["criticality"]
        if det["kind"] != "cusum":
            raise ValueError("only the CUSUM detector is implemented")
        self.kref, self.h, self.gap = float(det["kref"]), float(det["h"]), float(det["gap_s"])
        # evidence fades with a half-life instead of being wiped after gap_s of silence, so attacks paced just
        # over the gap still add up (default half-life = gap_s; the frozen policy file is not changed)
        self.half_life = float(det.get("half_life_s", self.gap))
        self.kref_host = {ip: float(v) for ip, v in (det.get("per_host_k") or {}).items()}
        self.sev_of = lad["severity"]; self.esc = float(lad["escalate_after_s"]); self.ttl = float(lad["ttl_s"])
        self.max_level = {k: int(v) for k, v in crit["max_level"].items()}
        self.inv = inventory; self.mode = mode; self.hosts = {}

    @staticmethod
    def base_level(sev, conf):
        if sev >= 3: return 4 if conf >= 0.9 else 3
        if sev == 2: return 3 if conf >= 0.9 else 2
        return 2 if conf >= 0.9 else 1

    def expire(self, now):
        """Clock-driven step-down for hosts that sent no window (gateway ipset timeouts run on the clock, fail-open).
        Same rule as step(): one level down per TTL after the last alarm. Returns {ip: (new level, time the last step-down happened)} for changed hosts."""
        changed = {}
        for ip, h in self.hosts.items():
            if h.cur == 0 or now - h.last_alarm < self.ttl: continue
            old = h.cur
            if self.mode == "binary":
                h.cur = 0
            else:
                while h.cur > 0 and now - h.last_step >= self.ttl:
                    h.cur -= 1; h.last_step += self.ttl
            if h.cur == 0: h.ep_start = None
            if h.cur != old: changed[ip] = (h.cur, h.last_step if self.mode != "binary" else h.last_alarm + self.ttl)
        return changed

    def step(self, ip, t, score, atk, rule=False):
        """One window of one host. Returns (alarm, level in force after this window)."""
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = _Host()
        # detection: CUSUM with exponential forgetting (notebook 06 reset S to 0 after a silence > gap_s, which
        # let an attacker pace pulses just over gap_s and never alarm)
        dt = t - h.prev_t
        if dt > 0 and h.S > 0:
            h.S *= 0.5 ** (dt / self.half_life)
        h.S = max(0.0, h.S + score - self.kref_host.get(ip, self.kref))
        alarm = bool(h.S > self.h or rule)
        h.prev_t = t
        # response (notebook 06 replay())
        if alarm:
            if h.ep_start is None or t - h.last_alarm > self.gap:
                h.ep_start, h.sev, h.confs = t, 0, []
            h.sev = max(h.sev, int(self.sev_of.get(atk, 1))); h.confs.append(score); h.last_alarm = h.last_step = t
            if self.mode == "binary":
                want = 4
            else:
                c = h.confs[-5:]
                want = self.base_level(h.sev, sum(c) / len(c))
                if t - h.ep_start >= self.esc: want += 1
                want = min(want, 4, self.max_level[self.inv.criticality(ip)])
            h.cur = max(h.cur, want)                        # never de-escalate during an active episode
        elif h.cur > 0:
            if self.mode == "binary":
                if t - h.last_alarm >= self.ttl: h.cur = 0
            else:
                while h.cur > 0 and t - h.last_step >= self.ttl:
                    h.cur -= 1; h.last_step += self.ttl
            if h.cur == 0: h.ep_start = None
        return alarm, h.cur
