"""SOC state: incidents, device health/traffic, and an event feed. Turns the per-window decisions of the response
engine into what the dashboard shows. One incident = one host action episode (opens when the host leaves L0, closes
when it is back at L0). Used identically by soc/replay.py and soc/live.py."""
import json, os, time
from collections import deque
from .pep import commands, LEVEL_NAME, LEVEL_TEXT

SEV_NAME = {1: "low", 2: "medium", 3: "high"}
SERIES = 150            # windows of history kept per device for the traffic charts (~5 min of activity)


class IncidentTracker:
    def __init__(self, inventory, explainer, policy, pacs_ip, dicom_port, site="TB", truth_of=None, id_prefix="INC"):
        self.inv, self.ex, self.pol = inventory, explainer, policy
        self.pacs_ip, self.port, self.site = pacs_ip, dicom_port, site
        self.ttl = int(policy["ladder"]["ttl_s"]); self.sev = policy["ladder"]["severity"]
        self.truth_of = truth_of; self.prefix = id_prefix      # live runs: a per-run prefix keeps analyst verdicts unique
        self.open, self.all, self.n = {}, [], 0
        self.hosts, self.events, self.now = {}, deque(maxlen=400), None
        self.system = {}
        for ip in inventory.roles:
            if ip != (inventory.pacs or pacs_ip) and ip not in inventory.ignore: self._host(ip, seen=False)

    def _host(self, ip, seen=True):
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = dict(ip=ip, name=self.inv.name(ip), role=self.inv.role(ip), criticality=self.inv.criticality(ip),
                                      registered=ip in self.inv.roles, level=0, first_seen=None, last_seen=None, last_score=0.0,
                                      windows=0, alarms=0, incidents=0, series=deque(maxlen=SERIES), status="not seen")
            if seen and ip not in self.inv.roles:
                self._event("new_device", ip, None, f"Unregistered device {ip} started talking to the PACS")
        return h

    def _event(self, kind, ip, t, text, inc=None, level=None):
        self.events.appendleft(dict(t=t if t is not None else self.now, kind=kind, host=ip,
                                    name=self.inv.name(ip) if ip else None, text=text, incident=inc, level=level))

    def step(self, ip, t, score, atk, prob, alarm, level, x, rule=False, row=None):
        self.now = t if self.now is None else max(self.now, t)
        h = self._host(ip); prev = h["level"]
        if h["first_seen"] is None: h["first_seen"] = t
        if h["status"] == "offline":
            self._event("device_online", ip, t, f"{h['name']} is back online")
        h.update(level=int(level), last_seen=t, last_score=round(float(score), 3), status="online")
        h["windows"] += 1; h["alarms"] += int(alarm)
        if row is not None:
            err = int(row.get("assoc_rj", 0) + row.get("abort", 0) + row.get("rst", 0) + row.get("bad_first_pdu", 0))
            h["series"].append([int(t), int(row["out_bytes"]), int(row["in_bytes"]), round(float(score), 3), int(level), int(alarm), err])
        inc = self.open.get(ip)
        if inc is None and level > 0:
            self.n += 1; h["incidents"] += 1
            inc = self.open[ip] = dict(id=f"{self.prefix}-{self.n:04d}", site=self.site, host=ip, name=h["name"], role=h["role"],
                                       criticality=h["criticality"], status="active", opened=t, updated=t, closed=None,
                                       level=int(level), max_level=int(level), cls=atk,
                                       severity=SEV_NAME.get(int(self.sev.get(atk, 1)), "low"), max_score=float(score),
                                       windows=0, alarm_windows=0, timeline=[], explanations=[], actions=[], truth=[],
                                       peak=dict(out_bytes=0, in_bytes=0))
            self.all.append(inc)
        if inc is None:
            return None
        inc["updated"] = t; inc["windows"] += 1; inc["alarm_windows"] += int(alarm)
        inc["timeline"].append([int(t), round(float(score), 3), int(level), int(alarm)])
        if row is not None:
            inc["peak"]["out_bytes"] = max(inc["peak"]["out_bytes"], int(row["out_bytes"]))
            inc["peak"]["in_bytes"] = max(inc["peak"]["in_bytes"], int(row["in_bytes"]))
        if self.truth_of:
            lab = self.truth_of(ip, t)
            if lab not in inc["truth"]: inc["truth"].append(lab)
        if alarm and int(self.sev.get(atk, 1)) >= int(self.sev.get(inc["cls"], 1)) and (atk != inc["cls"] or score > inc["max_score"]):
            inc["cls"] = atk; inc["severity"] = SEV_NAME.get(int(self.sev.get(atk, 1)), "low")
        explain_now = alarm and (not inc["explanations"] or level > inc["max_level"] or score > inc["max_score"] + 0.05)
        inc["max_score"] = max(inc["max_score"], float(score))
        if level != prev or not inc["actions"]:
            inc["actions"].append(dict(t=int(t), level=int(level), name=LEVEL_NAME[int(level)], text=LEVEL_TEXT[int(level)],
                                       commands=commands(ip, int(level), self.ttl, self.pacs_ip, self.port) if level else
                                       ["# all ipset entries expired (fail-open)"]))
        if explain_now and len(inc["explanations"]) < 6:
            e = self.ex.explain(x, atk, prob) if self.ex else dict(cls=atk, sentence=atk, groups=[])
            e["t"] = int(t); e["level"] = int(level); e["score"] = round(float(score), 3)
            inc["explanations"].append(e)
        head = (inc["explanations"][-1] if inc["explanations"] else {}).get("headline", atk)
        if inc["windows"] == 1:
            self._event("incident_opened", ip, t, f"{inc['id']} opened: {head} on {h['name']} -> L{level} {LEVEL_NAME[int(level)]}", inc["id"], int(level))
        elif level != prev:
            self._event("level_up" if level > prev else "level_down", ip, t,
                        f"{inc['id']} {h['name']}: L{prev} -> L{level} {LEVEL_NAME[int(level)]}", inc["id"], int(level))
        inc["level"] = int(level); inc["max_level"] = max(inc["max_level"], int(level))
        if level == 0:
            inc["status"] = "closed"; inc["closed"] = t; del self.open[ip]
            self._event("incident_closed", ip, t, f"{inc['id']} closed: {h['name']} back to normal (actions expired)", inc["id"], 0)
        return inc

    def decay(self, changed, now):
        """Apply clock-driven level changes from ResponseEngine.expire() to hosts and open incidents."""
        clock = now
        for ip, (lv, when) in changed.items():
            now = min(clock, when)                  # when the timeout really fired (the clock may have jumped a gap)
            h = self.hosts.get(ip)
            if not h: continue
            prev = h["level"]; h["level"] = int(lv); inc = self.open.get(ip)
            if not inc or lv == prev: continue
            inc["level"] = int(lv); inc["updated"] = now
            inc["actions"].append(dict(t=int(now), level=int(lv), name=LEVEL_NAME[int(lv)], text=LEVEL_TEXT[int(lv)],
                                       commands=commands(ip, int(lv), self.ttl, self.pacs_ip, self.port) if lv else
                                       ["# all ipset entries expired (fail-open)"]))
            if lv == 0:
                inc["status"] = "closed"; inc["closed"] = now; del self.open[ip]
                self._event("incident_closed", ip, now, f"{inc['id']} closed: {h['name']} back to normal (actions expired)", inc["id"], 0)
            else:
                self._event("level_down", ip, now, f"{inc['id']} {h['name']}: L{prev} -> L{lv} {LEVEL_NAME[int(lv)]} (timeout)", inc["id"], int(lv))

    def enforced(self, events):
        """Attach the PEP agent's confirmations (applied.jsonl) to incident actions and the event feed."""
        for ev in events:
            ip, kind = ev.get("ip"), ev.get("event")
            if kind not in ("level", "removed", "expired") or not ip: continue
            to = int(ev.get("to", 0)); inc = self.open.get(ip) or next((i for i in reversed(self.all) if i["host"] == ip), None)
            if inc:
                for a in reversed(inc["actions"]):
                    if a["level"] == to and "applied" not in a:
                        a["applied"] = ev["t"]; a["applied_ok"] = bool(ev.get("ok", True)); break
            name = self.inv.name(ip)
            if kind == "level":
                self._event("enforced", ip, ev["t"], f"Gateway applied L{to} {('watch','watch','restrict','quarantine','isolate')[to]} to {name}"
                            + (" and reset its open connections" if ev.get("conntrack_flushed") else ""), inc and inc["id"], to)
            elif kind == "expired":
                self._event("enforced", ip, ev["t"], f"Gateway entry for {name} expired on its own (fail-open)", inc and inc["id"], 0)

    def refresh_health(self, now, idle_s=60, offline_s=600):
        """Device status from the data clock: online (active in the last minute), idle, offline (> 10 min silent)."""
        for ip, h in self.hosts.items():
            if h["last_seen"] is None: continue
            age = now - h["last_seen"]
            st = "online" if age <= idle_s else "idle" if age <= offline_s else "offline"
            if st == "offline" and h["status"] != "offline" and h["registered"]:
                self._event("device_offline", ip, now, f"{h['name']} has been silent for 10 minutes")
            h["status"] = st

    def snapshot(self):
        hosts = []
        for h in sorted(self.hosts.values(), key=lambda h: h["ip"]):
            d = dict(h); d["series"] = list(h["series"]); hosts.append(d)
        return dict(generated=time.time(), data_time=self.now, site=self.site, incidents=self.all, hosts=hosts,
                    events=list(self.events), system=self.system,
                    pacs=dict(ip=self.pacs_ip, port=self.port, name=self.inv.name(self.pacs_ip)))

    def save(self, path, meta=None):
        s = self.snapshot(); s["meta"] = meta or {}
        tmp = f"{path}.{os.getpid()}.tmp"                # own temp file per process
        with open(tmp, "w", encoding="utf-8") as f: json.dump(s, f, default=float)
        for attempt in range(40):             # Windows: the dashboard may be reading the file -> retry briefly
            try:
                os.replace(tmp, path); return
            except PermissionError:
                time.sleep(0.05)
