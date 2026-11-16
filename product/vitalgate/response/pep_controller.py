"""Policy administrator side of enforcement: writes the wanted level per device for the PEP agent
(testbed/pep/pep_agent.py) and reads back what the gateway really applied.
desired.json: {"seq", "written", "hosts": {ip: {"level", "ttl", "hold"}}, "aets": {AE title: ip}}
ttl = seconds left at the current level (the ladder's TTL since the last alarm or step); the agent turns it into a
kernel timeout and renews only on a new seq, so if this controller stops every action expires (fail-open)."""
import json, os, time
from pathlib import Path


def _write_atomic(path, obj):
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(obj, f)
    for _ in range(40):                                  # Windows: a reader may hold the file for a moment
        try:
            os.replace(tmp, path); return
        except PermissionError:
            time.sleep(0.05)


class PepController:
    def __init__(self, pep_dir, engine, inventory, tracker, feedback_path="soc/data/feedback.json"):
        self.dir = Path(pep_dir); self.dir.mkdir(parents=True, exist_ok=True)
        self.eng, self.inv, self.trk, self.fb = engine, inventory, tracker, Path(feedback_path)
        self.seq, self.pos = 0, 0
        ap = self.dir / "applied.jsonl"
        self.pos = ap.stat().st_size if ap.exists() else 0     # only confirmations from this run

    def _held_hosts(self):
        try:
            fb = json.loads(self.fb.read_text(encoding="utf-8"))
        except Exception:
            return set()
        confirmed = {k for k, v in fb.items() if v.get("verdict") == "true_attack"}
        return {i["host"] for i in self.trk.all if i["id"] in confirmed}

    def write(self, now):
        held = self._held_hosts(); hosts = {}
        for ip, h in self.eng.hosts.items():
            if h.cur > 0:
                hosts[ip] = dict(level=int(h.cur), ttl=round(max(1.0, self.eng.ttl - (now - h.last_step)), 1), hold=ip in held)
        for ip in held:
            hosts.setdefault(ip, dict(level=0, ttl=0, hold=True))
        self.seq += 1
        _write_atomic(self.dir / "desired.json", dict(seq=self.seq, written=time.time(), hosts=hosts, aets=self.inv.aets))

    def new_events(self):
        ap = self.dir / "applied.jsonl"
        if not ap.exists(): return []
        with open(ap, "rb") as f:
            f.seek(self.pos); data = f.read()
        end = data.rfind(b"\n") + 1; self.pos += end
        out = []
        for line in data[:end].splitlines():
            try: out.append(json.loads(line))
            except Exception: pass
        return out

    def state(self):
        try:
            s = json.loads((self.dir / "state.json").read_text(encoding="utf-8"))
        except Exception:
            return dict(mode="no agent", note="PEP agent not running (testbed pep-a)")
        s["age_s"] = round(time.time() - s.get("t", 0), 1)
        s.pop("quarantine_items", None)
        return s
