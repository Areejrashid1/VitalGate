"""VitalGate PEP agent (runs in the PACS network namespace, NET_ADMIN).

Policy administrator -> agent: /out/pep/desired.json, written about once a second by the VitalGate controller
(soc/live.py): {"seq": n, "written": t, "hosts": {ip: {"level": 0-4, "ttl": seconds left at this level, "hold": bool}},
"aets": {AE title: ip}}. The agent turns it into nftables set elements with a timeout. It only renews an element
when it sees a NEW seq that extends it, so if the controller stops, every element expires in the kernel (fail-open).

Logs (all times are this container's clock, the same clock the attack scripts use for truth.csv):
  /out/pep/applied.jsonl     one line per change: level up/down, removals, expiries seen, conntrack flushes
  /out/pep/state.json        current set elements + rule counters + quarantine summary (dashboard)
  /out/pep/quarantine.jsonl  every image held in the quarantine store: received, checked, released or blocked
"""
import json, os, subprocess, time, urllib.request, urllib.error

D = os.environ.get("PEP_DIR", "/out/pep")
DESIRED, STATE, LOG, QLOG = (os.path.join(D, f) for f in ("desired.json", "state.json", "applied.jsonl", "quarantine.jsonl"))
QSTORE = os.environ.get("QSTORE", "http://172.28.1.21:8042")
SETS = {1: "watch", 2: "rate", 3: "quar", 4: "iso"}
os.makedirs(D, exist_ok=True)


def log(path, **row):
    row.setdefault("t", round(time.time(), 3))
    with open(path, "a") as f: f.write(json.dumps(row) + "\n")


def nft(script):
    r = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True)
    return r.returncode == 0, r.stderr.strip()


def conntrack(*args):
    try:
        r = subprocess.run(["conntrack", "-D", *args], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return r.returncode == 0 or "0 flow entries" in (r.stderr + r.stdout)


def kernel_sets():
    """{set: {ip: seconds left}} straight from the kernel."""
    out = {}
    for s in SETS.values():
        r = subprocess.run(["nft", "-j", "list", "set", "ip", "vg", s], capture_output=True, text=True)
        el = {}
        try:
            for x in json.loads(r.stdout)["nftables"]:
                for e in x.get("set", {}).get("elem", []):
                    e = e.get("elem", e)
                    if isinstance(e, dict): el[e["val"]] = e.get("expires", e.get("timeout", 0))
                    else: el[e] = 0
        except Exception:
            pass
        out[s] = el
    return out


def counters():
    r = subprocess.run(["nft", "-j", "list", "table", "ip", "vg"], capture_output=True, text=True)
    c = {}
    try:
        for x in json.loads(r.stdout)["nftables"]:
            rule = x.get("rule")
            if not rule: continue
            name = None; pk = by = 0
            for ex in rule["expr"]:
                if "match" in ex and isinstance(ex["match"].get("right"), str) and ex["match"]["right"].startswith("@"):
                    name = ex["match"]["right"][1:]
                if "counter" in ex: pk, by = ex["counter"]["packets"], ex["counter"]["bytes"]
            verdict = "dnat" if any("dnat" in ex for ex in rule["expr"]) else "masq" if any("masquerade" in ex for ex in rule["expr"]) \
                else "drop" if any("drop" in ex for ex in rule["expr"]) else "count"
            c[f"{rule['chain']}:{name or '-'}:{verdict}"] = dict(packets=pk, bytes=by)
    except Exception:
        pass
    return c


STALE_S = float(os.environ.get("STALE_S", "10"))


def read_desired():
    """The controller's latest wish, or None when it is older than STALE_S: a dead controller's leftover file must
    never create or renew an action (fail-open), e.g. after this agent restarts."""
    try:
        if time.time() - os.path.getmtime(DESIRED) > STALE_S: return None
        with open(DESIRED) as f: return json.load(f)
    except Exception:
        return None


# ------------------------------------------------------------------------------------------------ quarantine store
def http(method, path, body=None, timeout=10):
    req = urllib.request.Request(QSTORE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data) if data[:1] in (b"{", b"[") else data


class Quarantine:
    """Images that a quarantined device sent (redirected by the PEP) wait here. Each is checked (executable preamble);
    clean images are released to the PACS once the device is no longer quarantined, unless an analyst confirmed an
    attack on it (hold). Images with an executable preamble are never released."""
    def __init__(self):
        self.items, self.since, self.last = {}, 0, 0.0

    def poll(self, desired):
        if time.time() - self.last < 3: return
        self.last = time.time()
        try:
            ch = http("GET", f"/changes?since={self.since}&limit=200")
        except Exception as e:
            return
        for c in ch.get("Changes", []):
            if c.get("ChangeType") == "NewInstance" and c["ID"] not in self.items:
                self._receive(c["ID"], desired)
        self.since = ch.get("Last", self.since)
        self._release(desired)

    def _receive(self, iid, desired):
        try:
            meta = http("GET", f"/instances/{iid}/metadata?expand")
            tags = http("GET", f"/instances/{iid}/simplified-tags")
            raw = http("GET", f"/instances/{iid}/file", timeout=30)
        except Exception as e:
            log(QLOG, event="error", instance=iid, error=str(e)[:200]); return
        pre = raw[:128] if isinstance(raw, (bytes, bytearray)) else b""
        exe = pre[:2] == b"MZ" or pre[:4] == b"\x7fELF"
        aet = (meta.get("RemoteAET") or "").strip()
        ip = (desired or {}).get("aets", {}).get(aet, "unknown")
        it = dict(instance=iid, sop=tags.get("SOPInstanceUID"), aet=aet, ip=ip, received=time.time(),
                  bytes=len(raw) if isinstance(raw, (bytes, bytearray)) else 0,
                  check="executable-preamble" if exe else "clean", status="blocked" if exe else "held")
        self.items[iid] = it
        log(QLOG, event="received", **{k: v for k, v in it.items() if k != "received"})
        if exe: log(QLOG, event="blocked", instance=iid, sop=it["sop"], reason="executable in the DICOM preamble: never released")

    def _release(self, desired):
        hosts = (desired or {}).get("hosts", {})
        ready = {}
        for iid, it in self.items.items():
            if it["status"] != "held": continue
            h = hosts.get(it["ip"], {})
            if h.get("hold"):
                if it.get("why") != "hold": it["why"] = "hold"; log(QLOG, event="kept", instance=iid, reason="analyst confirmed an attack on the device")
                continue
            if h.get("level", 0) >= 3: continue                      # device still quarantined
            ready.setdefault(it["ip"], []).append(iid)
        for ip, ids in ready.items():
            try:
                http("POST", "/modalities/pacs/store", {"Resources": ids, "Synchronous": True}, timeout=120)
            except Exception as e:
                log(QLOG, event="release-failed", ip=ip, instances=len(ids), error=str(e)[:200]); continue
            now = time.time()
            for iid in ids:
                it = self.items[iid]; it["status"] = "released"; it["released"] = now
                log(QLOG, event="released", instance=iid, sop=it["sop"], aet=it["aet"], ip=ip, held_s=round(now - it["received"], 1))
                try: http("DELETE", f"/instances/{iid}")
                except Exception: pass

    def summary(self):
        s = {"held": 0, "released": 0, "blocked": 0}
        for it in self.items.values(): s[it["status"]] = s.get(it["status"], 0) + 1
        return s


# ------------------------------------------------------------------------------------------------ main loop
def main():
    ok, err = nft("table ip vg\ndelete table ip vg\n" + open(os.environ.get("RULES", "/app/rules.nft")).read())   # only our own table; Docker's stay
    log(LOG, event="start", ok=ok, error=err or None)
    if not ok: raise SystemExit(f"nftables rules failed: {err}")
    cur = {}           # ip -> {"level": L, "expires": agent time}
    seen_seq, last_state, q = None, 0.0, Quarantine()
    while True:
        d = read_desired()
        if d and d.get("seq") != seen_seq:
            seen_seq = d.get("seq"); now = time.time()
            want = {ip: h for ip, h in d.get("hosts", {}).items() if h.get("level", 0) > 0}
            for ip in set(cur) | set(want):
                old = cur.get(ip, {}).get("level", 0); new = want.get(ip, {}).get("level", 0)
                if new == 0:
                    if old:
                        nft(f"delete element ip vg {SETS[old]} {{ {ip} }}")
                        log(LOG, event="removed", ip=ip, frm=old, to=0, seq=seen_seq, controller_t=d.get("written"))
                        cur.pop(ip, None)
                    continue
                ttl = max(1, int(round(want[ip].get("ttl", 60)))) + 2   # +2 s: the controller steps down first while alive
                exp = now + ttl
                if new != old or exp > cur.get(ip, {}).get("expires", 0) + 2:
                    s = SETS[new]
                    script = (f"delete element ip vg {SETS[old]} {{ {ip} }}\n" if old and old != new else "")
                    ok, err = nft(script + f"add element ip vg {s} {{ {ip} timeout {ttl}s }}")
                    if not ok:                                        # element still there (renewal): replace it
                        ok, err = nft(f"delete element ip vg {s} {{ {ip} }}\nadd element ip vg {s} {{ {ip} timeout {ttl}s }}")
                    if not ok and old and old != new:                 # old element had already expired
                        ok, err = nft(f"add element ip vg {s} {{ {ip} timeout {ttl}s }}")
                    flushed = False
                    if new >= 3 and new > old:                        # cut open sessions so new ones meet the rules
                        flushed = conntrack("-s", ip)
                        if new == 4: conntrack("-d", ip)
                    if new != old:
                        log(LOG, event="level", ip=ip, frm=old, to=new, set=s, ttl=ttl, ok=ok, error=err or None,
                            conntrack_flushed=flushed, seq=seen_seq, controller_t=d.get("written"))
                    cur[ip] = dict(level=new, expires=exp)
        # what the kernel really holds: anything we think is there but expired = fail-open in action
        if time.time() - last_state > 1.0:
            k = kernel_sets(); last_state = time.time()
            for ip in list(cur):
                s = SETS[cur[ip]["level"]]
                if ip not in k.get(s, {}):
                    age = round(time.time() - os.path.getmtime(DESIRED), 1) if os.path.exists(DESIRED) else None
                    log(LOG, event="expired", ip=ip, frm=cur[ip]["level"], to=0, set=s, controller_age_s=age,
                        note="timeout ran out in the kernel without renewal (fail-open)")
                    cur.pop(ip)
            q.poll(d)
            st = dict(t=round(time.time(), 3), mode="enforcing", seq=seen_seq,
                      controller_age_s=round(time.time() - os.path.getmtime(DESIRED), 1) if os.path.exists(DESIRED) else None,
                      sets={s: {ip: e for ip, e in v.items()} for s, v in k.items()}, counters=counters(), quarantine=q.summary(),
                      quarantine_items=sorted(q.items.values(), key=lambda it: -it["received"])[:50])
            tmp = STATE + ".tmp"
            with open(tmp, "w") as f: json.dump(st, f)
            os.replace(tmp, STATE)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
