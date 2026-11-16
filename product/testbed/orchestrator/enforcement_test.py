"""Live enforcement test: the frozen VitalGate pipeline drives the real PEP (pep-a, nftables in the PACS namespace).
Starts soc/live.py as the controller, then runs three scripted scenarios and writes out/enforcement/report.{json,md}:

  1. Isolation:   an outside attacker bulk-downloads studies (exfiltration, severity 3) -> time from the attack's start
                  to the first gateway action and to
                  isolation (L4); a DICOM echo from the attacker works before and fails while it is isolated.
  2. Quarantine:  a compromised CT guesses AE titles -> L3. While quarantined, the CT's real image uploads (5 new images,
                  its own AE title) still succeed but land in the quarantine store; its REST access to the PACS is cut.
                  After the quarantine ends the clean images are released and found in the PACS.
  3. Fail-open:   the attacker is isolated again, then the controller (live.py) is killed: the gateway entry must expire
                  on its own and the attacker's echo work again.
Usage (from product/testbed, test bed up incl. quar-a and pep-a):   python orchestrator/enforcement_test.py
Takes about 15 minutes. Run id enf_01 in truth.csv (kept out of the evaluation campaigns)."""
import argparse, csv, json, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]                 # product/testbed
PRODUCT = HERE.parent
OUT = HERE / "out" / "enforcement"; OUT.mkdir(parents=True, exist_ok=True)
PEP = HERE / "out" / "pep"
ATK, CT, PACS = "172.28.1.77", "172.28.1.31", "172.28.1.20"
p = argparse.ArgumentParser(); p.add_argument("--run-id", default="enf_01"); p.add_argument("--warmup", type=int, default=60)
a = p.parse_args()
R = dict(run_id=a.run_id, started=time.strftime("%Y-%m-%d %H:%M:%S"))


def say(*x): print(time.strftime("%H:%M:%S"), *x, flush=True)


def dc(svc, *cmd, timeout=60, stdin=None):
    try:
        r = subprocess.run(["docker", "compose", "exec", "-T", svc, *cmd], cwd=HERE, capture_output=True, text=True,
                           timeout=timeout, input=stdin)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def attack(svc, cls, var, it, dur):
    return subprocess.Popen(["docker", "compose", "exec", "-T", svc, "python3", "/app/attack.py", cls, var, "--intensity", it,
                             "--duration", str(dur), "--run-id", a.run_id], cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def echo_ok(svc):                                          # one DICOM C-ECHO to the PACS, 8 s timeout
    rc, _, _ = dc(svc, "echoscu", "-to", "8", "-ta", "8", "-aec", "VG_ARCHIVE", PACS, "104", timeout=30)
    return rc == 0


def container_now():
    rc, out, _ = dc("pep-a", "python3", "-c", "import time;print(time.time())")
    return float(out.strip()) if rc == 0 else time.time()


def state():
    try: return json.loads((PEP / "state.json").read_text())
    except Exception: return {}


def in_set(ip, s):
    return ip in (state().get("sets", {}).get(s) or {})


def wait(cond, timeout, step=1.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cond(): return True
        time.sleep(step)
    return False


def applied(ip, since):
    out = []
    try:
        for line in open(PEP / "applied.jsonl"):
            e = json.loads(line)
            if e.get("ip") == ip and e.get("t", 0) >= since: out.append(e)
    except FileNotFoundError:
        pass
    return out


def truth_start(ip, since):
    for f in ("truth_started.csv", "truth.csv"):
        try:
            for r in csv.DictReader(open(HERE / "out" / f)):
                if r["src_ip"] == ip and r["run_id"] == a.run_id and float(r["start_ts"]) >= since - 1:
                    return float(r["start_ts"])
        except FileNotFoundError:
            pass
    return None


def drops(name):
    c = state().get("counters", {}); return c.get(name, {}).get("packets", 0)


# ------------------------------------------------------------------------------------------------ controller
def start_live():
    log = open(OUT / "live.log", "a")
    return subprocess.Popen([sys.executable, "soc/live.py", "--pep-dir", "testbed/out/pep"], cwd=PRODUCT, stdout=log, stderr=log)


say("checking the test bed ...")
if not state(): say("no PEP state yet (is pep-a running?) - waiting 20 s"); time.sleep(20)
if state().get("mode") != "enforcing": sys.exit("pep-a is not enforcing: docker compose up -d --build, then docker compose logs pep-a")
live = start_live(); say(f"controller (soc/live.py) started, warming up {a.warmup} s")
time.sleep(a.warmup)

# ------------------------------------------------------------------------------------------------ 1 · isolation
say("1 · isolation: echo from the attacker before the attack ...")
s1 = dict(echo_before=echo_ok("atk-a"))
t0 = container_now(); d0 = drops("vg_in:iso:drop")
proc = attack("atk-a", "exfiltration", "find_get", "high", 60)       # severity 3: the ladder isolates (L4); recon stops at L3
iso = wait(lambda: in_set(ATK, "iso"), 90, 0.5)
s1["isolated"] = iso
if iso:
    time.sleep(2); s1["echo_while_isolated"] = echo_ok("atk-a")
proc.wait(timeout=180)
st = truth_start(ATK, t0); ev = applied(ATK, t0)
first = min((e["t"] for e in ev if e.get("event") == "level"), default=None)
l4 = min((e["t"] for e in ev if e.get("event") == "level" and e.get("to") == 4), default=None)
s1.update(attack_start=st, first_action=first, isolation_applied=l4,
          time_to_first_action_s=round(first - st, 2) if first and st else None,
          time_to_isolation_s=round(l4 - st, 2) if l4 and st else None,
          packets_dropped_from_attacker=drops("vg_in:iso:drop") - d0,
          actions=[{k: e.get(k) for k in ("t", "frm", "to", "set", "conntrack_flushed", "ok")} for e in ev if e.get("event") == "level"])
R["isolation"] = s1; say("1 ·", json.dumps({k: v for k, v in s1.items() if k != "actions"}))
say("waiting for the attacker's actions to expire before the next scenario ...")
wait(lambda: not any(in_set(ATK, s) for s in ("watch", "rate", "quar", "iso")), 330, 2)

# ------------------------------------------------------------------------------------------------ 2 · quarantine
PROBE = r'''
import json, os, glob, subprocess, shutil
d = "/tmp/vg_probe"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
src = sorted(glob.glob("/library/raw/CT_*.dcm"))[:5]; files = []
for i, f in enumerate(src):
    g = os.path.join(d, f"probe_{i}.dcm"); shutil.copy(f, g)
    subprocess.run(["dcmodify", "-nb", "-gst", "-gse", "-gin", "-m", "PatientName=VG^QUARANTINE^PROBE", g], capture_output=True)
    files.append(g)
uids = []
for g in files:
    out = subprocess.run(["dcmdump", "-s", "+P", "0008,0018", g], capture_output=True, text=True).stdout
    uids.append(out.split("[")[1].split("]")[0] if "[" in out else None)
r = subprocess.run(["storescu", "-aet", "CT_SCAN31", "-aec", "VG_ARCHIVE", "-to", "30", "-ta", "30", "172.28.1.20", "104", *files],
                   capture_output=True, text=True)
print(json.dumps(dict(rc=r.returncode, uids=uids, err=r.stderr[-300:])))
'''
REST = "import urllib.request\ntry:\n    urllib.request.urlopen('http://172.28.1.20:8042/system', timeout=6); print('reachable')\nexcept Exception as e:\n    print('blocked', type(e).__name__)\n"
LOOKUP = r'''
import json, sys, urllib.request
found = []
for u in json.loads(sys.argv[1]):
    req = urllib.request.Request("http://172.28.1.20:8042/tools/lookup", data=u.encode(), method="POST")
    try: found.append(bool(json.loads(urllib.request.urlopen(req, timeout=10).read())))
    except Exception: found.append(False)
print(json.dumps(found))
'''
say("2 · quarantine: compromised CT guesses AE titles ...")
s2 = {}; t0 = container_now(); dn0 = drops("vg_pre:quar:dnat")
proc = attack("ct-a", "ae_bruteforce", "echo_guess", "high", 45)
q = wait(lambda: in_set(CT, "quar"), 120, 0.5); s2["quarantined"] = q
if q:
    time.sleep(2)
    rc, out, err = dc("ct-a", "python3", "-", stdin=PROBE, timeout=180)
    try: pr = json.loads(out.strip().splitlines()[-1])
    except Exception: pr = dict(rc=rc, uids=[], err=(err or out)[-300:])
    s2["upload_during_quarantine"] = dict(storescu_rc=pr.get("rc"), images=len(pr.get("uids", [])), succeeded=pr.get("rc") == 0,
                                          error=pr.get("err") if pr.get("rc") else None)
    rc, out, _ = dc("ct-a", "python3", "-", stdin=REST, timeout=30); s2["rest_to_pacs_while_quarantined"] = out.strip()
    uids = [u for u in pr.get("uids", []) if u]
else:
    uids = []
proc.wait(timeout=240)
ev = applied(CT, t0); st = truth_start(CT, t0)
l3 = min((e["t"] for e in ev if e.get("event") == "level" and e.get("to") == 3), default=None)
s2.update(attack_start=st, quarantine_applied=l3, time_to_quarantine_s=round(l3 - st, 2) if l3 and st else None,
          dicom_connections_redirected=drops("vg_pre:quar:dnat") - dn0)
say("2 · waiting for the quarantine to end and the images to be released (up to 8 min) ...")
def released():
    try: rel = [json.loads(l) for l in open(PEP / "quarantine.jsonl")]
    except FileNotFoundError: return []
    return [e for e in rel if e.get("event") == "released" and e.get("sop") in uids]
wait(lambda: uids and len(released()) >= len(uids), 480, 5)
rel = released(); s2["released"] = len(rel)
s2["held_s"] = sorted(e["held_s"] for e in rel)
quar_end = min((e["t"] for e in applied(CT, t0) if e.get("event") in ("level", "removed", "expired") and e.get("frm") == 3), default=None)
s2["quarantine_ended"] = quar_end
if uids:
    time.sleep(5)
    rc, out, _ = dc("mon-a", "python3", "-c", LOOKUP, json.dumps(uids), timeout=60)
    try: f = json.loads(out.strip()); s2["found_in_pacs"] = f"{sum(f)}/{len(f)}"
    except Exception: s2["found_in_pacs"] = f"lookup failed: {out[-200:]}"
R["quarantine"] = s2; say("2 ·", json.dumps(s2))

# ------------------------------------------------------------------------------------------------ 3 · fail-open
say("3 · fail-open: isolate the attacker again, then stop the controller ...")
s3 = {}; t0 = container_now()
proc = attack("atk-a", "exfiltration", "find_get", "high", 45)
iso = wait(lambda: in_set(ATK, "iso"), 90, 0.5); s3["isolated"] = iso
proc.wait(timeout=120)
if iso:
    exp_left = (state().get("sets", {}).get("iso") or {}).get(ATK)
    live.terminate(); t_kill = container_now(); s3["controller_killed"] = t_kill; s3["entry_seconds_left_at_kill"] = exp_left
    say(f"controller stopped; gateway entry has {exp_left} s left - waiting for it to expire on its own ...")
    gone = wait(lambda: not any(in_set(ATK, s) for s in ("watch", "rate", "quar", "iso")), 150, 1)
    t_gone = container_now(); s3["expired_without_controller"] = gone
    s3["expired_after_s"] = round(t_gone - t_kill, 1) if gone else None
    exp = [e for e in applied(ATK, t0) if e.get("event") == "expired"]
    s3["expiry_logged"] = bool(exp)
    s3["echo_after_expiry"] = echo_ok("atk-a")
else:
    live.terminate()
R["fail_open"] = s3; say("3 ·", json.dumps(s3))

# ------------------------------------------------------------------------------------------------ report
(OUT / "report.json").write_text(json.dumps(R, indent=1))
i, qq, f = R["isolation"], R["quarantine"], R["fail_open"]
md = f"""# VitalGate live enforcement test ({R['started']}, run id {a.run_id})

| Scenario | Result |
| --- | --- |
| 1 Isolation: attacker bulk-downloads studies | first gateway action {i.get('time_to_first_action_s')} s after the attack started; isolation (L4) after {i.get('time_to_isolation_s')} s; {i.get('packets_dropped_from_attacker')} attacker packets dropped |
| 1 Effect | DICOM echo from the attacker: before {'works' if i.get('echo_before') else 'FAILS'}, while isolated {'BLOCKED' if i.get('echo_while_isolated') is False else 'still works'} |
| 2 Quarantine: compromised CT guesses AE titles | quarantined (L3) after {qq.get('time_to_quarantine_s')} s |
| 2 Clinical continuity | {(qq.get('upload_during_quarantine') or {}).get('images')} new CT images uploaded during quarantine: {'succeeded' if (qq.get('upload_during_quarantine') or {}).get('succeeded') else 'FAILED'}; {qq.get('dicom_connections_redirected')} DICOM connections redirected to the quarantine store |
| 2 Everything else blocked | CT REST request to the PACS while quarantined: {qq.get('rest_to_pacs_while_quarantined')} |
| 2 Release | {qq.get('released')} images released after the quarantine ended (held {qq.get('held_s')} s); found in the PACS: {qq.get('found_in_pacs')} |
| 3 Fail-open | controller killed with {f.get('entry_seconds_left_at_kill')} s left on the attacker's entry; entry expired on its own after {f.get('expired_after_s')} s; echo afterwards {'works' if f.get('echo_after_expiry') else 'FAILS'} |
"""
(OUT / "report.md").write_text(md, encoding="utf-8"); print("\n" + md); say(f"saved {OUT / 'report.md'}")
