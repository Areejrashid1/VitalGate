"""Benign hospital traffic, written independently of the training lab.
ROLE=modality     exams pushed with DCMTK storescu (per-device PDU size, compression, series splitting, retries,
                  offline periods followed by a backlog flush, occasional echo heartbeats)
ROLE=workstation  worklist-style queries (findscu, varied keys/levels), retrieval with C-GET (getscu) or C-MOVE
                  (movescu, the PACS connects back), prior-study bulk fetches, web viewer HTTP GETs, misconfigured AE
ROLE=monitor      TCP health probes on the DICOM port, echo checks, REST status polls, ICMP pings
Load follows a compressed day curve (DAY_S seconds per 'day') plus random emergency bursts."""
import glob, math, os, random, shutil, socket, subprocess, tempfile, time, urllib.request
from common import *

ROLE = os.environ["ROLE"]
AET = os.environ.get("AET", ROLE.upper()[:8] + "_%02d" % random.randrange(100))
MOD = os.environ.get("MOD", "CT")
MEAN = float(os.environ.get("MEAN_S", "60"))                 # mean seconds between actions at load 1.0
EXAM = [int(x) for x in os.environ.get("EXAM_IMAGES", "20,120").split(",")]
SPEED = float(os.environ.get("SPEED", "1"))
DAY = float(os.environ.get("DAY_S", "7200"))
PDU = os.environ.get("MAX_PDU", "16384")
MOVE_PORT = os.environ.get("MOVE_PORT", "")                  # set -> this workstation retrieves with C-MOVE
T0 = random.uniform(0, DAY)
burst_until = 0.0


def load():
    global burst_until
    ph = ((time.time() + T0) % DAY) / DAY
    base = 0.25 + 1.5 * max(0.0, math.sin(math.pi * ph)) ** 1.5           # night ~0.25, mid-day ~1.75
    if time.time() < burst_until:
        return base * 3
    if random.random() < 0.01:                                            # emergency burst for a few minutes
        burst_until = time.time() + random.uniform(120, 600)
    return base


def pause(mean=MEAN):
    m = mean / (load() * SPEED)
    time.sleep(min(random.expovariate(1.0 / m), m * 6))


# ------------------------------------------------------------------------------------------- modality
backlog = []


def store(files, enc):
    cmd = ["storescu", "-aet", AET, "-aec", AEC, "-to", "30", "-ta", "30", "-pdu", PDU, *FLAGS[enc], PACS, PORT, *files]
    for attempt in range(3):
        rc, out = run(cmd)
        if rc == 0:
            return True
        time.sleep(random.uniform(2, 10) * (attempt + 1))
    return False


def make_exam():
    enc, lib = lib_files(MOD)
    n = random.randint(*EXAM)
    d = tempfile.mkdtemp(prefix="exam_", dir="/tmp")
    st, pid = uid(), "TB%07d" % random.randrange(10**7)
    series = [uid() for _ in range(random.choice([1, 1, 2, 3]))]
    files = []
    for i in range(n):
        f = os.path.join(d, "%04d.dcm" % i); shutil.copy(random.choice(lib), f); files.append(f)
    per = math.ceil(n / len(series))
    for k, se in enumerate(series):
        part = files[k * per:(k + 1) * per]
        if part:
            run(["dcmodify", "-nb", "-gin", "-m", f"(0020,000d)={st}", "-m", f"(0020,000e)={se}",
                 "-m", f"(0010,0020)={pid}", "-m", f"(0010,0010)=TB^{pid}", "-m", f"(0008,0060)={MOD}", *part])
    return d, enc, [files[k * per:(k + 1) * per] for k in range(len(series))]


def modality_step():
    r = random.random()
    if r < 0.08:
        rc, _ = run(["echoscu", "-aet", AET, "-aec", AEC, "-to", "10", PACS, PORT], 30)
        log(role=ROLE, action="echo", ok=rc == 0); return
    if r < 0.10:                                                          # device offline for a while (exams queue)
        off = random.uniform(300, 1200); log(role=ROLE, action="offline", seconds=round(off))
        t_end = time.time() + off
        while time.time() < t_end:
            backlog.append(make_exam()); pause()
        return
    exams = backlog[:] + [make_exam()]; backlog.clear()
    for d, enc, groups in exams:
        if random.random() < 0.5:                                         # one association per series
            ok = all(store(g, enc) for g in groups if g)
        else:
            ok = store([f for g in groups for f in g], enc)
        log(role=ROLE, action="store", images=sum(map(len, groups)), enc=enc, series=len(groups), ok=ok)
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------------------------------- workstation
def retrieve(st_uid):
    d = tempfile.mkdtemp(prefix="dl_", dir="/tmp")
    if MOVE_PORT:
        cmd = ["movescu", "-S", "-aet", AET, "-aem", AET, "-aec", AEC, "--port", MOVE_PORT, "-od", d, "-to", "30",
               "-k", "QueryRetrieveLevel=STUDY", "-k", f"StudyInstanceUID={st_uid}", PACS, PORT]
    else:
        cmd = ["getscu", "-S", "-aet", AET, "-aec", AEC, "-od", d, "-to", "30",
               "-k", "QueryRetrieveLevel=STUDY", "-k", f"StudyInstanceUID={st_uid}", PACS, PORT]
    rc, _ = run(cmd)
    n = len(os.listdir(d)); shutil.rmtree(d, ignore_errors=True)
    return rc == 0, n


def http_get(path):
    try:
        urllib.request.urlopen(f"http://{PACS}:{HTTP}{path}", timeout=10).read(); return True
    except Exception:
        return False


def workstation_step():
    r = random.random()
    if r < 0.15:
        ok = http_get(random.choice(["/studies", "/system", "/dicom-web/studies?limit=25", "/statistics"]))
        log(role=ROLE, action="web", ok=ok); return
    if r < 0.19:                                                          # misconfigured called AE
        rc, _ = run(["echoscu", "-aet", AET, "-aec", random.choice(["ARCHIVE", "PACS", "VG-ARCHIVE"]), "-to", "10", PACS, PORT], 30)
        log(role=ROLE, action="wrong-aec", rc=rc); return
    if r < 0.24:                                                          # prior studies for a returning patient
        _, uids = find_studies(AET, "TB*")
        random.shuffle(uids); got = sum(retrieve(u)[1] for u in uids[:random.randint(3, 6)])
        log(role=ROLE, action="priors", images=got); return
    level = random.choice(["STUDY", "STUDY", "STUDY", "SERIES"])
    extra = ["-k", "ModalitiesInStudy"] if level == "STUDY" else ["-k", "SeriesInstanceUID", "-k", "Modality"]
    pattern = random.choice(["TB*", "TB^TB1*", "TB^TB2*", "TB^TB3*", "*"])
    rc, uids = find_studies(AET, pattern, "STUDY" if level == "STUDY" else "STUDY", extra)
    if uids and random.random() < 0.55:
        ok, n = retrieve(random.choice(uids))
        log(role=ROLE, action="retrieve", mode="move" if MOVE_PORT else "get", images=n, ok=ok)
    else:
        log(role=ROLE, action="query", level=level, matches=len(uids))


# ------------------------------------------------------------------------------------------- monitor
def monitor_step():
    r = random.random()
    if r < 0.45:                                                          # TCP probe: connect + close, no PDU
        s = socket.socket(); s.settimeout(3)
        try: s.connect((PACS, int(PORT))); ok = True
        except Exception: ok = False
        finally: s.close()
        log(role=ROLE, action="tcp-probe", ok=ok)
    elif r < 0.7:
        rc, _ = run(["echoscu", "-aet", AET, "-aec", AEC, "-to", "10", PACS, PORT], 30)
        log(role=ROLE, action="echo", ok=rc == 0)
    elif r < 0.9:
        log(role=ROLE, action="rest-status", ok=http_get("/system"))
    else:
        run(["ping", "-c", "3", "-i", "0.5", PACS], 15); log(role=ROLE, action="ping")


def main():
    log(role=ROLE, action="start", aet=AET, mod=MOD)
    time.sleep(random.uniform(20, 60))                                    # let the PACS start
    step = {"modality": modality_step, "workstation": workstation_step, "monitor": monitor_step}[ROLE]
    while True:
        try:
            step()
        except Exception as e:
            log(role=ROLE, action="error", err=str(e)[:160]); time.sleep(5)
        if ROLE == "monitor":
            time.sleep(random.uniform(0.5, 1.5) * MEAN)                   # monitors run at a fixed rate
        else:
            pause()


if __name__ == "__main__":
    main()
