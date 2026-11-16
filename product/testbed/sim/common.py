import csv, json, os, random, re, socket, subprocess, time, uuid

SITE = os.environ.get("SITE", "A")
PACS = os.environ.get("PACS_HOST", "pacs")
PORT = os.environ.get("PACS_PORT", "104")
AEC = os.environ.get("PACS_AET", "VG_ARCHIVE")
HTTP = int(os.environ.get("PACS_HTTP", "8042"))
OUT = os.environ.get("OUT_DIR", "/out")
LIB = "/library"
FLAGS = {"raw": [], "jl": ["-xs"], "jb": ["-xy"]}           # storescu proposals per library encoding


def log(**kw):
    kw.update(ts=round(time.time(), 3), site=SITE, host=socket.gethostname())
    print(json.dumps(kw), flush=True)


def uid():
    return "2.25." + str(uuid.uuid4().int)


def run(cmd, timeout=900):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def lib_files(mod=None, enc=None):
    enc = enc or random.choice(["raw", "raw", "jl", "jb"])
    d = os.path.join(LIB, enc)
    fs = sorted(f for f in os.listdir(d) if mod is None or f.startswith(mod + "_"))
    return enc, [os.path.join(d, f) for f in fs]


def find_studies(aet, pattern="*", level="STUDY", extra=()):
    cmd = ["findscu", "-v", "-S", "-to", "20", "-aet", aet, "-aec", AEC, "-k", f"QueryRetrieveLevel={level}",
           "-k", f"PatientName={pattern}", "-k", "StudyInstanceUID", "-k", "StudyDate", *extra, PACS, PORT]
    rc, out = run(cmd, 120)
    return rc, re.findall(r"\(0020,000d\) UI \[([0-9.]+)\]", out)


def my_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "0.0.0.0"


def truth(file="truth.csv", **row):
    path = os.path.join(OUT, file)
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if new: w.writeheader()
        w.writerow(row)
