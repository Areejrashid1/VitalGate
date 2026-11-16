"""VitalGate SOC dashboard: a small web server (Python standard library only).
Serves the dashboard page, the current incidents (soc/data/incidents.json, written by soc/replay.py or the live
detector) and stores analyst actions (acknowledge, verdict, note) in soc/data/feedback.json. Analyst verdicts are
the labelled data a site can later contribute to federated retraining.

Access: analysts sign in on /login with a username and password. Accounts live in soc/data/users.json
(PBKDF2-SHA256 hashes, never plain passwords). The first start asks you to create an account.
Usage (from product/):
  python soc/server.py [--port 8090] [--data soc/data]        -> open http://localhost:8090 and sign in
  python soc/server.py --add-user NAME                        -> add an account or change its password, then exit
  python soc/server.py --remove-user NAME                     -> delete an account, then exit"""
import argparse, getpass, hashlib, hmac, json, os, re, secrets, socket, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser(); p.add_argument("--port", type=int, default=8090); p.add_argument("--host", default="127.0.0.1")
p.add_argument("--data", default=str(HERE / "data"))
p.add_argument("--add-user", metavar="NAME"); p.add_argument("--remove-user", metavar="NAME")
a = p.parse_args()
DATA = Path(a.data); DATA.mkdir(parents=True, exist_ok=True)
INC, FB, USERS = DATA / "incidents.json", DATA / "feedback.json", DATA / "users.json"
LOCK = threading.Lock()
IID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")              # incident ids look like INC-162003-0004
UNAME = re.compile(r"^[A-Za-z0-9_.@-]{2,40}$")
VERDICTS = (None, "", "true_attack", "false_alarm")    # the two buttons on the incident page (empty = cleared)
MAX_BODY = 64 * 1024
SESSION_S = 12 * 3600                                  # a sign-in lasts one shift
ITER = 200_000                                         # PBKDF2 rounds
SESSIONS = {}                                          # session id -> {"user", "expires"}  (in memory: restart = sign in again)
FAILS = {}                                             # client ip -> [failed attempts, locked until]


def load(path, default):
    for attempt in range(20):                 # Windows: the writer may be replacing the file right now -> retry briefly
        try:
            with open(path, encoding="utf-8") as f: return json.load(f)
        except FileNotFoundError:
            return default
        except (PermissionError, json.JSONDecodeError):
            time.sleep(0.05)
    return default


def save(path, obj):
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(obj, f, indent=1)
    os.replace(tmp, path)


# ---------------- accounts ----------------
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return dict(salt=salt.hex(), hash=hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER).hex(), iter=ITER)


def check_pw(user, pw):
    rec = load(USERS, {}).get(user)
    if not rec:                                          # same work for unknown users, so timing reveals nothing
        hashlib.pbkdf2_hmac("sha256", pw.encode(), b"x" * 16, ITER); return False
    got = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(rec["salt"]), int(rec.get("iter", ITER))).hex()
    return hmac.compare_digest(got, rec["hash"])


def set_user(name):
    if not UNAME.match(name): sys.exit("username: 2-40 letters, digits or . _ @ -")
    while True:
        pw = getpass.getpass(f"password for {name} (min 8 characters): ")
        if len(pw) < 8: print("too short"); continue
        if getpass.getpass("repeat password: ") != pw: print("passwords differ"); continue
        break
    users = load(USERS, {}); new = name not in users
    users[name] = dict(hash_pw(pw), created=users.get(name, {}).get("created", time.time()))
    save(USERS, users); print(f"{'added' if new else 'password changed for'} {name}  ({USERS})")


if a.add_user: set_user(a.add_user); sys.exit()
if a.remove_user:
    users = load(USERS, {})
    if users.pop(a.remove_user, None) is None: sys.exit(f"no user {a.remove_user}")
    save(USERS, users); print(f"removed {a.remove_user}"); sys.exit()
if not load(USERS, {}):
    if not sys.stdin.isatty(): sys.exit("no dashboard accounts yet: run  python soc/server.py --add-user <name>")
    print("No dashboard accounts yet. Create the first one.")
    set_user(input("username: ").strip())


# ---------------- web ----------------
class H(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ctype="application/json", headers=()):
        b = body if isinstance(body, bytes) else json.dumps(body, default=float).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store"); self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in headers: self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)

    def _redirect(self, to):
        self.send_response(302); self.send_header("Location", to); self.send_header("Content-Length", "0"); self.end_headers()

    def _user(self):
        c = SimpleCookie(self.headers.get("Cookie", "")).get("vg_session")
        s = SESSIONS.get(c.value) if c else None
        if s and s["expires"] > time.time(): return s["user"]
        if s: SESSIONS.pop(c.value, None)
        return None

    def _body(self):
        try: n = int(self.headers.get("Content-Length", 0))
        except ValueError: return None
        if n > MAX_BODY: return None
        try: body = json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError): return None
        return body if isinstance(body, dict) else None

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/login":
            return self._send(200, (HERE / "static" / "login.html").read_bytes(), "text/html; charset=utf-8")
        user = self._user()
        if path in ("/", "/index.html"):
            if not user: return self._redirect("/login")
            return self._send(200, (HERE / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if not user: return self._send(401, {"error": "sign in required"})
        if path == "/api/me": return self._send(200, {"user": user})
        if path == "/api/state":
            s = load(INC, dict(incidents=[], hosts=[], meta={}, data_time=None))
            s["feedback"] = load(FB, {}); s["server_time"] = time.time(); s["user"] = user
            return self._send(200, s)
        self._send(404, {"error": "not found"})

    def do_HEAD(self):
        self.send_response(200 if self.path.split("?", 1)[0] == "/login" else 404); self.send_header("Content-Length", "0"); self.end_headers()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if "application/json" not in (self.headers.get("Content-Type") or ""):   # a plain cross-site form cannot post here
            return self._send(415, {"error": "json only"})
        if path == "/api/login": return self._login()
        if path == "/api/logout":
            c = SimpleCookie(self.headers.get("Cookie", "")).get("vg_session")
            if c: SESSIONS.pop(c.value, None)
            return self._send(200, {"ok": True}, headers=[("Set-Cookie", "vg_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")])
        user = self._user()
        if not user: return self._send(401, {"error": "sign in required"})
        if not path.startswith("/api/feedback/"): return self._send(404, {"error": "not found"})
        iid = path.rsplit("/", 1)[1]
        if not IID.match(iid): return self._send(400, {"error": "bad incident id"})
        body = self._body()
        if body is None: return self._send(400, {"error": "bad json"})
        body = {k: body[k] for k in ("ack", "verdict", "note") if k in body}
        if any(not isinstance(body.get(k), (str, type(None))) for k in ("verdict", "note")) or \
           ("ack" in body and not isinstance(body["ack"], bool)):
            return self._send(400, {"error": "bad field type"})
        if body.get("verdict") not in VERDICTS or len(body.get("note") or "") > 4000:
            return self._send(400, {"error": "bad value"})
        body["analyst"] = user                              # who did it comes from the sign-in, not from the request
        with LOCK:
            fb = load(FB, {}); cur = fb.get(iid, {})
            for k in ("ack", "verdict", "note", "analyst"):
                if k in body: cur[k] = body[k]
            cur.setdefault("history", []).append(dict(t=time.time(), **body))
            fb[iid] = cur; save(FB, fb)
        self._send(200, cur)

    def _login(self):
        ip, now = self.client_address[0], time.time()
        n, until = FAILS.get(ip, (0, 0))
        if until > now: return self._send(429, {"error": f"too many attempts, try again in {int(until - now) + 1} s"})
        body = self._body() or {}
        user, pw = str(body.get("username", ""))[:40].strip(), str(body.get("password", ""))[:200]
        if UNAME.match(user) and pw and check_pw(user, pw):
            FAILS.pop(ip, None)
            sid = secrets.token_urlsafe(32); SESSIONS[sid] = dict(user=user, expires=now + SESSION_S)
            for k in [k for k, s in SESSIONS.items() if s["expires"] < now]: SESSIONS.pop(k, None)
            return self._send(200, {"ok": True, "user": user},
                              headers=[("Set-Cookie", f"vg_session={sid}; Path=/; Max-Age={SESSION_S}; HttpOnly; SameSite=Strict")])
        n += 1
        FAILS[ip] = (n, now + 60 if n >= 5 else 0)          # 5 wrong tries -> 60 s lock-out
        if n >= 5: FAILS[ip] = (0, now + 60)
        time.sleep(0.5)
        self._send(401, {"error": "wrong username or password"})


url = f"http://{'localhost' if a.host in ('127.0.0.1', '0.0.0.0') else a.host}:{a.port}"
if a.host not in ("127.0.0.1", "localhost"):
    print("warning: listening beyond this machine over plain HTTP; use it only on a trusted network")
class Server(ThreadingHTTPServer):
    # Windows lets a second process bind the same port and then splits requests between the two (an old
    # dashboard keeps answering). Take the port exclusively so a second start fails loudly instead.
    allow_reuse_address = os.name != "nt"
    def server_bind(self):
        if os.name == "nt": self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


try:
    srv = Server((a.host, a.port), H)
except OSError:
    sys.exit(f"port {a.port} is already in use: another dashboard (or program) is running. Stop it, or use --port 8091")
print(f"VitalGate SOC dashboard: open {url}  and sign in  (accounts: {len(load(USERS, {}))}, data: {DATA})")
srv.serve_forever()
