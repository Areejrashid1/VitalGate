"""VitalGate SOC dashboard: a small web server (Python standard library only).
Serves the dashboard page, the current incidents (soc/data/incidents.json, written by soc/replay.py or the live
detector) and stores analyst actions (acknowledge, verdict, note) in soc/data/feedback.json. Analyst verdicts are
the labelled data a site can later contribute to federated retraining.
Usage (from product/):  python soc/server.py [--port 8090] [--data soc/data]   -> open http://localhost:8090"""
import argparse, json, os, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser(); p.add_argument("--port", type=int, default=8090); p.add_argument("--host", default="127.0.0.1")
p.add_argument("--data", default=str(HERE / "data"))
a = p.parse_args()
DATA = Path(a.data); DATA.mkdir(parents=True, exist_ok=True)
INC, FB = DATA / "incidents.json", DATA / "feedback.json"
LOCK = threading.Lock()


def load(path, default):
    for attempt in range(20):                 # Windows: the writer may be replacing the file right now -> retry briefly
        try:
            with open(path, encoding="utf-8") as f: return json.load(f)
        except FileNotFoundError:
            return default
        except (PermissionError, json.JSONDecodeError):
            time.sleep(0.05)
    return default


class H(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body, default=float).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, (HERE / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path.startswith("/api/state"):
            s = load(INC, dict(incidents=[], hosts=[], meta={}, data_time=None))
            s["feedback"] = load(FB, {})
            s["server_time"] = time.time()
            return self._send(200, s)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/api/feedback/"):
            return self._send(404, {"error": "not found"})
        iid = self.path.rsplit("/", 1)[1]
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        with LOCK:
            fb = load(FB, {}); cur = fb.get(iid, {})
            for k in ("ack", "verdict", "note", "analyst"):
                if k in body: cur[k] = body[k]
            cur.setdefault("history", []).append(dict(t=time.time(), **{k: body[k] for k in body if k != "history"}))
            fb[iid] = cur
            tmp = str(FB) + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f: json.dump(fb, f, indent=1)
            os.replace(tmp, FB)
        self._send(200, cur)


print(f"VitalGate SOC dashboard on http://{'localhost' if a.host in ('127.0.0.1', '0.0.0.0') else a.host}:{a.port}  (data: {DATA})")
ThreadingHTTPServer((a.host, a.port), H).serve_forever()
