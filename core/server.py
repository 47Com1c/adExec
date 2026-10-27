"""
core/server.py — Tiny stdlib HTTP server for the adExec web viewer.

Serves the static assets in web/ plus two data endpoints:
  GET /api/targets                  -> list every recon/<target>/report.json
  GET /data/<target>/report.json    -> one target's report

No third-party dependencies; nothing is written, only read from output_dir.
"""

import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


class _Handler(BaseHTTPRequestHandler):
    output_dir = "."          # set by serve()

    # -- helpers ------------------------------------------------------- #

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _send_file(self, fp: Path):
        try:
            self._send(200, fp.read_bytes(), _CTYPES.get(fp.suffix, "application/octet-stream"))
        except FileNotFoundError:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def _within_output(self, fp: Path) -> bool:
        try:
            fp.resolve().relative_to(Path(self.output_dir).resolve())
            return True
        except ValueError:
            return False

    def _targets(self) -> list:
        out = []
        base = Path(self.output_dir)
        if base.exists():
            for rp in sorted(base.glob("*/report.json")):
                try:
                    d = json.loads(rp.read_text())
                except Exception:
                    continue
                out.append({
                    "target":          d.get("target"),
                    "domain":          d.get("domain"),
                    "hostname":        d.get("hostname"),
                    "finished_at":     d.get("finished_at"),
                    "severity_counts": d.get("severity_counts", {}),
                    "report":          f"/data/{rp.parent.name}/report.json",
                })
        return out

    # -- routing ------------------------------------------------------- #

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("/", "/index.html"):
            return self._send_file(WEB_DIR / "index.html")
        if path in ("/app.js", "/style.css"):
            return self._send_file(WEB_DIR / path.lstrip("/"))
        if path == "/api/targets":
            return self._send(200, json.dumps(self._targets()))
        if path.startswith("/data/"):
            fp = Path(self.output_dir) / path[len("/data/"):]
            if fp.name == "report.json" and self._within_output(fp) and fp.exists():
                return self._send_file(fp)
            return self._send(404, "{}", "application/json; charset=utf-8")

        return self._send(404, "not found", "text/plain; charset=utf-8")

    def log_message(self, *args):
        pass                       # keep the terminal clean


def _find_port(host: str, start: int, tries: int = 20) -> int:
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((host, port)) != 0:   # nothing listening = free
                return port
    return start


def serve(output_dir, host="127.0.0.1", port=8777, open_browser=True, term=None):
    _Handler.output_dir = str(output_dir)
    port = _find_port(host, port)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"

    msg = f"Web viewer: {url}   (Ctrl-C to stop)"
    if term:
        term.success(msg)
    else:
        print(msg)

    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if term:
            term.info("Viewer stopped.")
    finally:
        httpd.server_close()
