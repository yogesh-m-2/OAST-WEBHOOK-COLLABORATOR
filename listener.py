"""
Lightweight OAST/raw-TCP listener for The Great Automation.
Binds a TCP capture port (default 23.94.111.244:4444), logs raw bytes + source,
and serves notifications + bind-config to the dashboard over a loopback API
on 127.0.0.1:4445.

Run:  python3 listener.py

Env overrides (optional; UI can change host/port at runtime too):
  OAST_BIND, OAST_PORT, OAST_API_BIND, OAST_API_PORT, OAST_MAX_BYTES, OAST_MAX_STORED
"""
import os
import socket
import threading
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── Defaults ────────────────────────────────────────────────────────────────
DEFAULT_BIND = os.environ.get("OAST_BIND", "23.94.111.244")
DEFAULT_PORT = int(os.environ.get("OAST_PORT", "4444"))

API_HOST  = os.environ.get("OAST_API_BIND", "127.0.0.1")   # loopback only
API_PORT  = int(os.environ.get("OAST_API_PORT", "4445"))

MAX_BYTES  = int(os.environ.get("OAST_MAX_BYTES", "8192"))
MAX_STORED = int(os.environ.get("OAST_MAX_STORED", "500"))

# IPs we permit binding to. The box can only bind interfaces it owns; we also
# allow 0.0.0.0 (all) and loopback. This both prevents silent bind failures and
# keeps the runtime-config endpoint from being abused to point elsewhere.
ALLOWED_BIND_HOSTS = {"0.0.0.0", "127.0.0.1", DEFAULT_BIND}

_hits = []
_lock = threading.Lock()


def _record(source_ip, source_port, raw):
    entry = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "source": f"{source_ip}:{source_port}",
        "ip": source_ip,
        "raw": raw.decode("utf-8", errors="replace"),
        "bytes": len(raw),
        "seen": False,
        "cleared": False,
    }
    with _lock:
        _hits.append(entry)
        if len(_hits) > MAX_STORED:
            del _hits[0:len(_hits) - MAX_STORED]
    print(f"[+] hit from {entry['source']} ({entry['bytes']} bytes)")


def _handle_conn(conn, addr):
    try:
        conn.settimeout(2.0)
        chunks, total = [], 0
        try:
            while total < MAX_BYTES:
                data = conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        except socket.timeout:
            pass
        raw = b"".join(chunks) or b"(connection with no data)"
        _record(addr[0], addr[1], raw)
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nok")
        except OSError:
            pass
    finally:
        conn.close()


class ListenerController:
    """Owns the capture socket. Can rebind to a new host/port at runtime."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.last_error = None

    def _serve_loop(self, sock):
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except OSError:
                break  # socket closed during rebind/shutdown
            threading.Thread(target=_handle_conn, args=(conn, addr),
                             daemon=True).start()

    def start(self):
        with self._lock:
            self._stop.clear()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))      # raises if host not ownable
            s.listen(64)
            self._sock = s
            self.last_error = None
            self._thread = threading.Thread(target=self._serve_loop, args=(s,),
                                            daemon=True)
            self._thread.start()
            print(f"[*] TCP listener on {self.host}:{self.port}")

    def stop(self):
        with self._lock:
            self._stop.set()
            sock = self._sock
            self._sock = None
        # Unblock the accept() call so the serve loop exits promptly, then close.
        if sock:
            try:
                host = "127.0.0.1" if self.host == "0.0.0.0" else self.host
                poke = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                poke.settimeout(0.3)
                poke.connect((host, self.port))
                poke.close()
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)

    def rebind(self, host, port):
        """Stop current socket and bind a new one. On failure, restore the old."""
        old_host, old_port = self.host, self.port
        self.stop()
        time.sleep(0.2)  # let the accept loop unwind
        self.host, self.port = host, port
        try:
            self.start()
            return True, None
        except Exception as e:
            # roll back so we're never left with no listener
            self.host, self.port = old_host, old_port
            self.last_error = str(e)
            try:
                self.start()
            except Exception:
                pass
            return False, str(e)


controller = ListenerController(DEFAULT_BIND, DEFAULT_PORT)


def _valid_port(p):
    return isinstance(p, int) and 1 <= p <= 65535


class _API(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        if self.path == "/notifications":
            with _lock:
                active = [h for h in _hits if not h["cleared"]]
            self._send({"count": len(active), "items": active})
        elif self.path == "/config":
            self._send({
                "host": controller.host,
                "port": controller.port,
                "allowed_hosts": sorted(ALLOWED_BIND_HOSTS),
                "last_error": controller.last_error,
            })
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/mark-seen":
            with _lock:
                for h in _hits:
                    h["seen"] = True
            self._send({"ok": True})
        elif self.path == "/clear":
            with _lock:
                for h in _hits:
                    h["cleared"] = True
            self._send({"ok": True})
        elif self.path == "/config":
            data = self._read_json()
            host = str(data.get("host", controller.host)).strip()
            try:
                port = int(data.get("port", controller.port))
            except (TypeError, ValueError):
                self._send({"ok": False, "error": "port must be a number"}, 400)
                return
            if host not in ALLOWED_BIND_HOSTS:
                self._send({"ok": False,
                            "error": f"host must be one of {sorted(ALLOWED_BIND_HOSTS)} "
                                     f"(the box can only bind interfaces it owns)"}, 400)
                return
            if not _valid_port(port):
                self._send({"ok": False, "error": "port out of range (1-65535)"}, 400)
                return
            ok, err = controller.rebind(host, port)
            if ok:
                self._send({"ok": True, "host": host, "port": port})
            else:
                self._send({"ok": False, "error": err,
                            "host": controller.host, "port": controller.port}, 400)
        else:
            self._send({"error": "not found"}, 404)


def _api_server():
    HTTPServer((API_HOST, API_PORT), _API).serve_forever()


if __name__ == "__main__":
    controller.start()
    print(f"[*] notification API on {API_HOST}:{API_PORT}")
    _api_server()
