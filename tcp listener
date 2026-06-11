"""
Lightweight OAST/raw-TCP listener for The Great Automation.
Listens on 0.0.0.0:4444 for any TCP connection, logs raw bytes + source,
and serves notifications to the dashboard over a small HTTP API on 127.0.0.1:4445.
"""
import socket
import threading
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

TCP_PORT = 4444
API_PORT = 4445
MAX_BYTES = 8192          # cap per connection; we only need the first chunk
MAX_STORED = 500          # ring-buffer cap so memory stays flat

_hits = []                # newest-last
_lock = threading.Lock()


def _record(source_ip, source_port, raw):
    entry = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "source": f"{source_ip}:{source_port}",
        "ip": source_ip,
        # decode for display only; keep it safe for JSON
        "raw": raw.decode("utf-8", errors="replace"),
        "bytes": len(raw),
        "seen": False,          # toaster shown?
        "cleared": False,       # removed by "clear all"?
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
        # minimal valid HTTP reply so browser/curl callbacks don't hang
        try:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nok")
        except OSError:
            pass
    finally:
        conn.close()


def _tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", TCP_PORT))
    s.listen(64)
    print(f"[*] TCP listener on 0.0.0.0:{TCP_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=_handle_conn, args=(conn, addr), daemon=True).start()


class _API(BaseHTTPRequestHandler):
    def log_message(self, *a):       # silence default logging
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # active = not cleared; the dashboard renders these
        if self.path == "/notifications":
            with _lock:
                active = [h for h in _hits if not h["cleared"]]
            self._send({"count": len(active), "items": active})
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
        else:
            self._send({"error": "not found"}, 404)


def _api_server():
    HTTPServer(("127.0.0.1", API_PORT), _API).serve_forever()


if __name__ == "__main__":
    threading.Thread(target=_tcp_server, daemon=True).start()
    print(f"[*] notification API on 127.0.0.1:{API_PORT}")
    _api_server()
