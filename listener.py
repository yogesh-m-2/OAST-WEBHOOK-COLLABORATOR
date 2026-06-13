"""
OAST listener for The Great Automation.

What it does:
  - Listens on 23.94.111.244:4444 for ANY TCP connection (HTTP, raw bytes, OAST
    callbacks). Logs the raw bytes + source IP.
  - Exposes a small JSON API on 0.0.0.0:4445 that your PyCharm dashboard POLLS
    directly over the internet (no SSH tunnel). Protected by a shared token.

Run on the VPS:
    python3 listener.py

The token below must match OAST_TOKEN in the PyCharm app (oast_routes.py).
Change it to anything you like; just keep both sides equal.
"""
import os
import socket
import threading
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── Config ──────────────────────────────────────────────────────────────────
CAPTURE_HOST = os.environ.get("OAST_BIND", "23.94.111.244")
CAPTURE_PORT = int(os.environ.get("OAST_PORT", "4444"))

API_HOST = os.environ.get("OAST_API_BIND", "0.0.0.0")   # internet-reachable so PyCharm can poll
API_PORT = int(os.environ.get("OAST_API_PORT", "4445"))

# Shared secret. PyCharm must send this in the X-OAST-Token header.
# Change it to your own value; keep it identical in oast_routes.py.
TOKEN = os.environ.get("OAST_TOKEN", "change-this-secret-7c1f9a2b")

MAX_BYTES = int(os.environ.get("OAST_MAX_BYTES", "8192"))
MAX_STORED = int(os.environ.get("OAST_MAX_STORED", "500"))

ALLOWED_BIND_HOSTS = {"0.0.0.0", "127.0.0.1", CAPTURE_HOST}

# ─── Sniffer noise filter ────────────────────────────────────────────────────
# Most-aggressive policy: only KEEP IPv4 packets whose destination is THIS VPS
# (an OAST callback always arrives AT us). Everything else is dropped early:
#   - non-IPv4 (ARP, EtherType 0x0027 link chatter, IPv6 0x86dd)
#   - our own outbound traffic, provider chatter (85.217.x), broadcast/multicast
#   - SSH (port 22) admin traffic
#   - our own API port (anti-spiral)
# Override the kept IP with OAST_KEEP_DST_IP if your public IP differs.
KEEP_DST_IP = os.environ.get("OAST_KEEP_DST_IP", CAPTURE_HOST)
DROP_PORTS = {22, API_PORT}   # SSH + our own API
# extra dst ports to drop, comma-separated, e.g. OAST_DROP_PORTS="123,161"
_extra = os.environ.get("OAST_DROP_PORTS", "")
for _p in _extra.split(","):
    _p = _p.strip()
    if _p.isdigit():
        DROP_PORTS.add(int(_p))

_hits = []
_lock = threading.Lock()

# ─── Correlation tokens (Burp-Collaborator style) ────────────────────────────
# You plant a unique token in your SSRF/SQLi payload (as a subdomain, URL path,
# or DNS name). Any captured packet whose bytes contain an active token is
# flagged matched=True with the token id — that's your confirmed OOB callback.
# Everything else is "noise" (scanners) and hidden by default in the UI.
TOKENS_FILE = os.environ.get("OAST_TOKENS_FILE",
                             os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          "tokens.json"))
_tokens = {}            # token_str -> {"label": str, "created": ts}
_tokens_lock = threading.Lock()


def _load_tokens():
    global _tokens
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with _tokens_lock:
            _tokens = dict(data)
        print(f"[*] loaded {len(_tokens)} correlation token(s)")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[!] could not load tokens: {e}")


def _save_tokens():
    try:
        with _tokens_lock:
            snapshot = dict(_tokens)
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"[!] could not save tokens: {e}")


def _match_token(raw_text):
    """Return the first active token contained in the packet text, or None.
    Case-insensitive — DNS/Host casing varies."""
    if not raw_text:
        return None
    low = raw_text.lower()
    with _tokens_lock:
        for tok in _tokens:
            if tok.lower() in low:
                return tok
    return None

# ─── Live mute rules (persisted, editable from the frontend) ─────────────────
# Stored in filter_rules.json next to this file. Three rule types you can add by
# clicking a packet in the dashboard: source IP, destination port, protocol kind.
RULES_FILE = os.environ.get("OAST_RULES_FILE",
                            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "filter_rules.json"))
_rules = {"src_ips": [], "dst_ports": [], "kinds": []}
_rules_lock = threading.Lock()


def _load_rules():
    global _rules
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with _rules_lock:
            _rules = {
                "src_ips": list(data.get("src_ips", [])),
                "dst_ports": [int(p) for p in data.get("dst_ports", [])],
                "kinds": list(data.get("kinds", [])),
            }
        print(f"[*] loaded mute rules: {len(_rules['src_ips'])} IPs, "
              f"{len(_rules['dst_ports'])} ports, {len(_rules['kinds'])} kinds")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[!] could not load rules: {e}")


def _save_rules():
    try:
        with _rules_lock:
            snapshot = {
                "src_ips": sorted(set(_rules["src_ips"])),
                "dst_ports": sorted(set(_rules["dst_ports"])),
                "kinds": sorted(set(_rules["kinds"])),
            }
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        print(f"[!] could not save rules: {e}")


def _hit_matches(hit, rtype, value):
    """Does an already-stored hit match a newly added rule? Used to retroactively
    hide existing noise when you mute it. Supports wildcard/CIDR for src_ip."""
    if rtype == "src_ip":
        return _ip_matches(hit.get("ip", ""), value)
    if rtype == "kind":
        return hit.get("kind") == value
    if rtype == "dst_port":
        dst = hit.get("dst", "")
        return dst.endswith(f":{value}")
    return False


def _ip_matches(ip, pattern):
    """Match an IP against a rule pattern. Supports:
       exact     85.217.140.4
       wildcard  85.217.140.*  /  85.217.*  /  85.*
       CIDR      85.217.0.0/16
    """
    if not ip:
        return False
    if pattern == ip:
        return True
    # CIDR
    if "/" in pattern:
        try:
            net, bits = pattern.split("/")
            bits = int(bits)
            def _to_int(a):
                parts = [int(x) for x in a.split(".")]
                return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return (_to_int(ip) & mask) == (_to_int(net) & mask)
        except Exception:
            return False
    # wildcard with trailing * on octet boundaries: 85.*  85.217.*  85.217.140.*
    if pattern.endswith("*"):
        prefix = pattern[:-1]              # "85.217.140."  or "85.217."  or "85."
        if prefix.endswith("."):
            return ip.startswith(prefix)
        # also allow "85.217.140.*" matching without requiring user to add the dot
        return ip.startswith(prefix)
    return False


def _muted_by_rules(kind, src, dst):
    """True if this packet matches a live mute rule (src IP / dst port / kind)."""
    src_ip = src.split(":")[0] if src else ""
    dst_port = dst.split(":")[1] if dst and ":" in dst else ""
    with _rules_lock:
        for pat in _rules["src_ips"]:
            if _ip_matches(src_ip, pat):
                return True
        if dst_port and dst_port.isdigit() and int(dst_port) in _rules["dst_ports"]:
            return True
        if kind and kind in _rules["kinds"]:
            return True
    return False


def _record(source_ip, source_port, raw, kind="tcp-capture", extra=None):
    raw_text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    matched_token = _match_token(raw_text)
    entry = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "source": f"{source_ip}:{source_port}",
        "ip": source_ip,
        "raw": raw_text,
        "bytes": len(raw),
        "kind": kind,
        "matched": matched_token is not None,
        "token": matched_token,
    }
    if extra:
        entry.update(extra)
    entry["seen"] = False
    entry["cleared"] = False
    with _lock:
        _hits.append(entry)
        if len(_hits) > MAX_STORED:
            del _hits[0:len(_hits) - MAX_STORED]
    tag = f" [MATCH:{matched_token}]" if matched_token else ""
    print(f"[+] {kind} from {entry['source']} ({entry['bytes']} bytes){tag}")


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
    """Owns the capture socket; can rebind to a new host/port at runtime."""
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
                break
            threading.Thread(target=_handle_conn, args=(conn, addr),
                             daemon=True).start()

    def start(self):
        with self._lock:
            self._stop.clear()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(64)
            self._sock = s
            self.last_error = None
            self._thread = threading.Thread(target=self._serve_loop, args=(s,),
                                            daemon=True)
            self._thread.start()
            print(f"[*] capture listener on {self.host}:{self.port}")

    def stop(self):
        with self._lock:
            self._stop.set()
            sock = self._sock
            self._sock = None
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
        old_host, old_port = self.host, self.port
        self.stop()
        time.sleep(0.2)
        self.host, self.port = host, port
        try:
            self.start()
            return True, None
        except Exception as e:
            self.host, self.port = old_host, old_port
            self.last_error = str(e)
            try:
                self.start()
            except Exception:
                pass
            return False, str(e)


controller = ListenerController(CAPTURE_HOST, CAPTURE_PORT)


def _valid_port(p):
    return isinstance(p, int) and 1 <= p <= 65535


class _API(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-OAST-Token, Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("X-OAST-Token", "") == TOKEN

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-OAST-Token, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        if not self._authed():
            self._send({"error": "unauthorized"}, 401)
            return
        if self.path.startswith("/notifications"):
            only_matched = "matched=1" in self.path
            with _lock:
                active = [h for h in _hits if not h["cleared"]]
            matched_count = sum(1 for h in active if h.get("matched"))
            items = [h for h in active if h.get("matched")] if only_matched else active
            self._send({"count": len(items),
                        "matched_count": matched_count,
                        "total_count": len(active),
                        "items": items})
        elif self.path == "/tokens":
            with _tokens_lock:
                toks = [{"token": t, **v} for t, v in _tokens.items()]
            self._send({"tokens": toks})
        elif self.path == "/config":
            self._send({
                "host": controller.host,
                "port": controller.port,
                "allowed_hosts": sorted(ALLOWED_BIND_HOSTS),
                "last_error": controller.last_error,
            })
        elif self.path == "/rules":
            with _rules_lock:
                self._send({
                    "src_ips": sorted(set(_rules["src_ips"])),
                    "dst_ports": sorted(set(_rules["dst_ports"])),
                    "kinds": sorted(set(_rules["kinds"])),
                })
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        if not self._authed():
            self._send({"error": "unauthorized"}, 401)
            return
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
        elif self.path == "/tokens-add":
            data = self._read_json()
            tok = str(data.get("token", "")).strip()
            label = str(data.get("label", "")).strip()
            if not tok:
                self._send({"ok": False, "error": "token required"}, 400)
                return
            with _tokens_lock:
                _tokens[tok] = {"label": label or tok, "created": time.time()}
            _save_tokens()
            # retroactively re-match existing hits against the new token
            with _lock:
                for h in _hits:
                    if not h.get("matched") and tok.lower() in (h.get("raw", "").lower()):
                        h["matched"] = True
                        h["token"] = tok
            self._send({"ok": True, "token": tok})
        elif self.path == "/tokens-remove":
            data = self._read_json()
            tok = str(data.get("token", "")).strip()
            with _tokens_lock:
                _tokens.pop(tok, None)
            _save_tokens()
            self._send({"ok": True})
        elif self.path in ("/rules-add", "/rules-remove"):
            data = self._read_json()
            rtype = str(data.get("type", "")).strip()   # src_ip | dst_port | kind
            value = data.get("value")
            key = {"src_ip": "src_ips", "dst_port": "dst_ports", "kind": "kinds"}.get(rtype)
            if not key or value in (None, ""):
                self._send({"ok": False, "error": "need type (src_ip|dst_port|kind) and value"}, 400)
                return
            if rtype == "dst_port":
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    self._send({"ok": False, "error": "dst_port must be a number"}, 400)
                    return
            with _rules_lock:
                lst = _rules[key]
                if self.path == "/rules-add":
                    if value not in lst:
                        lst.append(value)
                else:
                    if value in lst:
                        lst.remove(value)
            _save_rules()
            # also retroactively hide already-captured matching hits on add
            if self.path == "/rules-add":
                with _lock:
                    for h in _hits:
                        if _hit_matches(h, rtype, value):
                            h["cleared"] = True
            with _rules_lock:
                self._send({"ok": True,
                            "src_ips": sorted(set(_rules["src_ips"])),
                            "dst_ports": sorted(set(_rules["dst_ports"])),
                            "kinds": sorted(set(_rules["kinds"]))})
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
                            "error": f"host must be one of {sorted(ALLOWED_BIND_HOSTS)}"}, 400)
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


ETH_P_ALL = 0x0003


def _hexdump(data, limit=256):
    data = data[:limit]
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hexpart:<48}  {asciipart}")
    return "\n".join(out)


def _decode_packet(frame):
    """Decode an Ethernet frame. Returns (kind, src, dst, summary) or None to
    DROP. Most-aggressive filter: keep only IPv4 packets whose destination is
    our VPS, excluding SSH and our own API port."""
    if len(frame) < 14:
        return None
    eth_type = (frame[12] << 8) | frame[13]
    payload = frame[14:]

    # DROP everything that isn't IPv4 (ARP, 0x0027 link chatter, IPv6, etc.)
    if eth_type != 0x0800 or len(payload) < 20:
        return None

    ihl = (payload[0] & 0x0F) * 4
    proto = payload[9]
    src = ".".join(str(b) for b in payload[12:16])
    dst = ".".join(str(b) for b in payload[16:20])

    # DROP unless this packet is arriving AT our VPS. Kills all our outbound,
    # provider chatter, broadcast and multicast in one check.
    if dst != KEEP_DST_IP:
        return None

    l4 = payload[ihl:]
    if proto == 6 and len(l4) >= 20:   # TCP
        sport = (l4[0] << 8) | l4[1]
        dport = (l4[2] << 8) | l4[3]
        if dport in DROP_PORTS:        # SSH / our API
            return None
        doff = (l4[12] >> 4) * 4
        body = l4[doff:]
        head = f"TCP {src}:{sport} -> {dst}:{dport}  ({len(body)} bytes payload)"
        txt = head + "\n\n" + (body.decode("utf-8", "replace") if body else "(no payload)") \
              + "\n\n--- hex ---\n" + _hexdump(l4)
        return ("tcp", f"{src}:{sport}", f"{dst}:{dport}", txt)
    if proto == 17 and len(l4) >= 8:   # UDP
        sport = (l4[0] << 8) | l4[1]
        dport = (l4[2] << 8) | l4[3]
        if dport in DROP_PORTS:
            return None
        body = l4[8:]
        label = "UDP"
        if dport == 53 or sport == 53:
            label = "UDP/DNS"
        head = f"{label} {src}:{sport} -> {dst}:{dport}  ({len(body)} bytes)"
        txt = head + "\n\n--- hex ---\n" + _hexdump(body)
        return ("dns" if "DNS" in label else "udp", f"{src}:{sport}", f"{dst}:{dport}", txt)
    if proto == 1:                     # ICMP
        return ("icmp", src, dst, f"ICMP {src} -> {dst}\n\n" + _hexdump(l4))
    return ("ip", src, dst, f"IP proto {proto} {src} -> {dst}\n\n" + _hexdump(payload))


def _sniffer():
    """Capture EVERY frame on the interface (TCP/UDP/ARP/ICMP/...) and record it.
    Filters out our own API port so we don't sniff our own poll traffic into a loop."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except (AttributeError, PermissionError, OSError) as e:
        print(f"[!] sniffer disabled ({e}). Needs Linux + root. TCP capture on "
              f"{CAPTURE_PORT} still works.")
        return
    print("[*] raw sniffer active (all ports, all protocols)")
    while True:
        try:
            frame = s.recv(65535)
        except OSError:
            continue
        dec = _decode_packet(frame)
        if not dec:
            continue
        kind, src, dst, txt = dec
        # don't capture our own API traffic (the poll loop) or we feedback-spiral
        if f":{API_PORT}" in src or f":{API_PORT}" in dst:
            continue
        # live mute rules (added by clicking packets in the dashboard)
        if _muted_by_rules(kind, src, dst):
            continue
        src_ip = src.split(":")[0] if src else "?"
        src_port = src.split(":")[1] if ":" in src else "0"
        _record(src_ip, src_port, txt, kind=kind, extra={"dst": dst})


def _api_server():
    HTTPServer((API_HOST, API_PORT), _API).serve_forever()


SNIFFER_ENABLED = os.environ.get("OAST_SNIFFER", "1") != "0"


if __name__ == "__main__":
    _load_rules()
    _load_tokens()
    controller.start()
    if SNIFFER_ENABLED:
        threading.Thread(target=_sniffer, daemon=True).start()
    else:
        print("[*] sniffer off (OAST_SNIFFER=0); TCP capture only")
    print(f"[*] notification API on {API_HOST}:{API_PORT} (token required)")
    _api_server()
