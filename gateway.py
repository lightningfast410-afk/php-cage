# gateway.py — the php-cage as a real, deployable HTTP gateway.
#
# This is #1 on the top-50 profit builds: the v3 cage turned
# from a demo into a server that actually sits in front of PHP
# and proxies real HTTP traffic. Standard library only.
#
# How it works (same checks as v3, now on live traffic):
#   admin path first: POST /__cage/revoke revokes a client
#     (admin token = HMAC(master, "revoke:"+kid+":"+ts), header
#     X-Cage-Admin "<ts>:<sig>", body = kid, plain text).
#   then, for every other request: published path only,
#     GET/POST only, body cap, upload-progress path closed,
#     valid fresh single-use per-client key, per-client rate
#     limit — then proxy to the upstream PHP server with an
#     internal token only the gateway knows, and strip the
#     PHP version banner from the response.
#
# Configuration (environment, fail-closed):
#   CAGE_MASTER_SECRET — required; without it the gateway
#     refuses to start. From a secret store, never in code.
#   UPSTREAM — host:port of the PHP server (default
#     127.0.0.1:8081). The upstream must only accept traffic
#     carrying the internal token, and ideally only from the
#     gateway's network — otherwise the cage can be bypassed
#     by going straight to upstream, exactly as in v3.
#   PORT — gateway listen port (default 8080).
#   PUBLISHED — comma-separated published paths (default
#     /index.php,/submit.php,/api/data.php).
#
# Honest limits (same as v3): keys must travel over HTTPS in
# production — this demo server itself speaks plain HTTP, so
# put it behind a TLS terminator before any real use, or keys
# can be sniffed. A stolen master secret falls everything.
# The gateway does not patch PHP and cannot fix flaws in the
# application behind the door.
import hashlib
import hmac
import json
import os
import sys
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MASTER = os.environ.get("CAGE_MASTER_SECRET")
if not MASTER:
    print("GATEWAY REFUSES TO START: no master secret set (fail-closed).")
    sys.exit(1)
MASTER_B = MASTER.encode()
INTERNAL = hmac.new(MASTER_B, b"internal", hashlib.sha256).hexdigest()
UPSTREAM = os.environ.get("UPSTREAM", "127.0.0.1:8081")
PORT = int(os.environ.get("PORT", "8080"))
TOLERANCE = 300
MAX_BODY = 1_000_000
ALLOWED_METHODS = {"GET", "POST"}
PUBLISHED = set(os.environ.get(
    "PUBLISHED", "/index.php,/submit.php,/api/data.php").split(","))
revoked = set()
seen_nonces = {}
buckets = {}
audit = []
prev_hash = "0" * 64


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def client_secret(kid: str) -> bytes:
    return hmac.new(MASTER_B, kid.encode(), hashlib.sha256).digest()


def make_token(kid: str, ts: int, nonce: str, method: str, path: str, body: bytes) -> str:
    msg = f"{kid}:{ts}:{nonce}:{method}:{path}:{body_hash(body)}".encode()
    return f"{kid}:{ts}:{nonce}:" + hmac.new(client_secret(kid), msg, hashlib.sha256).hexdigest()


def chain_log(decision: str, detail: str):
    global prev_hash
    entry = {"decision": decision, "detail": detail}
    blob = (prev_hash + json.dumps(entry, sort_keys=True)).encode()
    h = hashlib.sha256(blob).hexdigest()
    audit.append({"prev": prev_hash, "entry": entry, "hash": h})
    prev_hash = h


def verify_chain() -> bool:
    prev = "0" * 64
    for rec in audit:
        blob = (prev + json.dumps(rec["entry"], sort_keys=True)).encode()
        if hashlib.sha256(blob).hexdigest() != rec["hash"] or rec["prev"] != prev:
            return False
        prev = rec["hash"]
    return True


def bucket_allow(kid: str, now: float) -> bool:
    tokens, last = buckets.get(kid, (5.0, now))
    tokens = min(5.0, tokens + (now - last) * (1 / 12))
    if tokens >= 1:
        buckets[kid] = (tokens - 1, now)
        return True
    buckets[kid] = (tokens, now)
    return False


def verify_token(token: str, method: str, path: str, body: bytes, now: float):
    try:
        kid, ts, nonce, sig = token.split(":")
        ts = int(ts)
    except ValueError:
        return None, "malformed key"
    if kid in revoked:
        return None, "revoked key"
    if abs(now - ts) > TOLERANCE:
        return None, "stale key"
    if (kid, nonce) in seen_nonces:
        return None, "replayed key"
    msg = f"{kid}:{ts}:{nonce}:{method}:{path}:{body_hash(body)}".encode()
    expect = hmac.new(client_secret(kid), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None, "bad key"
    seen_nonces[(kid, nonce)] = ts + TOLERANCE
    return kid, "ok"


def proxy(method: str, path: str, body: bytes):
    host, port = UPSTREAM.split(":")
    conn = HTTPConnection(host, int(port), timeout=5)
    conn.request(method, path, body=body,
                 headers={"X-Cage-Internal": INTERNAL,
                          "Content-Length": str(len(body))})
    resp = conn.getresponse()
    data = resp.read()
    headers = {k: v for k, v in resp.getheaders()
               if k.lower() != "x-powered-by"}
    conn.close()
    return resp.status, data, headers


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, body: bytes, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self, reason):
        chain_log("DENY", reason)
        self._send(403, reason.encode())

    def _handle(self):
        now = time.time()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        # Admin path: revoke a client. Checked before all else.
        if self.path == "/__cage/revoke" and self.command == "POST":
            admin = self.headers.get("X-Cage-Admin", "")
            try:
                ts, sig = admin.split(":")
                ts = int(ts)
            except ValueError:
                return self._deny("bad admin token")
            kid = body.decode()
            expect = hmac.new(
                MASTER_B, f"revoke:{kid}:{ts}".encode(),
                hashlib.sha256).hexdigest()
            if abs(now - ts) > TOLERANCE or not hmac.compare_digest(expect, sig):
                return self._deny("bad admin token")
            revoked.add(kid)
            chain_log("REVOKE", kid)
            return self._send(200, f"revoked {kid}".encode())
        if self.path not in PUBLISHED:
            return self._deny("door not on the map")
        if self.command not in ALLOWED_METHODS:
            return self._deny("method not allowed")
        if len(body) > MAX_BODY:
            return self._deny("body too big")
        if b"PHP_SESSION_UPLOAD_PROGRESS" in body:
            return self._deny("upload-progress path closed")
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Cage "):
            return self._deny("no key — strangers never reach PHP")
        kid, reason = verify_token(auth[5:], self.command, self.path, body, now)
        if kid is None:
            return self._deny(reason)
        if not bucket_allow(kid, now):
            return self._deny("rate limited")
        try:
            status, data, headers = proxy(self.command, self.path, body)
        except Exception:
            chain_log("DENY", "upstream unavailable")
            return self._send(502, b"upstream unavailable")
        chain_log("ALLOW", f"{self.command} {self.path}")
        return self._send(status, data, headers)

    do_GET = _handle
    do_POST = _handle
    do_DELETE = _handle
    do_PUT = _handle


def main():
    print(f"PHP cage gateway listening on :{PORT}, upstream {UPSTREAM}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
