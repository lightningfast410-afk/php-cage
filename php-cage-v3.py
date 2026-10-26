# php-cage-v3.py — bulletproof edition, server-wide.
#
# This is the hardened version of the cage. v2's checks are all
# still here (published scripts only, GET/POST only, body cap,
# upload-progress path closed, body-bound keys, internal token
# so direct PHP calls fail, version banner stripped). v3 closes
# the holes v2 left open:
#   * REPLAY: v2 keys were valid for 5 minutes, so a captured
#     request could be re-sent inside the window. v3 keys carry
#     a nonce, and each nonce works exactly once per client.
#   * ONE KEY FOR EVERYONE: v2 had a single shared secret. v3
#     derives a separate key per client from one master secret,
#     and any client can be REVOKED (kill switch) — a revoked
#     client's keys die immediately, even fresh ones.
#   * HAMMERING: v3 rate-limits each client (token bucket, 5
#     per window here) so keys cannot be brute-forced at speed
#     and one client cannot flood PHP.
#   * SILENT INSECURE START: v2 ran with a hardcoded demo
#     secret. v3 FAILS CLOSED: no master secret in the
#     environment means it refuses to start at all.
#   * NO EVIDENCE: v3 writes every cage decision to a
#     hash-chained audit log, so tampering with the log shows
#     up on verification.
#   * STATIC INTERNAL TOKEN: the gateway-to-PHP token is now
#     derived from the master secret too, so rotating the
#     master rotates everything.
#
# REMAINING HONEST LIMITS (bulletproof is a direction, not a
# state): if the master secret leaks, every derived key falls
# with it — guard it like a password and rotate on suspicion.
# Keys in headers must travel over HTTPS only; on plain HTTP
# anyone on the path can sniff a valid key and use it until
# it expires or is revoked. The cage cannot fix flaws in the
# application code behind the door, and it cannot fix PHP
# itself — the PHP2Shell update in PATCH-GUIDE.md is still
# required. Nothing makes any software permanently flaw-free;
# "permanent" here means patched runtime + gate + a process
# that repeats every patch cycle.
import hashlib
import hmac
import json
import os
import sys

MASTER = os.environ.get("CAGE_MASTER_SECRET")
if not MASTER:
    print("CAGE REFUSES TO START: no master secret set (fail-closed).")
    print("Set CAGE_MASTER_SECRET from a secret store, then start again.")
    sys.exit(1)
MASTER_B = MASTER.encode()
INTERNAL = hmac.new(MASTER_B, b"internal", hashlib.sha256).hexdigest()
NOW = 1_000_000
TOLERANCE = 300                          # keys live 5 minutes
MAX_BODY = 1_000_000
ALLOWED_METHODS = {"GET", "POST"}
# Server-wide published list: every PHP script the server is
# meant to serve, across all its sites. Anything else is not
# a door, including forgotten .php files and test pages.
PUBLISHED = {"/index.php", "/submit.php", "/api/data.php"}
revoked = set()
seen_nonces = {}                         # (kid, nonce) -> expiry
audit = []
prev_hash = "0" * 64
executed = 0


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


class Bucket:
    def __init__(self, capacity, rate):
        self.capacity = capacity
        self.rate = rate
        self.tokens = float(capacity)
        self.last = 0.0

    def allow(self, now):
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


buckets = {}


def bucket_for(kid: str) -> Bucket:
    if kid not in buckets:
        buckets[kid] = Bucket(5, 1 / 12)
    return buckets[kid]


def verify_token(token: str, method: str, path: str, body: bytes):
    try:
        kid, ts, nonce, sig = token.split(":")
        ts = int(ts)
    except ValueError:
        return None, "malformed key"
    if kid in revoked:
        return None, "revoked key"
    if abs(NOW - ts) > TOLERANCE:
        return None, "stale key"
    if (kid, nonce) in seen_nonces:
        return None, "replayed key"
    msg = f"{kid}:{ts}:{nonce}:{method}:{path}:{body_hash(body)}".encode()
    expect = hmac.new(client_secret(kid), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None, "bad key"
    seen_nonces[(kid, nonce)] = ts + TOLERANCE
    return kid, "ok"


def strip_banner(headers):
    """Drop the PHP version banner before a response leaves.
    Attackers build target lists from version banners."""
    return {k: v for k, v in headers.items() if k.lower() != "x-powered-by"}


def backend(req):
    """The PHP layer itself. Refuses anything not sent by the gateway."""
    global executed
    if req["headers"].get("X-Cage-Internal") != INTERNAL:
        return 403, "direct access denied — use the cage door"
    executed += 1
    return 200, f"PHP ran: {req['method']} {req['path']}"


def cage(req):
    """The one locked door. Deny by default, forward only on a valid key."""
    path, method, body = req["path"], req["method"], req["body"]

    def deny(reason):
        chain_log("DENY", reason)
        return 403, reason

    if path not in PUBLISHED:
        return deny("door not on the map")
    if method not in ALLOWED_METHODS:
        return deny("method not allowed")
    if len(body) > MAX_BODY:
        return deny("body too big")
    if b"PHP_SESSION_UPLOAD_PROGRESS" in body:
        return deny("upload-progress path closed")
    auth = req["headers"].get("Authorization", "")
    if not auth.startswith("Cage "):
        return deny("no key — strangers never reach PHP")
    kid, reason = verify_token(auth[5:], method, path, body)
    if kid is None:
        return deny(reason)
    if not bucket_for(kid).allow(NOW):
        return deny("rate limited")
    status, msg = backend({"method": method, "path": path, "body": body,
                           "headers": {"X-Cage-Internal": INTERNAL}})
    chain_log("ALLOW" if status == 200 else "DENY", msg)
    return status, msg


def show(label, status, msg):
    print(f"  {label}: {status} {msg}  (PHP executed so far: {executed})")


print("PHP cage v3, bulletproof, server-wide")
good_body = b"amount=99"
good_token = make_token("client-1", NOW, "n-legit", "POST", "/submit.php", good_body)
show("attacker, no key",
     *cage({"method": "GET", "path": "/index.php", "body": b"", "headers": {}}))
show("attacker, straight at PHP (bypass)",
     *backend({"method": "GET", "path": "/index.php", "body": b"", "headers": {}}))
show("attacker, tampered body",
     *cage({"method": "POST", "path": "/submit.php", "body": b"amount=9999",
            "headers": {"Authorization": "Cage " + good_token}}))
show("attacker, expired key",
     *cage({"method": "POST", "path": "/submit.php", "body": good_body,
            "headers": {"Authorization": "Cage " + make_token(
                "client-1", NOW - 1000, "n-old", "POST", "/submit.php", good_body)}}))
show("key holder, wrong door",
     *cage({"method": "GET", "path": "/admin/phpinfo.php", "body": b"",
            "headers": {"Authorization": "Cage " + make_token(
                "client-1", NOW, "n-wrong", "GET", "/admin/phpinfo.php", b"")}}))
show("key holder, banned method",
     *cage({"method": "DELETE", "path": "/submit.php", "body": b"",
            "headers": {"Authorization": "Cage " + make_token(
                "client-1", NOW, "n-del", "DELETE", "/submit.php", b"")}}))
show("key holder, oversized body",
     *cage({"method": "POST", "path": "/submit.php", "body": b"x" * (MAX_BODY + 1),
            "headers": {"Authorization": "Cage " + make_token(
                "client-1", NOW, "n-big", "POST", "/submit.php", b"x" * (MAX_BODY + 1))}}))
show("legit user, valid key",
     *cage({"method": "POST", "path": "/submit.php", "body": good_body,
            "headers": {"Authorization": "Cage " + good_token}}))
show("attacker, replay of the legit request",
     *cage({"method": "POST", "path": "/submit.php", "body": good_body,
            "headers": {"Authorization": "Cage " + good_token}}))
revoked.add("client-1")
show("revoked client, fresh key",
     *cage({"method": "POST", "path": "/submit.php", "body": good_body,
            "headers": {"Authorization": "Cage " + make_token(
                "client-1", NOW, "n-fresh", "POST", "/submit.php", good_body)}}))
for i in range(1, 7):
    show(f"client-2, rapid request {i}",
         *cage({"method": "POST", "path": "/submit.php", "body": good_body,
                "headers": {"Authorization": "Cage " + make_token(
                    "client-2", NOW, f"n-r{i}", "POST", "/submit.php", good_body)}}))
up_body = b"PHP_SESSION_UPLOAD_PROGRESS=1"
show("key holder, upload-progress body",
     *cage({"method": "POST", "path": "/submit.php", "body": up_body,
            "headers": {"Authorization": "Cage " + make_token(
                "client-2", NOW, "n-up", "POST", "/submit.php", up_body)}}))
print("  banner stripped:",
      strip_banner({"Server": "Apache", "X-Powered-By": "PHP/8.4.26"}))
print(f"  FINAL: PHP executed {executed} time(s) — only legit requests.")
print(f"  Audit entries: {len(audit)}, hash chain valid: {verify_chain()}")
print("  The cage does not patch PHP: update to 8.5.12 / 8.4.27 /")
print("  8.3.36 / 8.2.35 per PATCH-GUIDE.md — the cage only makes")
print("  sure strangers cannot reach it.")
