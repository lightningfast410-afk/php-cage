# PHP Cage v3 — a server-wide gateway for PHP

## What it is

A deny-by-default gateway that sits in front of a whole PHP
server — every site on it — and lets a request reach PHP only
if it passes every check, in order:

1. The path is a published script (every other `.php` door on
   the server is closed; the published list is explicit).
2. The method is allowed (GET/POST only).
3. The body is under the size cap.
4. The body does not use the session upload-progress path
   (the most abused PHP2Shell path — closed outright).
5. It carries a valid, fresh, single-use key: HMAC-bound to
   the exact method, path and body, 5-minute expiry, nonce
   that works exactly once (replays denied).
6. The client is not revoked and not rate-limited (per-client
   keys derived from one master secret; revocation is a kill
   switch; each client is rate-limited).
7. The gateway forwards with an internal token only it knows
   — direct calls to PHP are refused, so there is no way
   around the cage door.
8. On the way out, the gateway strips the PHP version banner
   (servers that advertise old PHP get target-listed).

## What it is NOT

It is not a patch for PHP. The October 2026 PHP2Shell flaws
(CVE-2026-109618, CVE-2026-109619, CVSS 9.2, exploited in the
wild) are fixed only by updating PHP to 8.5.12, 8.4.27,
8.3.36 or 8.2.35 — see PATCH-GUIDE.md. The cage closes the
attack path; it does not fix the underlying flaws, flaws in
the application code behind the door, or anything else on the
server. Nothing makes software permanently flaw-free; the
permanent part is the process: update, restart, verify,
rotate-if-exposed, gate — every patch cycle.

## How to run

The cage refuses to start without a master secret
(fail-closed). Set it from a secret store, never in code:

```
CAGE_MASTER_SECRET=<from your secret store> python3 php-cage-v3.py
```

Keys must travel over HTTPS only. On plain HTTP, anyone on
the path can sniff a valid key and use it until it expires
or is revoked. Guard the master secret like a password and
rotate it on suspicion — if it leaks, every derived key
falls with it.

## Proof (test run, this machine)

- 8 attack classes blocked (no key, direct bypass, tampered
  body, expired key, wrong door, banned method, oversized
  body, upload-progress body), plus replay blocked, revoked
  client blocked, 6th rapid request rate-limited.
- 6 legit requests through, 16 audit entries, hash chain
  valid, version banner stripped.
- Without a master secret: refuses to start (exit 1).

## Files

- `php-cage-v3.py` — the cage (standard library only).
- `gateway.py` — the cage as a deployable HTTP gateway that
  actually proxies to PHP (standard library only).
- `PATCH-GUIDE.md` — the vendor patch procedure for PHP2Shell.

## License

MIT License — see `LICENSE` in this repo. Copyright (c) 2026
Zackariah Partridge.
