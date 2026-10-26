#!/usr/bin/env python3
"""php-patch-check.py — verify a PHP install against the PHP2Shell fixes.

Runs ON the server that runs PHP (it needs the php binary).
Standard library only. No network access, no changes made.

Usage:
    python3 php-patch-check.py [--php PATH]

Checks (each prints PASS, FAIL, or WARN):
  1. version — PHP2Shell (CVE-2026-109618, CVE-2026-109619) is
     fixed only in 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (8.6.0+).
     Anything at or below 8.1 has no official fixed release.
  2. session.upload_progress.enabled == 0 — the most abused
     PHP2Shell path. Must be set server-level (FPM pool or
     Apache config) before request parsing; ini_set is too late.
  3. expose_php == Off — a version banner is a targeting signal.
  4. display_errors == Off in production (WARN if on).
  5. memory_limit — the OOM-path mitigation is an ADMIN-enforced
     -1 (FPM pool / Apache config, not app-overridable), paired
     with a container/cgroup limit that kills only the affected
     worker. A finite limit alone is not the mitigation (WARN).

Exit code: 0 = no FAIL, 1 = any FAIL, 2 = error (php binary
missing or its output unparseable). WARN never fails the run.

This checker proves the patch landed. It does not patch
anything: updating PHP is still the owner's job, followed by
restarting every PHP worker and verifying again.
"""

import argparse
import re
import subprocess
import sys

# (major, minor) -> minimum fixed patch version. 8.6 fixed in 8.6.0.
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12, (8, 6): 0}


def run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def parse_version(text):
    match = re.search(r"PHP (\d+)\.(\d+)\.(\d+)", text or "")
    if not match:
        return None
    return tuple(int(g) for g in match.groups())


def parse_ini(text):
    values = {}
    for line in (text or "").splitlines():
        match = re.match(r"^([A-Za-z0-9_.]+)\s+=>\s+(\S+)", line.strip())
        if match:
            values.setdefault(match.group(1), match.group(2))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--php", default="php", help="php binary to check")
    args = parser.parse_args()

    version_out = run([args.php, "-v"])
    if version_out is None:
        print("error: cannot run php binary: %s" % args.php)
        return 2
    version = parse_version(version_out)
    if version is None:
        print("error: cannot parse php version output")
        return 2

    ini_out = run([args.php, "-i"])
    ini = parse_ini(ini_out)

    results = []  # (name, status, detail)

    major, minor, patch = version
    ver_str = "%d.%d.%d" % version
    if (major, minor) in FIXED:
        if patch >= FIXED[(major, minor)]:
            results.append(("version", "PASS",
                            "%s is at or above the fixed release" % ver_str))
        else:
            results.append(("version", "FAIL",
                            "%s is below the fixed release for %d.%d"
                            % (ver_str, major, minor)))
    elif major > 8 or (major == 8 and minor > 6):
        results.append(("version", "PASS",
                        "%s is newer than the known fixed lines; "
                        "confirm against vendor notes" % ver_str))
    else:
        results.append(("version", "FAIL",
                        "%s has no official fixed release; vendor "
                        "backports are minimal mitigation, not a "
                        "supported release" % ver_str))

    upload = ini.get("session.upload_progress.enabled")
    if upload == "0":
        results.append(("session.upload_progress.enabled", "PASS", "disabled"))
    elif upload is None:
        results.append(("session.upload_progress.enabled", "WARN",
                        "not found in php -i output; verify server-level setting"))
    else:
        results.append(("session.upload_progress.enabled", "FAIL",
                        "enabled (%s); set to 0 server-level and restart "
                        "workers" % upload))

    expose = ini.get("expose_php")
    if expose and expose.lower() == "off":
        results.append(("expose_php", "PASS", "Off"))
    elif expose is None:
        results.append(("expose_php", "WARN", "not found in php -i output"))
    else:
        results.append(("expose_php", "FAIL",
                        "On; set expose_php=Off and restart workers"))

    display = ini.get("display_errors")
    if display and display.lower() == "off":
        results.append(("display_errors", "PASS", "Off"))
    elif display is None:
        results.append(("display_errors", "WARN", "not found in php -i output"))
    else:
        results.append(("display_errors", "WARN",
                        "On; turn Off in production (errors to logs only)"))

    mem = ini.get("memory_limit")
    if mem == "-1":
        results.append(("memory_limit", "PASS",
                        "-1 (admin-enforced); pair with a container/cgroup "
                        "limit that kills only the affected worker"))
    elif mem is None:
        results.append(("memory_limit", "WARN", "not found in php -i output"))
    else:
        results.append(("memory_limit", "WARN",
                        "%s; a finite limit alone is not the OOM-path "
                        "mitigation (see PATCH-GUIDE.md)" % mem))

    for name, status, detail in results:
        print("%s: %s — %s" % (status, name, detail))
    failed = sum(1 for _, s, _ in results if s == "FAIL")
    warned = sum(1 for _, s, _ in results if s == "WARN")
    print("summary: %d FAIL, %d WARN, %d checks" % (failed, warned, len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
