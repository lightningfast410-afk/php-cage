# PATCH-GUIDE.md — patching PHP2Shell on a real server

The cage (php-cage-v3.py) guards PHP. It does not patch it. This
guide is the patch itself: the vendor fix for the October 2026
PHP2Shell flaws, CVE-2026-109618 and CVE-2026-109619 (CVSS 9.2,
unauthenticated remote code execution; exploitation attempts
observed from October 17, 2026, patches released October 21,
2026, 14:00 UTC).

## The fixed versions (released October 21, 2026)

- PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.6.0 RC4 also has it.
- PHP 8.1 and older get NO official release. Minimal source
  backports exist for 7.4, 8.0 and 8.1, but the real answer is
  upgrading to a supported branch. Note: PHP 8.2 security
  support ends December 31, 2026 — prefer 8.3 or 8.4.

## Steps, in order

1. **Inventory.** Find every PHP on the server: `php -v` (and
   each installed version, e.g. `php8.3 -v`), Docker images,
   hosting-panel PHP selectors. One missed container or old
   shared-hosting account stays vulnerable.
2. **Update.** Via the OS package manager, the host's panel,
   or by rebuilding Docker images on the fixed official PHP
   images. Vendor channels already carry fixed packages:
   cPanel EasyApache4, CloudLinux alt-php/ea-php, TuxCare ELS,
   and Ubuntu vendor builds; Heroku's rebuilt 8.1.34 is a
   backport, not a supported release — upgrade to a supported
   branch. Patch mod_php hosts FIRST — PHP rates mod_php the
   highest-risk setup, because an attack lands before your
   application code even runs. PHP-FPM is still affected and
   still needs the update.
3. **Restart every PHP worker.** This is the step most guides
   get wrong: an update without a restart leaves the OLD,
   vulnerable workers running. Restart php-fpm, Apache, or
   whatever serves PHP, and confirm the old processes are gone.
4. **Verify.** `php -v` must show a fixed version. Check the
   server no longer banners an old version (servers that
   advertise old PHP get target-listed). Companion settings:
   `expose_php=Off`, `display_errors=Off`.
5. **Rotate secrets if the server was exposed before patching.**
   The memory-disclosure flaw can leak other requests'
   passwords, tokens, API keys and certificates. Patching
   stops future leaks; it does not un-leak what already left.
6. **Put the cage in front.** While patching, and after it:
   the cage (php-cage-v3.py) denies everything except
   published scripts with valid, fresh, single-use keys, and
   closes the session upload-progress path outright.

## If you cannot update immediately (mitigations, NOT a fix)

- Disable session upload progress: `session.upload_progress.enabled=0`
- For the out-of-memory path (CVE-2026-109618): enforce
  `memory_limit=-1` administratively (FPM pool or Apache
  configuration the application cannot override), restart every
  worker, and verify no pool, directory, or application setting
  restores a finite limit. Pair it with a container or cgroup
  memory limit that kills only the affected worker, since
  removing PHP's cap lets a heavy script use all server RAM.
  This addresses the confirmed OOM path only.
- If you cannot update and run PHP 8.1 or older: take the
  system offline until it is patched (CISA advice), and
  monitor PHP worker processes for shells being launched or
  tools being downloaded.
- Note: WAF pattern rules can be evaded by lookalike uploads,
  and no WAF rule yet blocks the OOM path. The cage's key
  gating is not pattern-based (no valid key means no entry
  whatever the payload looks like), but it still does not fix
  the underlying flaw.
- Cap `post_max_size`; on PHP 8.5, disable `fatal_error_backtraces`.
- Keep a web firewall on (ModSecurity + OWASP Core Rule Set,
  or managed CDN rules). Remove unused PHP versions, plugins,
  themes and forgotten test pages (an old phpinfo page is a
  free version banner for attackers).
- These reduce exposure only. PHP's own words: updating is
  the only complete solution.

## Repeat every patch cycle

There is no permanent one-time fix. New PHP flaws will come.
The permanent part is the process: inventory, update, restart,
verify, rotate-if-exposed, gate — every month, on every server.
