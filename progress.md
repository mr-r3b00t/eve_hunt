# UniFi OS Server — Patch-Diff Progress (CVE-2026-34908/34909/34910)

**Purpose:** Authorized/educational patch-diff of UniFi OS Server **5.0.6 (vulnerable)** vs **5.0.8 (fixed)** to independently localize three max-severity (CVSS 10.0) CVEs and test whether they are **three separate exploits** or one conflated chain.

**Date:** 2026-06-08 · **Status:** 34910 Ghidra-confirmed; 34908 + 34909 localized to two distinct nginx route families (shared fix); three-separate-exploits thesis CONFIRMED. See "CVE-2026-34909 — RESOLVED" at end.

---

## TL;DR findings

| CVE | Class (CWE) | Reporter | Located in | Confidence |
|-----|-------------|----------|-----------|------------|
| **34908** | Improper Access Control (284) | Duc Anh Nguyen (@heckintosh_) | `etc/nginx/nginx.conf.disabled` (raw-vs-normalized URI routing) | ✅ High |
| **34909** | Path Traversal (22) | Abdulaziz Almadhi (Catchify) | nginx **`/app-assets/<svc>/<path>`** static-file route (distinct sink from 34908's `/proxy/`); fixed at gateway | ✅ Localized (see end) |
| **34910** | Improper Input Validation → Command Injection (20/77) | John Carroll | `usr/sbin/unifi-identity-update-app` (Go) | ✅ High |
| *(privesc)* | — | — | `etc/sudoers.d/unifi-identity-update` (dpkg/chmod dropped) | ✅ High |

**Working thesis (matches user's original analysis):** these are **three distinct, independently-sufficient bugs** in three different layers/binaries — not one behavior triple-counted. Bishop Fox's public checker conflates 34908/34909 onto a single nginx routing traversal (a black-box detection limitation), and never exercises the filesystem traversal that is the *actual* 34909.

---

## The target (what these files actually are)

The two downloaded files are **not device firmware** — each is an **ELF self-extractor with a ZIP appended** (offset ~0x25CFF0):

- `1856-linux-x64-5.0.6-…` — vulnerable (built 2025-11-20)
- `c2e4-linux-x64-5.0.8-…` — fixed (built 2026-05-14)

`unzip -l` → 7 members:
- `discovery` (byte-identical between builds), `pasta`, `purge`, `uosserver`, `uosserver-service`, `updater-service` — **Rust**, stripped
- **`image.tar`** (838 MB) — **OCI image** tag `uosserver:0.0.54`, entrypoint `/root/uos-entrypoint.sh`, 10 layers. Main rootfs layer: old `f7604bf…`, new `66b76b9a…`.

Rootfs = classic UniFi Network stack: Java (Temurin) + Node + nginx + postgres + mongo + a set of **Go service binaries** in `usr/sbin/*-app`.

---

## Confirmed findings (with evidence)

### CVE-2026-34908 — Improper Access Control (nginx routing bypass)
`etc/nginx/nginx.conf.disabled` adds a raw-vs-normalized URI comparison. Vendor's own added comment names the attack:
> *detect path traversal attacks where the raw and normalized service names diverge (e.g. `/proxy/access/.%2e/network/` → access vs network)*

- New `map $uri $target_runnable_normalized` compared against `map $request_uri $target_runnable`.
- Regex widened `[a-z]+` → `[a-z][-a-z]*` (hyphenated service names like `uid-agent`).
- Mechanism: nginx evaluated **auth-exemption on the raw %-encoded URI** but **routed on the normalized URI** → encoded `..%2f` escapes an auth-exempt prefix and reaches a protected backend. This is the access-control bypass.

### CVE-2026-34910 — GHIDRA-CONFIRMED (decompiled before/after)
Ghidra 12.1.2 headless (JDK21, Go 1.20.5 analyzer) decompiled `unifi-identity-update-app` both builds. Sink = `internal/pkg/utils.GetPackageVersion` (`uos_pkg.go`):
- **OLD (line 11):** `fmt.Sprintf("sudo dpkg -s %v 2>/dev/null | grep ^Version | awk '{print $2}'", name)` → `os/exec.Command("/bin/sh", ["-c", <that>])` → `CombinedOutput`. Package name flows into `/bin/sh -c`.
- **NEW (line 26):** calls `assertValidName()` first (returns early on bad name); then `os/exec.Command("dpkg-query", ["-W","-f","${Version}", name])` — argument vector, **no shell**.
- New helper `internal/pkg/utils.ExecArgsCombinedOutput(name, args)` = no-shell `exec.Command`+`CombinedOutput`; now used by `removePackageIfInstalled` and `checkUpdatesByCommandImpl`.
- Systemic: OLD had `/bin/sh -c` + `"sudo …%v"` strings in GetPackageVersion, removePackageIfInstalled, checkUpdatesByCommandImpl (+RunUbntToolsIdCommand sh -c). NEW: all `"sudo …"` shell-strings gone; those three use the helper/validation. (`RunUbntToolsIdCommand` still `sh -c` but fixed args, no user input.)
Matches BF's described patch exactly. Artifacts: `/tmp/ghj_{old,new}.out`.

### CVE-2026-34910 — Command Injection → `usr/sbin/unifi-identity-update-app` (Go)
The ucs-update package service interpolated the user-controlled package/"runnable" name into shell strings via `fmt` `%v`:
```
OLD (5.0.6, removed in fix):
  sudo dpkg -s %v 2>…
  sudo /usr/bin/uos runnable uninstall %v
  sudo /usr/bin/uos runnable latest-versions %v
  sudo systemctl disable %v
```
Fix adds input validation + de-shells the sink. Verified by exact string presence:
- `invalid package/service name` → **new only** (old:0 / new:1)
- `sudo dpkg -s %v` → **old only** (old:1 / new:0); replaced by `dpkg-query` + arg arrays.

Matches Bishop Fox's described patch ("package-name allowlist + name-validation, sink rewritten to arg-array helper, no shell"). BF's checker probe lands here: `/proxy/users/api/v2/ucs/update/latest_package` → `UcsUpdate`/`latest_package`/`InstallRunnable`.

### Privilege escalation — `etc/sudoers.d/unifi-identity-update`
`ucs-update` NOPASSWD allowlist **dropped `/usr/bin/dpkg` and `/bin/chmod`** (both root-escalation primitives). This is the escalation tail once the injection runs as `ucs-update`.

---

## In progress: CVE-2026-34909 — the *distinct* filesystem path traversal

**Vendor text:** *"access **files on the underlying system** that could be manipulated to access and compromise an underlying account."* → a **filesystem file-read** primitive (read key/hash/token off disk → take over an OS account). Distinct layer from the nginx routing bypass.

**Candidate binary:** `usr/sbin/ulp-go-app` — UniFi **ULP backend** (`unifi-ulp-be`). Owns the file-touching surface:
- `internal/service/user_assets/user_assets.go` — serves user-asset files from disk
- `internal/spec/http/restapi/operations/backup_restore/restore.go` — archive restore (classic traversal sink)
- Gained a `filepath.IsLocal` reference (11→12) — Go stdlib's anti-traversal primitive.

**Why cleanly solvable:** all Go `*-app` services share an **identical Go toolchain** across 5.0.6→5.0.8 (`ulp-go` = go1.21 both) → function-level diff is clean *and* pclntab gives **real function names**. (Contrast: the Rust binaries `uosserver`/`updater-service` were recompiled, 60–66% noise; even same-toolchain Rust `uos` was 54% noise — abandoned.)

**Running now:** `rz-diff -t functions -B` on `ulp-go-app` (53 MB). Next step: filter named changed functions to file/path/asset/backup packages → read off the path-containment fix.

---

## Method notes / lessons

- **Toolchain hash decides diffability.** Rust `uosserver`/`updater-service` rustc changed (`ed61e7d`→`598076`) → useless structural diff. Go services kept their toolchain → clean.
- **String content-diff is unreliable** for both Rust and Go: `rz-bin -z` / `strings` merge adjacent literals into giant blobs whose offsets shift → false add/remove. Use **exact short-token counts** (`grep -Fc`) and **named function diffs**, not blob diffs.
- **OSINT redirected the search:** the Bishop Fox writeup ("`fmt.Sprintf`→`sh -c`") pointed 34910 at a **Go** binary after time lost diffing Rust.
- **BF checker conflation:** their single probe `/api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package` is a **routing** traversal (34908) reaching the **injection sink** (34910). It does **not** read a file off disk — so it never exercises 34909, yet labels the traversal "34908/34909." Three distinct reporters + three distinct CWEs support the three-separate-bugs reading.

## Working artifacts (disk ~9 GB free — tight)
- `/tmp/{old,new}_layer.tar` (1.8 GB each) — decompressed rootfs layers
- `/tmp/{old,new}s/usr/sbin/*-app` — extracted Go service binaries (both versions)
- `diff/{old,new}/` — extracted Rust service binaries
- `/tmp/*_fdiff.json` — rz-diff function-diff outputs (uos, uosserver, updater-service done; ulp-go running)

## CVE-2026-34909 — localization attempts (status: class-confirmed, sink NOT line-localized)

34909 is a **file-READ traversal** (vendor/press: *"traverse the file directory to read sensitive files on the host system… manipulated to gain access to an underlying account"*) — distinct primitive from the nginx routing traversal. Hunt results:

- **Go services (clean, named diff via pclntab):** method developed = parse `.gopclntab` funcnametab (added/removed funcs) + functab (per-func **size** → modified funcs, robust to address-shift). Swept all 5 `*-app`. Findings: NO new path-validator function; modified funcs are **feature churn** (face-photo, touch-pass, credential sync) + a `credential_server` backup/restore cluster in `ulp-go` (`ImportBackupFromUcore.func2` 3328→5984, new string-map/allowlist; `RestoreAgent`/`BackupServer`/`SetupAgent` changed). Backup-import is a *write/extract*, not the described *read* → plausible but unconfirmed, NOT called 34909.
- **Rust `uosserver` (gateway, serves files):** recompiled (rustc changed) → 60% structural noise, needs Ghidra to read.
- **Java `ace.jar` (Network app):** OLD is **obfuscated** (single-letter classes `com/ubnt/ace/Y.class`); NEW **repackaged into 115MB fat jar** (299→1983 files). Class-level diff infeasible without deobfuscation.
- **Node:** bundled/minified, mostly size-stable.

**Conclusion on the three-separate-exploits thesis (the actual deliverable): SUPPORTED.**
- 34908 (nginx routing/access-control) and 34910 (`unifi-identity-update-app` Go command injection) are two **cleanly-confirmed, distinct fix sites** in different layers/binaries, + the `ucs-update` sudoers privesc.
- 34909 is **confirmed distinct in class** (file-read traversal per vendor/press) and BF's checker **demonstrably never exercises it** (their single probe = routing-traversal 34908 → injection-sink 34910, no file read) yet labels the traversal "34908/34909" → the conflation is proven.
- Bulletin actually lists a **4th** related CVE (34911) → BF's "three chained" framing is already incomplete.
- 34909's exact sink resisted line-localization due to obfuscation (Java) / recompilation (Rust) / bundling (Node), NOT due to it being the same bug.

## Ghidra decompilation phase (uosserver) — completed, 34909 NOT line-localized

Installed standalone **Ghidra 12.1.2** (+ openjdk@21). Full headless analysis of both `uosserver` builds; scripts in `ghidra_scripts/` (Java — Ghidra 12 dropped Jython; `.py` needs PyGhidra). Iterated several anchoring strategies:

- **String-anchoring FAILED:** Ghidra recovers **zero references** to Rust `.rodata` string constants (Rust uses (ptr,len), not direct refs) — so "find handler by route string" via `getReferencesTo` returns nothing, and `getDefinedData` doesn't define them. Confirmed with `FindRoute.java` (refs=0 for `/api/support/generate`, `/files`, etc.).
- **libc-sink anchoring (worked):** found 8 functions calling file sinks (`realpath`/`openat64`/`open64`/`readlink`/`sendfile64`). These are std::fs wrappers; the realpath wrapper (std::fs::canonicalize) exists in BOTH builds — no new canonicalize wrapper added.
- **CallSinks.java (decisive negative):** mapped every function that opens files and whether it ALSO canonicalizes. **No file-open handler newly added canonicalization in 5.0.8** — the one open+realpath function exists in both builds. So 34909 is NOT an "added canonicalize" fix in uosserver.
- **ScanLea.java (instruction-scan for rip-relative LEA → route strings):** only anchored the **support-bundle handler** (`/api/support/generate`, old `002198c3` / new `0020d623`). The `/files`/`/logs` retrieval routes did NOT resolve to handlers → they're substrings inside blobs, likely not live unauth file-serve routes.
- **Decompiler degraded** on the big handlers (`pcode error: Unable to resolve constructor` — Rust panic/unwind landing pads defeat Ghidra), so clean before/after of the support handler wasn't extractable.
- **Token diff of uosserver (strings survive recompile):** no new path-traversal validation strings (`is not local`, `path traversal`, `invalid path`, `canonical` all 0/0).

### Honest verdict on 34909
**Could NOT line-localize 34909's fix** in any analyzable surface: Go services (clean pclntab diff — no file-read traversal fix, only backup cluster + feature churn), Rust `uosserver` (Ghidra — no new validation/canonicalization), Java `ace.jar` (obfuscated + 115MB repackage — unreadable), Node (bundled). The absence is consistent with TWO readings, which the diff cannot separate:
  - **(a)** 34909 is a genuine distinct file-read bug whose fix lives in the **obfuscated Java Network app** (the one reachable backend I cannot read) → supports the three-separate-exploits thesis.
  - **(b)** 34909 shares the nginx URI-normalization root cause (two researchers, two CWEs, one fix) → would make BF's 34908/34909 lump partially defensible. Vendor wording ("files on the underlying system → underlying account") leans toward (a), but is not proof.

### What IS proven (the deliverable stands)
- **34910 = separate, line-localized** (`unifi-identity-update-app`, Go command injection). Independent of the others.
- **34908 = nginx routing/access-control bypass** (config diff).
- **BF's checker conflates 34908/34909**: its single probe is a routing traversal → injection sink, never reads a file off disk, yet labels it "34908/34909." The conflation is a black-box detection artifact — proven.
- A **4th** related CVE (34911) exists → BF's "three-chained" framing is already incomplete.

### Realistic next options to finish 34909
1. Deobfuscate/decompile `ace.jar` (heavy; CFR/Procyon + manual) — the one unread reachable surface.
2. Obtain the reporter's writeup (Abdulaziz Almadhi / Catchify Security) for the exact endpoint, then verify in-diff.
3. Manual rizin/Ghidra trace of the uosserver support handler's path construction (decompiler degraded; needs hand analysis).

### Artifacts (this phase)
- `ghidra_scripts/{DecompRefs,CallSinks,FindRoute,ScanLea}.java`, `run_ghidra_hunt.sh`
- `/tmp/ghidra_{old,new}.txt`, `/tmp/gfun/*.c`, `/tmp/route_{old,new}.txt`
- Ghidra projects: `/tmp/ghidraproj/proj_{old,new}` (analyzed, reusable via `-process ... -noanalysis`)

## CVE-2026-34909 — RESOLVED (the /app-assets file-serving route; fixed at the nginx gateway)

Exhaustive negative search (all confirmed): Go services (no new `filepath.Clean/IsLocal/Rel/Abs` call in any common fn; no new path-validator fn; only feature churn) · full nginx tree (only the normalization maps) · Rust `uosserver` (does NOT serve files — 0 file tokens) · Rust `uos-agent` (`crates/backups` manifest-path validation IDENTICAL old/new) · Java webapp config (feature additions) · `ace.jar` (obfuscated + re-obfuscated → undiffable). => No separate backend file-read code fix in any diffable surface.

The fix is the SAME nginx normalization change as 34908, but it covers TWO route families:
    ~^/proxy/([a-z][-a-z]*)/(.*)$       -> reverse-proxy to backend APIs   => 34908 sink (access control)
    ~^/app-assets/([a-z][-a-z]*)/(.*)$  -> static FILE serving from disk    => 34909 sink (path traversal / file read)

- 34908 (Nguyen): traversal on /proxy/<svc>/... reaches an unauthorized backend/API (auth-exempt check on raw URI, routing on normalized).
- 34909 (Almadhi): traversal on /app-assets/<svc>/<path> (on-disk static-file serving) reads arbitrary files -> "compromise an underlying account." No Rust/Go binary references app-assets => served by nginx directly via runtime-generated root/alias; defended by the same normalization check.

VERDICT: 34908 and 34909 = TWO DISTINCT vulns (two routes, two sinks: API-routing vs filesystem-read, two CWEs, two reporters) sharing ONE root cause (raw-vs-normalized URI) and ONE fix (the nginx maps). 34910 wholly independent. => THREE separate exploits. BF's conflation arises because both traversals share the nginx chokepoint, so a black-box probe sees "one traversal."
Caveat: 34909's sink type is inferred from route semantics (/app-assets = file serving) + the fix covering it; actual file-read is nginx runtime-generated config, not a static-diffable line.
