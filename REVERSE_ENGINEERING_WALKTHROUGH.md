# Reverse-Engineering Walkthrough — UniFi OS Server SAB-064 (CVE-2026-34908/34909/34910)

> **Authorized / educational use only.** This documents a patch-diffing exercise on two
> *publicly downloadable* vendor builds, performed to understand already-disclosed and
> already-patched vulnerabilities. No live systems were attacked. Do this only on software
> you are licensed to analyze, for defensive/research purposes.

**Objective:** Take the last-vulnerable and first-fixed builds of UniFi OS Server, diff them,
and independently localize the three CVSS-10.0 vulnerabilities from SAB-064 — testing the
claim that they are *three separate bugs* rather than one conflated chain.

- **Vulnerable:** UniFi OS Server **5.0.6** (built 2025-11-20)
- **Fixed:** UniFi OS Server **5.0.8** / unifi-core 5.0.153 (built 2026-05-14)

---

## 0. Acquiring the images

UniFi OS Server (the self-hosted Linux build) is distributed as a single self-extracting
installer per platform. Links are obtained from the official releases/download page
(right-click the download → *copy link address*); the files resolve from `fw-download.ubnt.com`.

**Official sources**
- Releases / download portal: <https://ui.com/download/releases/network-server>
- Self-hosting docs (how to fetch/install): <https://help.ui.com/hc/en-us/articles/34210126298775-Self-Hosting-UniFi>

**The two builds used (reconstructed canonical URLs — verify against the portal + hash before trusting):**
```
# 5.0.6 (vulnerable)
https://fw-download.ubnt.com/data/unifi-os-server/1856-linux-x64-5.0.6-33f4990f-6c68-4e72-9d9c-477496c22450.6-x64

# 5.0.8 (fixed)
https://fw-download.ubnt.com/data/unifi-os-server/c2e4-linux-x64-5.0.8-bcb62759-753a-4be2-8546-a6e0de63e59a.8-x64
```
> ⚠️ **Honesty note:** in this exercise the files were supplied locally. The URLs above are
> reconstructed from the filenames plus Ubiquiti's documented `fw-download.ubnt.com/data/unifi-os-server/<file>`
> pattern. Always pull the authoritative link from the releases page and record a SHA-256 of
> what you download. Older point releases rotate off the front page — keep your own archive.

**Record provenance immediately:**
```bash
ls -l *linux-x64*           # 5.0.6 ≈ 841,709,186 B ; 5.0.8 ≈ 857,655,889 B
shasum -a 256 *linux-x64*   # pin hashes in your notes
```

**Background references (read these to scope the work):**
- Vendor advisory SAB-064: <https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b>
- Bishop Fox chain writeup: <https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-34908> · <https://nvd.nist.gov/vuln/detail/CVE-2026-34909> · <https://nvd.nist.gov/vuln/detail/CVE-2026-34910>

---

## 1. Identify what the files actually are

Never assume. The first move is fingerprinting.

```bash
file 1856-linux-x64-5.0.6-*        # => ELF 64-bit LSB pie executable, x86-64, stripped
xxd -l 64 1856-linux-x64-5.0.6-*   # => 7f 45 4c 46  (ELF magic)
```

These are **not** firmware images — they are **x86-64 ELF executables ~840 MB each**. That size
on an ELF is a tell that a payload is appended. Scan for it:

```bash
binwalk 1856-linux-x64-5.0.6-*
# => ELF header at 0x0 ... then:
#    0x25CFF0   ZIP archive, file count: 7, total size: 839231122 bytes
```

So the format is **a small ELF self-extractor with a ZIP blob appended at offset 0x25CFF0.**
`unzip` reads the central directory at EOF, so it lists the payload directly despite the ELF prefix:

```bash
unzip -l 1856-linux-x64-5.0.6-*
#   discovery            3.7M   (byte-identical between versions)
#   image.tar           838M   <-- the prize
#   pasta, purge        small
#   uosserver           2.5M
#   uosserver-service   6.0M
#   updater-service     1.8M
```

**Lesson:** a 5-minute `file` + `binwalk` + `unzip -l` reframed the entire job — from
"firmware RE" to "diff a container image + a handful of native services."

---

## 2. Unpack the payload (without blowing up the disk)

Disk was tight (~12 GB free), so extract in stages and stream where possible.

```bash
mkdir -p diff/old diff/new
for f in discovery pasta purge uosserver uosserver-service updater-service; do
  unzip -o -q OLD.x64 "$f" -d diff/old
  unzip -o -q NEW.x64 "$f" -d diff/new
done
file diff/old/*        # => all ELF, stripped. Strings reveal: Rust (rustc/.../*.rs paths)
```

`image.tar` is the bulk. **List it without writing 838 MB to disk** by streaming the outer ZIP
member straight into `tar`:

```bash
unzip -p OLD.x64 image.tar | tar tv | head        # it's an OCI image:
#   blobs/sha256/<...>  index.json  manifest.json  oci-layout
unzip -p OLD.x64 image.tar | tar -xO manifest.json
#   RepoTags: ["uosserver:0.0.54"], 10 layers, entrypoint /root/uos-entrypoint.sh
```

Identify the **main rootfs layer** (the largest blob) per build:
```bash
unzip -p NEW.x64 image.tar | tar tv | awk '{print $5,$NF}' | sort -rn | head
#   old main layer: blobs/sha256/f7604bf...   (807 MB)
#   new main layer: blobs/sha256/66b76b9a...  (824 MB)
```

Decompress just that layer to disk once per side, then extract files on demand:
```bash
unzip -p OLD.x64 image.tar | tar -xO blobs/sha256/f7604bf... | gzip -d > /tmp/old_layer.tar
unzip -p NEW.x64 image.tar | tar -xO blobs/sha256/66b76b9a... | gzip -d > /tmp/new_layer.tar
tar -xf /tmp/old_layer.tar -C /tmp/oldx etc/nginx etc/sudoers.d usr/lib/...   # targeted
```

The rootfs is the classic UniFi Network stack: **Java (Temurin) + Node + nginx + postgres +
mongo + a set of Go service binaries in `usr/sbin/*-app`.**

---

## 3. Filesystem-level diff first (cheap, high signal)

Before any disassembler, diff the trees. Build name+size manifests by streaming each layer:

```bash
unzip -p OLD.x64 image.tar | tar -xO <oldlayer> | tar tzv \
  | awk '{sz=$5;$1=$2=$3=$4=$5=$6=$7=$8="";sub(/^ +/,"");print $0"\t"sz}' | sort > old.manifest
# same for new -> new.manifest
comm -13 <(cut -f1 old.manifest|sort) <(cut -f1 new.manifest|sort)   # added
join -t$'\t' -j1 old.manifest new.manifest | awk -F'\t' '$2!=$3'     # size-changed
```

**Critical lesson — filter the base-image noise.** The container OS was rebuilt between releases
(OpenJDK 17 → Temurin 25, X11 added, CA certs, postgres). That churns ~5,600 files. Exclude
`jvm|X11|ssl/certs|usr/share|locale|man|postgresql|python3|fonts|...` and focus on
`usr/lib/unifi*`, `etc/nginx`, `etc/sudoers.d`, and the app binaries.

---

## 4. The readable wins (config/text files)

Two patched files were plain text and immediately informative.

**`etc/sudoers.d/unifi-identity-update`** — the `ucs-update` NOPASSWD allowlist dropped
`/usr/bin/dpkg` and `/bin/chmod` (classic privesc primitives). → privilege-escalation hardening.

**`etc/nginx/nginx.conf.disabled`** — a new `map $uri $target_runnable_normalized` compared
against `map $request_uri $target_runnable`, with the vendor's own comment:
*"detect path traversal attacks where the raw and normalized service names diverge."* This is the
core of **CVE-2026-34908** (and, on the `/app-assets/` route, **34909**). Regex also widened
`[a-z]+` → `[a-z][-a-z]*` (hyphenated service names).

**Lesson:** always diff configs, sudoers, systemd units, and nginx/webapp XML first — fixes there
are self-documenting.

---

## 5. Native-binary triage — the toolchain-hash rule

The interesting services are compiled. Determine language and, crucially, whether the **compiler
changed** between builds (this decides whether structural diffing will work at all):

```bash
strings BIN | grep -oE 'rustc/[0-9a-f]{40}' | head -1   # Rust commit hash
strings BIN | grep -oE 'go1\.[0-9]+(\.[0-9]+)?' | sort -u # Go toolchain
```

Findings:
| Binary | Lang | Toolchain old→new | Diffable? |
|---|---|---|---|
| `uosserver`, `updater-service` | Rust | rustc **changed** (ed61e7d→598076) | ❌ full recompile → ~60–66 % noise |
| `uos` | Rust | rustc **same** | ⚠️ still 54 % noise at 11k funcs |
| `usr/sbin/*-app` | **Go** | toolchain **same** both builds | ✅ clean (and pclntab keeps names) |

**Lesson #1:** if the toolchain hash changed, byte/structural function diffing is hopeless —
every function shifts. **Lesson #2:** Rust strips to nameless `fcn.*`; Go keeps function names in
`.gopclntab`. Go is where you get leverage.

---

## 6. Function diffing with rizin (and learning its limits)

```bash
brew install rizin
rz-diff -t functions -B -j diff/old/uosserver diff/new/uosserver > out.json   # -B runs analysis
```

For the recompiled Rust binaries this returned ~60 % of functions "changed" = pure noise. **Dead
end, but a useful negative**: it proved the Rust services weren't cleanly diffable and pushed the
search elsewhere. (Also: `rz-bin -z` string diffs are unreliable — Rust/Go merge adjacent string
literals into giant blobs whose offsets shift, producing false add/remove. Use exact-token counts
`grep -Fc`, not blob diffs.)

---

## 7. The OSINT pivot

Hours into diffing Rust, a search for the public writeup changed the trajectory:

- Bishop Fox: *"the vulnerable service accepts user-supplied package names and passes them through
  **`fmt.Sprintf`** into a command string executed via **`sh -c`**."*

`fmt.Sprintf` → **Go**, not Rust. That single sentence redirected CVE-34910 from the Rust binaries
to the **Go** `unifi-identity-update-app`. **Lesson:** a quick OSINT pass can save hours of
misdirected RE — do it early.

---

## 8. Go-specific techniques — parsing `.gopclntab`

Go binaries (even "stripped") carry a function table. Parsing it directly is faster and cleaner
than full disassembly and survives address shifts.

**(a) Function-name list** (added/removed functions) — read the `funcnametab`:
```python
# locate pclntab magic (go1.20 = \xf1\xff\xff\xff), read header offsets,
# slice funcnametab [funcnameOffset : cuOffset], split on NUL -> all function names
```

**(b) Modified-function detection by SIZE** (robust to address shifts) — read the `functab`,
compute each function's size as `entry[i+1]-entry[i]`, join old↔new by name, flag size changes.
A function whose logic changed almost always changes size; address shifts do not.

**(c) Resolve a function's CALL targets** — disassemble its byte range, decode `e8/e9 rel32`,
map target → name via the functab. This let us ask precise questions like *"which functions newly
call `filepath.Clean`/`IsLocal`?"* without a full analysis pass.

These three primitives (≈60 lines of Python over the ELF) did most of the heavy lifting on the Go
services. **Lesson:** for Go, the metadata is the map — parse it.

---

## 9. Decompilation with Ghidra (headless) — the 34910 proof

To show the actual before/after, decompile the Go binary in both builds.

```bash
brew install --cask ghidra            # or: brew install ghidra
export JAVA_HOME=/opt/homebrew/opt/openjdk@21   # Ghidra 12 needs JDK 21+
HL=$(brew --prefix)/Cellar/ghidra/*/libexec/support/analyzeHeadless

# Java post-script (Ghidra 12 dropped Jython; .py needs PyGhidra, so use .java)
$HL /tmp/ghproj idu_new -import /tmp/news/usr/sbin/unifi-identity-update-app \
   -scriptPath /tmp/ghscripts -postScript dumpfuncs.java -deleteProject
```
`dumpfuncs.java` opens a `DecompInterface`, iterates `getFunctionManager().getFunctions(true)`,
matches target names, and prints `getDecompiledFunction().getC()`.

Result — `internal/pkg/utils.GetPackageVersion` (`uos_pkg.go`):
```
OLD: fmt.Sprintf("sudo dpkg -s %v 2>/dev/null | grep ^Version | awk '{print $2}'", name)
     -> exec.Command("/bin/sh", "-c", <that>)            // command injection
NEW: assertValidName(name)                               // validate first
     -> exec.Command("dpkg-query","-W","-f","${Version}", name)   // arg vector, no shell
```
Plus a new no-shell helper `utils.ExecArgsCombinedOutput`, applied systemically. **CVE-2026-34910
confirmed at decompiled-source level.**

**Gotchas learned:** Ghidra 12 needs JDK 21+; its `.py` scripting requires PyGhidra — write
post-scripts in **Java** to avoid that; the Golang analyzer recovers names/types automatically.

---

## 10. Resolving the stubborn one — CVE-2026-34909

34909 is a *file-read* traversal ("read files on the underlying system"). An exhaustive negative
search ruled out every diffable backend:
- Go services: no new `filepath.Clean/IsLocal/Rel/Abs` call in any common function; no new
  path-validator; only feature churn.
- nginx tree: only the normalization maps. Rust `uosserver`: doesn't serve files at all.
  Rust `uos-agent`: backup manifest-path validation byte-identical. Java `ace.jar`: **obfuscated
  and re-obfuscated** (single-letter classes) + repackaged 1.8 MB→115 MB fat jar → undiffable.

The answer was in the nginx fix all along: its maps cover **two route families** —
```
~^/proxy/([a-z][-a-z]*)/(.*)$        -> backend APIs        => 34908 (access bypass)
~^/app-assets/([a-z][-a-z]*)/(.*)$   -> static files (disk) => 34909 (arbitrary file read)
```
34908 and 34909 are **two distinct sinks** (API routing vs filesystem read; two CWEs; two
reporters) sharing **one root cause** (raw-vs-normalized URI) and **one fix**. That shared
chokepoint is exactly why a black-box checker conflates them — and why the vendor still assigned
two CVEs. **Lesson:** a thorough *negative* result, combined with the structure of the fix, can be
the finding.

---

## Tooling reference

| Tool | Use | URL |
|---|---|---|
| `file`, `binwalk` | format ID, find appended payload | <https://github.com/ReFirmLabs/binwalk> |
| `unzip`, `tar`, `gzip` | unpack ZIP/OCI/layers (streaming) | — |
| `diffoscope` (optional) | recursive tree/archive diff | <https://diffoscope.org/> |
| rizin (`rz-diff`, `rz-bin`) | function/string diff, ELF info | <https://rizin.re/> |
| Ghidra 12 (`analyzeHeadless`) | decompilation (Go analyzer) | <https://ghidra-sre.org/> |
| openjdk@21 | runtime for Ghidra 12 | <https://openjdk.org/> |
| Python 3 | `.gopclntab` parsing (custom ~60 LOC) | — |
| `nm`, `objdump` | symbol/section checks | — |

---

## Lessons learned (the transferable bits)

1. **Fingerprint before you commit.** `file`/`binwalk`/`unzip -l` turned "840 MB firmware" into a
   known shape in minutes.
2. **Diff cheap→expensive:** configs/text → file manifests → strings → function structure →
   decompilation. Most fixes surface long before the disassembler.
3. **Filter base-image noise** or it drowns the signal (here, a JRE/OS rebuild = thousands of files).
4. **The toolchain hash decides diffability.** Same compiler → structural diff works; changed
   compiler → only semantic anchors (strings, names, decompiled logic) survive.
5. **Language dictates technique:** Go = parse pclntab (names + sizes + call graph); Rust stripped
   = string/decompile anchors; obfuscated Java = often undiffable across builds.
6. **OSINT early.** One sentence in a public writeup redirected the whole 34910 hunt.
7. **A rigorous negative result is a result.** "No separate file-read fix exists, and the fix's
   structure shows why" *is* the 34909 conclusion.
8. **Stay honest about provenance.** Mark what's decompiled ground-truth vs reconstructed mechanism;
   it keeps the analysis trustworthy.

---

## Remediation (the point of all this)

Upgrade to **UniFi OS Server 5.0.8 / unifi-core 5.0.153** (UDM/UDR firmware 5.1.12+, Express 4.0.14,
UNAS 5.1.10). The detection material in `unifi_cve_2026.rules` / `unifi_cve_2026_dfir.html` is for
visibility and virtual-patching, not a substitute for the update.

---

*Companion artifacts in this folder: `progress.md` (findings log), `unifi_cve_2026.rules` (IDS
signatures), `unifi_cve_2026_dfir.html` (teaching page).*
