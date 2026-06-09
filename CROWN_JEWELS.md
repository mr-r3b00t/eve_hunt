# Crown-Jewel Analysis — Path-Traversal Targets on UniFi OS (CVE-2026-34909)

> **Authorized / defensive use.** This identifies the sensitive files on a UniFi OS console that a
> path-traversal *file read* (CVE-2026-34909, via `/app-assets/<svc>/..%2f…`) would target, so
> defenders can prioritise protection, monitoring, and post-incident rotation. Paths were derived
> from the extracted UniFi OS Server 5.0.8 rootfs.

## 1. Why this matters
CVE-2026-34909 gives an unauthenticated attacker an **arbitrary file read**. A file read is only as
dangerous as the file it returns. The advisory's phrase *"…manipulated to access and compromise an
underlying account"* is the key: the attacker reads a file that **is itself a credential or key**,
then simply **logs in** — no further exploit required. This document ranks those files.

**Origin legend**
- **[IMG]** ships in the firmware image — *static, identical on every device* (can't be rotated; segment instead).
- **[RT]** generated at first boot under the persistent data root — *unique per device, most damaging to leak*.
- **[INF]** standard UniFi location, exact path inferred from conventions/config (verify on your build).

The persistent secret root is **`/data/`** (external storage mirrors under `/srv/`). Services run as
unprivileged users (`unifi`, `unifi-core`, `ulp-go`, `uid`, `ucs-update`, `postgres`, `mongodb`).

---

## 2. Attacker target-priority (what gets grabbed first)
Ranked by *speed-to-compromise* — highest payoff, lowest effort first:

| # | Read this | Because |
|---|-----------|---------|
| 1 | `/etc/sudoers.d/*` | Free recon: tells the attacker exactly which `NOPASSWD` binaries to abuse next (this is how the 34910 privesc path was found). |
| 2 | `/data/unifi-core/config/unifi-core*.key` | Device + remote-access **TLS private keys** → impersonate/MITM the console, hijack remote access. |
| 3 | `/etc/shadow` | Offline-crack admin/root hashes → log in. |
| 4 | `/usr/lib/unifi/data/system.properties` + `keystore` | Network controller keystore password + DB settings. |
| 5 | `/data/*/ws/config.props` (uid, credential-server, ulp-go) | Runtime **DB field-encryption keys** + service secrets (`db.encrypted = true`). |
| 6 | Mongo / Postgres data files | Bulk dump: admin hashes, SSO/remote tokens, adopted-device keys, identities. |

---

## 3. Tiered crown-jewel inventory

### Tier 1 — Direct account / root takeover
| Path | Origin | Contains | Attacker gains |
|---|---|---|---|
| `/etc/shadow`, `/etc/gshadow` | IMG | OS password hashes | Crack → local login |
| `/etc/passwd` | IMG | Accounts/UIDs/shells | Recon + user enumeration |
| `/etc/sudoers`, `/etc/sudoers.d/{10_unifi,unifi-identity-update,ucs-agent,uid,ulp-go,unifi-core,unifi-credential-server,unifi-directory}` | IMG | Service-account `sudo` grants | **Privesc map** — which NOPASSWD binaries to abuse |
| `/etc/ssh/ssh_host_*_key` | RT | SSH host private keys | Impersonate/MITM the device over SSH |
| `/root/.ssh/authorized_keys`, `/root/.ssh/id_*`, `/home/*/.ssh/*` | RT/INF | Trusted/holder keys | Direct shell as that user |

### Tier 2 — Device & remote-access identity (impersonate the box)
| Path | Origin | Contains | Attacker gains |
|---|---|---|---|
| `/data/unifi-core/config/unifi-core.key` | RT | Gateway **TLS private key** | Decrypt/MITM the admin UI |
| `/data/unifi-core/config/unifi-core-direct.key` + `-direct.crt` | RT | **Remote/direct-connect** key | Hijack remote access to the device |
| `/data/unifi-core/config/` (whole dir) + cloud/remote-access tokens stored here | RT | Ubiquiti-account / remote tokens | Control the device *through the cloud* |
| `usr/share/unifi-core/app/config/lutron/key.pem`, `…/nca_ca.crt` | IMG | Integration private key / CA | MITM integrations; static key reuse across devices |
| `/etc/ssl/private/ssl-cert-snakeoil.key` | IMG | Default snakeoil key | Low value (default), but confirms read primitive |

### Tier 3 — UniFi Network application (the classic UniFi secrets)
| Path | Origin | Contains | Attacker gains |
|---|---|---|---|
| `/usr/lib/unifi/data/keystore` | RT/INF | Network controller TLS **keystore** | Server identity / TLS MITM |
| `/usr/lib/unifi/data/system.properties` | RT/INF | **Keystore password + DB config** | Unlock keystore; DB access details |
| UniFi Network Mongo DB (under the unifi data dir, persisted on `/data`) | RT/INF | Admin **hashes**, SSO/remote **tokens**, adopted-device keys | Controller + fleet takeover |

### Tier 4 — Identity / credential subsystem → "compromise an underlying account"
*(the literal target class named in the 34909 advisory)*
| Path | Origin | Contains | Attacker gains |
|---|---|---|---|
| `/data/unifi-credential-server/ws/config.props`, `/data/uid/ws/config.props` | RT | Runtime override files: **DB field-encryption key** (`db.encrypted = true`), service secrets | Decrypt stored credentials |
| `/data/{uid,unifi-credential-server,ucs-user-assets,ulp-go,unifi-directory}/` | RT | Per-service workspaces: session/JWT signing material, credential content | Forge sessions / read identities |
| `/data/unifi-access/` | RT/INF | Door/access credentials (PIN, NFC, face data) | Physical-access compromise |
| PostgreSQL cluster `/var/lib/postgresql/{14,16}/main/*` (DBs: `ulp-go,uid,unifi-credential-server,ucs-user-assets,unifi-directory`) | RT | Encrypted-at-rest identity data + the key (if Tier-4 file also read) | Full identity-DB dump |
| Postgres socket/`pg_hba.conf` (peer auth via `/var/run/postgresql`) | IMG/RT | Auth model | Confirms local DB access path |

### Tier 5 — Service-to-service trust, env & backups
| Path | Origin | Contains | Attacker gains |
|---|---|---|---|
| `/var/lib/unifi/env-overrides`, `/etc/default/unifi`, `/etc/default/unifi-core*` | RT/IMG | Env vars (may carry secrets/feature keys) | Config/secret leakage |
| Internal **`X-Source`** trust header secret (referenced in `uos-agent`) | RT/INF | Inter-service trust token | Forge "internal" requests |
| Backup material via `@ubnt/encrypted-archive` + backup key | RT/INF | Encrypted backup + its key | Decrypt exfiltrated backups (full config/secret history) |
| `/data/unifi-core/uidb.json` | RT | Device fingerprint DB | Low sensitivity (recon only) |

---

## 4. Defensive controls (map to the tiers)

**a) Stop the read at the sink (primary).** Upgrade to **5.0.8 / unifi-core 5.0.153** — the nginx
raw-vs-normalized check blocks the encoded traversal before it reaches the file route. Defense in
depth: any file-serving handler must confine reads to its asset root (`filepath.IsLocal` /
`HasPrefix(Clean(p), root)` / `os.Root`).

**b) Least privilege.** The web/asset-serving process (unprivileged service user) must not be able to
read Tier 1–4 paths. Verify file ownership/modes; the asset server should only read its own
`/usr/lib/<svc>` static dir and never `/etc/shadow`, other services' `/data/<svc>`, or the DB dirs.

**c) Read-auditing (auditd).** HTTP logs never show file *contents*, so watch the crown jewels at the
syscall level and alert on reads by an unexpected UID:
```
-w /etc/shadow                            -p r -k uos_crownjewel
-w /etc/sudoers                           -p r -k uos_crownjewel
-w /etc/sudoers.d                         -p r -k uos_crownjewel
-w /etc/ssh                               -p r -k uos_crownjewel
-w /data/unifi-core/config                -p r -k uos_crownjewel
-w /usr/lib/unifi/data/keystore           -p r -k uos_crownjewel
-w /usr/lib/unifi/data/system.properties  -p r -k uos_crownjewel
# then: alert when auid/uid is a web/service account, not an admin
```

**d) IDS — sensitive-target variant of the 34909 rule** (alarm hard, not just "traversal seen"):
```
alert http any any -> $HOME_NET any (
  msg:"CVE-2026-34909 UniFi OS traversal targeting CROWN-JEWEL file";
  flow:established,to_server; http.request_line; content:"/app-assets/"; nocase;
  pcre:"/(?:\.\.|%2e%2e|%252e).{0,80}(etc%2f(shadow|passwd|sudoers)|unifi-core[^ ]*\.key|keystore|system\.properties|ssh_host|id_rsa|config\.props)/i";
  classtype:web-application-attack; reference:cve,2026-34909; priority:1; sid:9000902; rev:1;)
```

**e) Assume-breach rotation playbook** (if any traversal of these is observed):
| If read… | Rotate / act |
|---|---|
| `unifi-core*.key`, keystore, snakeoil | Regenerate device certs/keystore; re-establish remote access |
| `/data/*/ws/config.props` (enc keys) | Rotate DB field-encryption keys; re-encrypt identity data |
| `/etc/shadow`, Mongo/PG hashes | Force reset of all admin/local passwords |
| `ssh_host_*`, authorized_keys | Regenerate host keys; purge unknown authorized_keys |
| cloud/remote tokens | Revoke remote access; re-link the Ubiquiti account |
| backup key / encrypted backups | Rotate backup key; treat all historical secrets as exposed |
| **[IMG] static keys** (lutron, nca_ca, snakeoil) | Cannot rotate per-device → network-segment, restrict, monitor |

---

## 5. Residual risk & notes
- **[RT] runtime keys are the real prize** — unique to the target; their leak = that device owned.
- **[IMG] static keys can't be rotated** by an operator; treat them as "known to attackers" and rely
  on segmentation + monitoring.
- **Encrypted-at-rest helps only if the key file isn't *also* readable.** Several Tier-4 secrets are
  encrypted with a key that lives in a sibling `config.props` — one traversal that grabs both defeats it.
- This list is the *target surface*; the **fix** remains the version upgrade. Everything here is for
  prioritising monitoring, least-privilege review, and IR rotation.

*Companion artifacts: `unifi_cve_2026_dfir.html` (teaching page), `unifi_cve_2026.rules` (IDS),
`REVERSE_ENGINEERING_WALKTHROUGH.md` (how these paths were found), `progress.md` (findings log).*
