# Probes

This document describes each of the **seventeen** probes in detail: the
misconfiguration it looks for, the evidence it adds, the weighting
strategy, and the false-positive mitigations applied.

| # | Probe | What it hunts |
|---|-------|---------------|
| 1 | `suid` | SUID / SGID binaries that can spawn a shell |
| 2 | `writable_path` | World-writable entries in `$PATH` |
| 3 | `capabilities` | File / process Linux capabilities |
| 4 | `writable_etc` | Writable `/etc` authentication files |
| 5 | `docker_socket` | Exposed Docker control socket |
| 6 | `polkit` | polkit / pkexec misconfigurations (PwnKit) |
| 7 | `world_writable` | World-writable sensitive files + missing sticky bits |
| 8 | `kernel_vuln` | Kernel-version CVE matching |
| 9 | `cron` | World-writable / wildcard crontabs |
| 10 | `sudoers` | NOPASSWD / over-broad sudoers rules |
| 11 | `ssh_keys` | World-readable private SSH keys |
| 12 | `groups` | Privileged group membership (docker, lxd, disk, …) |
| 13 | `service` | World-writable systemd unit files |
| 14 | `kernel_hardening` | Weak sysctl hardening values |
| 15 | `process` | Suspicious running processes |
| 16 | `nfs` | `no_root_squash` NFS exports |
| 17 | `ld_preload` | World-writable `ld.so.conf` / global `LD_*` |

> **Implementation note.** Probes must never call glibc NSS functions
> (`getpwuid`, `getgrnam`, …) directly: in a *statically linked*
> binary those lookups segfault because `libnss_*.so` is not embedded.
> The `groups` and `sudoers` probes therefore parse `/etc/passwd` and
> `/etc/group` directly through the `zp_username_for_uid`,
> `zp_primary_gid_for_uid`, and `zp_user_in_group` helpers in
> `src/util.c`.

---

## 1. `suid` - SUID / SGID binary scanner

### What it looks for

Every regular file in the scan root (or the entire filesystem if
no `--root` is given) with the SUID or SGID bit set in its mode.

### Evidence weighting

| Condition                                | Weight | Severity |
|------------------------------------------|--------|----------|
| Root-owned AND dangerous basename        | 0.95   | CRITICAL |
| Dangerous basename, non-root owner       | 0.85   | HIGH     |
| Root-owned, non-dangerous                | 0.50   | MEDIUM   |
| Non-root, non-dangerous                  | 0.30   | LOW      |

The "dangerous basename" list is drawn from the GTFOBins catalog:
binaries that can be coerced into spawning a shell or otherwise
escaping the caller's permission set.

### Skipped directories

The walker deliberately skips `proc`, `sys`, `dev`, `snap`, `run`,
and `lost+found`.  These either re-enter the filesystem
(`/proc/<pid>/root`), contain transient content, or contain a flood
of legitimately-SUID files that drown the signal.

### False-positive mitigations

- Distribution-shipped SUID binaries (`/usr/bin/sudo`,
  `/usr/bin/passwd`, `/usr/bin/mount`) are present on every Linux
  box and are not vulnerable on their own.  They are reported at
  MEDIUM because the *set* of SUID binaries is itself an audit
  artefact.
- Snap- and flatpak-shipped SUIDs are skipped by the directory
  filter.
- The walker caps its depth at eight to bound scan time.

---

## 2. `writable_path` - World-writable PATH entries

### What it looks for

Each entry in the `$PATH` environment variable is `stat`'d.  Any
directory that is world-writable becomes evidence.  A bare "."
entry is escalated to CRITICAL.

### Evidence weighting

| Condition                                | Weight | Severity |
|------------------------------------------|--------|----------|
| Current directory (`.`) in PATH          | 0.98   | CRITICAL |
| Writable system PATH dir (e.g. /usr/bin) | 0.90   | HIGH     |
| Writable non-system PATH dir             | 0.75   | HIGH     |

### False-positive mitigations

- Only directories that exist AND are world-writable are reported.
- Missing directories are silently skipped (they cause no actual
  exposure).
- A directory that is `chmod o-w` between two runs will *not* be
  re-reported; the engine produces a fresh chain each scan.

---

## 3. `capabilities` - File and process Linux capabilities

### What it looks for

`getcap`-style xattr scan of every executable under the scan root,
plus a read of `/proc/self/status`'s `CapBnd` (bounding) line.

### Critical capability set

`cap_sys_admin`, `cap_dac_override`, `cap_setuid`, `cap_setgid`,
`cap_sys_ptrace`, `cap_net_raw`, `cap_dac_read_search`,
`cap_sys_module`, `cap_sys_rawio`, `cap_linux_immutable`,
`cap_sys_boot`, `cap_net_admin`.

### Evidence weighting

- Critical-cap file -> 0.9 weight, HIGH severity.
- Non-critical-cap file -> 0.5 weight, MEDIUM severity.
- Process bounding set retains critical caps -> 0.6 weight,
  MEDIUM severity.

### False-positive mitigations

- The xattr name is exactly `security.capability`.  Wrong xattrs
  are not interpreted.
- Capabilities on the probe binary itself are not added twice.

---

## 4. `writable_etc` - Writable /etc authentication files

### What it looks for

`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/group`,
`/etc/gshadow`, plus the contents of `/etc/sudoers.d/`.

### Evidence weighting

- World-writable authentication file -> 0.99 weight, CRITICAL.
- World-writable drop-in under `/etc/sudoers.d/` -> 0.95 weight,
  CRITICAL.

### False-positive mitigations

- Symlinks are not dereferenced; an attacker who controls a
  symlink target can hide behind a non-world-writable symlink, but
  the lstat-based mode check still catches the world-writable
  final target via the parent walk.

---

## 5. `docker_socket` - Exposed Docker control socket

### What it looks for

`/var/run/docker.sock`, `/run/docker.sock`,
`/run/docker/docker.sock`.

### Evidence weighting

| Condition                                | Weight | Severity |
|------------------------------------------|--------|----------|
| Socket is reachable AND pingable         | 0.99   | CRITICAL |
| Socket is world-writable                 | 0.85   | HIGH     |
| Socket present but not accessible        | 0.40   | LOW      |

### Active probing

When a socket is present, the probe attempts a non-destructive
`GET /_ping HTTP/1.0` over the socket.  This is the standard
Docker daemon health-check.  A positive response confirms that the
current user can drive `docker` operations.

---

## 6. `polkit` - polkit / pkexec misconfiguration

### What it looks for

- The polkit package's version file (under `/usr/share/polkit-1/`
  or `/etc/polkit-1/`).
- The `pkexec` binary's SUID bit and version match against known
  CVEs.
- World-writable polkit rules directories.

### CVE coverage

- **CVE-2021-4034 (PwnKit)** - SUID `pkexec` with polkit before
  0.122 is CRITICAL (weight 0.99).  polkit 0.120.x or 0.121.0-0.121.3
  with SUID `pkexec` is HIGH (weight 0.70).

The probe inspects the version file and mode bits only; it does not
attempt to exploit `pkexec`.  World-writable polkit rules
directories are flagged independently of the package version (weight
0.95, CRITICAL).

---

## 7. `world_writable` - World-writable sensitive files

### What it looks for

A bounded-depth walk of `/etc`, `/root`, `/home`, `/opt`, `/var`,
`/usr/local`, `/usr/local/etc`, and `/srv`.  For each regular
file with the world-write bit set, an evidence link is added.

### Evidence weighting

| Location           | Weight | Severity |
|--------------------|--------|----------|
| Under `/etc`       | 0.95   | CRITICAL |
| Under `/root`      | 0.85   | HIGH     |
| Under `/opt` or `/usr/local` | 0.70 | MEDIUM |
| Other              | 0.50   | LOW      |

### Sticky-bit sub-probe

`/tmp`, `/dev/shm`, `/var/tmp`, `/var/spool`, and `/var/lock` are
checked for the sticky bit (`S_ISVTX`).  A missing sticky bit is
HIGH severity with weight 0.85.

---

## 8. `kernel_vuln` - Kernel version CVE matcher

### What it looks for

`/proc/version` is read; the first three numeric components are
parsed as `major.minor.patch`.  Each entry in the built-in CVE
table is matched if the host kernel falls within the entry's range.

### Built-in CVE table

| CVE              | Name                                | Weight | Severity  |
|------------------|-------------------------------------|--------|-----------|
| CVE-2016-5195    | Dirty COW (mm/gup.c PTRACE race)    | 0.95   | CRITICAL  |
| CVE-2022-0847    | Dirty Pipe (pipe buffer flag leak)  | 0.95   | CRITICAL  |
| CVE-2022-2588    | cls_route UAF                       | 0.75   | HIGH      |
| CVE-2023-0386    | OverlayFS FUSE capability leak      | 0.70   | HIGH      |
| CVE-2023-32233   | Netfilter UAF (GameOver(lay))       | 0.70   | HIGH      |
| CVE-2023-2640    | OverlayFS privilege escalation      | 0.70   | HIGH      |
| CVE-2024-1086    | nf_tables UAF                       | 0.60   | HIGH      |

### Conservative matching

The table is deliberately conservative.  CVEs without a public,
weaponised, high-reliability exploit are not added.  Backported
distro kernels are NOT modelled - matching is done against the
upstream version string only; an admin should correlate against
their distro's security feed.

### Clean verdict

If the kernel matches no entry, the chain is *explicitly* given a
REJECT link so the engine can be certain to adopt REJECT.

---

## 9. `cron` - Crontab / cron.d abuse

### What it looks for

`/etc/crontab`, every file under `/etc/cron.d/`, `/etc/cron.daily/`,
`/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`,
`/etc/anacrontab`, and the spool directories `/var/spool/cron/` and
`/var/spool/cron/crontabs/`.  World-writable files, cron symlinks
that resolve to world-writable targets, and wildcard-injection
candidates are flagged.

### Evidence weighting

| Condition                              | Weight | Severity |
|----------------------------------------|--------|----------|
| World-writable crontab / cron file     | 0.99   | CRITICAL |
| Cron symlink resolves to world-writable | 0.95  | CRITICAL |
| Wildcard-injection candidate           | 0.70   | HIGH     |

A wildcard-injection candidate is a crontab line containing `*`
together with a shell builtin/utility that expands arguments
(`tar`, `rsync`, `zip`, `cp `, `mv `, `chown`, `chmod`) — the
classic backup-job exploit.

### False-positive mitigations

- The probe reads the file mode, not the directory mode, so a
  writable *parent* that contains a non-writable crontab is not
  over-reported.

---

## 10. `sudoers` - Sudoers misconfiguration

### What it looks for

`/etc/sudoers` and every drop-in under `/etc/sudoers.d/`.  Rules
granting `NOPASSWD` or `ALL` to the current user (or to a group
the user belongs to) are flagged.

### Evidence weighting

| Condition                          | Weight | Severity |
|------------------------------------|--------|----------|
| `NOPASSWD` + `ALL` for current user | 0.95  | CRITICAL |
| `ALL` (password) for current user   | 0.60   | HIGH     |

### Implementation note

Membership checks use `zp_user_in_group` (direct `/etc/group`
parse), never `getgrnam`, so the probe is safe under static
linking.

---

## 11. `ssh_keys` - Private key exposure

### What it looks for

`/root/.ssh/` and `/home/*/.ssh/`.  Any file whose name matches a
private-key pattern (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`,
`id_xmss`, `identity`, `key`, `private_key`, plus names containing
`_key` or ending `.pem`) that is world- or group-readable is
flagged.

### Evidence weighting

| Condition                          | Weight | Severity |
|------------------------------------|--------|----------|
| World-writable private key         | 0.95   | CRITICAL |
| Group- or world-readable (not ww)  | 0.60   | HIGH     |

### False-positive mitigations

- `authorized_keys` and `known_hosts` never match the key-name
  patterns, so they are not reported.
- The key pattern match is name-based, not content based, to avoid
  reading key material into memory.

---

## 12. `groups` - Privileged group membership

### What it looks for

Whether the current user is a member of any privilege-granting
group: `docker`, `lxd`, `disk`, `shadow`, `root`, `sudo`/`wheel`,
`kmem`, `mem`, `adm`, and several low-risk groups (`video`,
`netdev`, `input`, `ssl-cert`).

### Evidence weighting

| Group     | Severity  | Weight |
|-----------|-----------|--------|
| docker    | CRITICAL  | 0.95   |
| lxd       | CRITICAL  | 0.95   |
| disk      | CRITICAL  | 0.90   |
| root      | CRITICAL  | 0.99   |
| kmem/mem  | HIGH      | 0.90   |
| shadow    | HIGH      | 0.80   |
| sudo/wheel| HIGH      | 0.85   |
| adm       | MEDIUM    | 0.50   |

### Implementation note

Membership is resolved by parsing `/etc/passwd` and `/etc/group`
directly (`zp_username_for_uid`, `zp_primary_gid_for_uid`,
`zp_user_in_group`).  This avoids the glibc NSS crash that occurs
in statically linked binaries.

---

## 13. `service` - Systemd/SysV unit abuse

### What it looks for

**Systemd:** Units under `/etc/systemd/system/`, `/lib/systemd/system/`,
and `/usr/lib/systemd/system/`.  Any `.service` file that is
world-writable is flagged (an attacker who can write a unit can
obtain the service's privileges on next start/reload).  A root-owned
unit whose `ExecStart=` binary is world-writable is also flagged.

**SysV init.d:** Scripts under `/etc/init.d/` and `/etc/rc.d/`.
World-writable init scripts are flagged (an attacker who can modify
a script executed as root gains root on next service restart).

### Evidence weighting

| Condition                              | Weight | Severity |
|----------------------------------------|--------|----------|
| World-writable unit file               | 0.99   | CRITICAL |
| Root service w/ world-writable ExecStart | 0.99 | CRITICAL |
| World-writable SysV init script        | 0.99   | CRITICAL |

### False-positive mitigations

- Vendor-shipped units are usually root-owned and non-writable;
  only genuinely world-writable files escalate.
- Only `*.service` files are scanned under systemd directories;
  vendor scripts in `/usr/share/` are not part of the SysV scan
  roots.

---

## 14. `kernel_hardening` - sysctl hardening checks

### What it looks for

Ten sysctl values are read from `/proc/sys`; each value below its
required threshold adds an evidence link:

| sysctl                                   | Required | Weight | Severity |
|------------------------------------------|----------|--------|----------|
| `kernel.randomize_va_space`              | `2`      | 0.85   | HIGH     |
| `kernel.yama.ptrace_scope`               | `1`      | 0.70   | MEDIUM   |
| `kernel.dmesg_restrict`                  | `1`      | 0.70   | MEDIUM   |
| `kernel.kptr_restrict`                   | `2`      | 0.60   | MEDIUM   |
| `kernel.unprivileged_bpf_disabled`       | `1`      | 0.85   | HIGH     |
| `kernel.perf_event_paranoid`             | `3`      | 0.50   | LOW      |
| `kernel.kexec_load_disabled`             | `1`      | 0.60   | MEDIUM   |
| `fs.protected_hardlinks`                 | `1`      | 0.70   | MEDIUM   |
| `fs.protected_symlinks`                  | `1`      | 0.70   | MEDIUM   |
| `fs.suid_dumpable`                       | `0`      | 0.70   | MEDIUM   |

A fully hardened host gets a REJECT (CLEAN) link.

---

## 15. `process` - Suspicious running processes

### What it looks for

`/proc` is scanned for root-owned processes whose executable is
world-writable or whose binary has been deleted while running.  This
is a PID-scoped probe: it inspects live processes, not the filesystem.

### Evidence weighting

| Condition                             | Weight | Severity |
|---------------------------------------|--------|----------|
| Root process running world-writable exe | 0.95 | CRITICAL |
| Root process running deleted binary   | 0.70   | MEDIUM   |

### False-positive mitigations

- Only the executable path (`/proc/<pid>/exe`) and the `Uid` field
  of `/proc/<pid>/status` are read; no attach, no `ptrace`.

---

## 16. `nfs` - Insecure NFS exports

### What it looks for

`/etc/exports` is parsed for exports that are world-exported (`*`)
or contain `no_root_squash` or `insecure`.  A world-exported
`no_root_squash` mount lets a remote root client act as local root
on the export.

The parser splits exports on `(` to handle the standard
`host(options)` format, supporting multiple hosts per line and
complex option strings.

### Evidence weighting

| Condition                          | Weight | Severity |
|------------------------------------|--------|----------|
| World-exported `no_root_squash`    | 0.99   | CRITICAL |
| Other world / insecure / no_root_squash | 0.60 | HIGH  |

### False-positive mitigations

- The probe reports the parsed misconfiguration even if `nfsd` is
  not currently running; a live export is a stronger signal but
  the static config is the audit artefact.
- The parser handles standard `/etc/exports` format with
  `host(options)` syntax and ignores comment lines.

---

## 17. `ld_preload` - Dynamic-linker abuse

### What it looks for

`/etc/ld.so.conf` (or the `/etc/ld.so.conf.d/` directory) and every
file under `/etc/ld.so.conf.d/`.  Any world-writable entry is
flagged: an attacker who controls a library path used by the dynamic
linker owns every newly started process.  A global `LD_PRELOAD` or
`LD_LIBRARY_PATH` set in `/etc/environment` is also flagged.

### Evidence weighting

| Condition                             | Weight | Severity |
|---------------------------------------|--------|----------|
| World-writable `ld.so.conf` / `.conf.d` file | 0.99 | CRITICAL |
| Global `LD_PRELOAD`/`LD_LIBRARY_PATH` in `/etc/environment` | 0.70 | HIGH |

### False-positive mitigations

- The probe checks file mode, not directory mode.

---

## Adding a new probe

A probe is a function with the signature
`int zp_probe_*(struct zp_evidence_chain *, const char *root,
struct audit_ctx *)`.  To add one:

1. Implement it in `src/probes/<name>.c`.
2. Declare it in `include/probes.h` and register it in the probe
   table in `src/probe_runner.c`.
3. Add a `Makefile` object rule (already globbed) - no change
   needed if you follow the `src/probes/*.c` convention.
4. Add unit tests under `tests/` and register them in
   `tests/test_cases.inc`.

Probes must be pure readers.  They must never modify the host,
never execute attacker-controlled content, and never call NSS
functions directly (use the `/etc/passwd` / `/etc/group` helpers
in `src/util.c`).
