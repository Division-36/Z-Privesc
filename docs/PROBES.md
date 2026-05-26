# Probes

This document describes each of the eight probes in detail: the
misconfiguration it looks for, the evidence it adds, the weighting
strategy, and the false-positive mitigations applied.

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
`tmp`, `var`, and `lost+found`.  These either re-enter the
filesystem (`/proc/<pid>/root`), contain transient content, or
contain a flood of legitimately-SUID files that drown the signal.

### False-positive mitigations

- Distribution-shipped SUID binaries (`/usr/bin/sudo`,
  `/usr/bin/passwd`, `/usr/bin/mount`) are present on every Linux
  box and are not vulnerable on their own.  They are reported at
  MEDIUM because the *set* of SUID binaries is itself an audit
  artefact.
- Snap- and flatpak-shipped SUIDs are skipped by the directory
  filter.
- The walker caps its depth at eight to bound scan time.

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

## 3. `capabilities` - File and process Linux capabilities

### What it looks for

`getcap`-style xattr scan of every executable under the scan root,
plus a read of `/proc/self/status`'s `CapBnd` (bounding) line.

### Critical capability set

`cap_sys_admin`, `cap_dac_override`, `cap_setuid`, `cap_setgid`,
`cap_sys_ptrace`, `cap_net_raw`, `cap_dac_read_search`,
`cap_sys_module`, `cap_sys_rawio`, `cap_linux_immutable`.

### Evidence weighting

- Critical-cap file -> 0.9 weight, HIGH severity.
- Non-critical-cap file -> 0.5 weight, MEDIUM severity.
- Process bounding set retains critical caps -> 0.6 weight,
  MEDIUM severity.

### False-positive mitigations

- The xattr name is exactly `security.capability`.  Wrong xattrs
  are not interpreted.
- Capabilities on the probe binary itself are not added twice.

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

## 6. `polkit` - polkit / pkexec misconfiguration

### What it looks for

- The polkit package's version file (under `/usr/share/polkit-1/`
  or `/etc/polkit-1/`).
- The `pkexec` binary's SUID bit and version match against known
  CVEs.
- World-writable polkit rules directories.

### CVE coverage

- **CVE-2021-4034 (PwnKit)** - any polkit < 0.120 with SUID
  `pkexec` is CRITICAL.
- **CVE-2021-3156 (Baron Samedit)** - sudo before 1.9.5p2; the
  probe is a *kernel* version check elsewhere, but the polkit
  probe notes the polkit version because operators update the two
  together.

### False-positive mitigations

- The probe does not attempt to exploit `pkexec`; it only inspects
  version and mode bits.
- World-writable polkit rules directories are flagged even if
  polkit is up to date - the directory misconfiguration is
  independent of the package version.

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

`/tmp`, `/dev/shm`, and `/var/tmp` are checked for the sticky bit
(`S_ISVTX`).  A missing sticky bit is HIGH severity with weight
0.85.

## 8. `kernel_vuln` - Kernel version CVE matcher

### What it looks for

`/proc/version` is read; the first three numeric components are
parsed as `major.minor.patch`.  Each entry in the built-in CVE
table is matched if the host kernel falls within the entry's range.

### Built-in CVE table (abridged)

| CVE              | Name                                | Severity  |
|------------------|-------------------------------------|-----------|
| CVE-2016-5195    | Dirty COW                           | CRITICAL  |
| CVE-2021-3156    | Baron Samedit (sudo)                | CRITICAL  |
| CVE-2021-4034    | PwnKit (polkit)                     | CRITICAL  |
| CVE-2022-0847    | Dirty Pipe                          | CRITICAL  |
| CVE-2022-2588    | cls_route UAF                       | HIGH      |
| CVE-2023-0386    | OverlayFS FUSE                      | HIGH      |
| CVE-2023-32233   | Netfilter GameOver(lay)             | HIGH      |
| CVE-2023-2640    | OverlayFS privilege escalation      | HIGH      |
| CVE-2023-4911    | Looney Tunables (glibc)             | CRITICAL  |
| CVE-2024-1086    | nf_tables UAF                       | HIGH      |

### Conservative matching

The table is deliberately conservative.  CVEs without a public,
weaponised, high-reliability exploit are not added.  Backported
distro kernels are NOT modelled - matching is done against the
upstream version string only; an admin should correlate against
their distro's security feed.

### Clean verdict

If the kernel matches no entry, the chain is *explicitly* given a
REJECT link so the engine can be certain to adopt REJECT.
