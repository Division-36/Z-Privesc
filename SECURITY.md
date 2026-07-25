# Security policy

## Supported versions

| Version | Supported           |
|---------|---------------------|
| 1.0.x   | Yes                 |
| < 1.0   | No                  |

## Reporting a vulnerability

Please report security issues by email to
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com).  Do not
file a public GitHub issue for a suspected vulnerability.

When reporting, please include:

- A clear description of the issue and its impact.
- Reproduction steps, including commands and environment.
- The version of `z_privesc` and the operating system you reproduced
  it on.
- Whether you intend to disclose publicly and on what timeline.

We will acknowledge receipt within 72 hours and aim to ship a fix
within 14 days for critical issues.  We follow a 90-day coordinated
disclosure window.

## Out-of-scope issues

The following are not security issues and should be filed as ordinary
bug reports:

- Crash on a non-Linux platform.
- False-positive findings where the underlying system is correctly
  hardened.
- Cosmetic or stylistic complaints about the JSON output.

## Hardening of this tool

The build defaults to `-fstack-protector-strong`,
`-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now`, and
`-Wl,--as-needed`.  Releases are produced as stripped static binaries
via `make release`.  Releases are signed with minisign; see
[RELEASE-SIGNING.md](RELEASE-SIGNING.md) for the verification flow.
