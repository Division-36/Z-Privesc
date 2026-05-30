# Release signing

All Z-Privesc release tarballs are signed with
[minisign](https://jedisct1.github.io/minisign/).  This document
explains how to verify a release.

## Verifying a release

```sh
# 1. Download the tarball, signature, and public key.
curl -O https://github.com/Division-36/Z-Privesc/releases/download/v1.0.0/z_privesc-1.0.0-linux-x86_64.tar.gz
curl -O https://github.com/Division-36/Z-Privesc/releases/download/v1.0.0/z_privesc-1.0.0-linux-x86_64.tar.gz.minisig
curl -O https://github.com/Division-36/Z-Privesc/releases/download/v1.0.0/public.key

# 2. Verify.
minisign -Vm z_privesc-1.0.0-linux-x86_64.tar.gz \
         -p public.key
```

A successful verification prints `Signature and comment signature are
valid`.

## Public key

The release public key fingerprint is published in
[public.key](public.key) and on the GitHub release page.  The
private key is held only by the project lead; the key is rotated
only on suspected compromise, and a `SECURITY` advisory will be
issued if a rotation is required.

## Reproducing a build

The release pipeline is reproducible.  To rebuild a release locally:

```sh
git checkout v1.0.0
make clean
make static
make release
sha256sum dist/z_privesc-1.0.0-linux-x86_64.tar.gz
```

The SHA-256 of the produced tarball should match the value published
in the release notes.

## Reporting a signing issue

If a signature does not verify, **do not run the binary**.  Email
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com) with the
failing command output and the SHA-256 of the tarball you downloaded.
