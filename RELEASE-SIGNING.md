# Release signing

All Z-Privesc release tarballs are signed with
[minisign](https://jedisct1.github.io/minisign/).  This document
explains how to verify a release.

## Verifying a release

```sh
# 1. Download the tarball and signature.
curl -O https://github.com/Division-36/Z-Privesc/releases/download/v1.0.0/z_privesc-1.0.0-linux-x86_64.tar.gz
curl -O https://github.com/Division-36/Z-Privesc/releases/download/v1.0.0/z_privesc-1.0.0-linux-x86_64.tar.gz.minisig

# 2. Verify with the public key embedded in this repo.
minisign -Vm z_privesc-1.0.0-linux-x86_64.tar.gz \
         -p public.key
```

A successful verification prints `Signature and comment signature
verified`.

## Trust-on-first-use (TOFU) verification

You may also verify directly with the public key string:

```
minisign -Vm <file> -P RWSKrBQzqEjk6dndIFokFP3UHqr5mU/bCa6RnHAigPHzAb19FgRsg29i
```

## Public key

The release public key fingerprint is published in
[public.key](public.key).  The private key is held only by the project
lead; the key is rotated only on suspected compromise, and a `SECURITY`
advisory will be issued if a rotation is required.

## Reproducing a build

The release pipeline is reproducible.  To rebuild a release locally:

```sh
git checkout v1.0.0
make clean
make static
make release
sha256sum dist/z_privesc-1.0.0-linux-x86_64.tar.gz
```

The SHA-256 of the v1.0.0 release tarball is:

```
eedb6341881ae607449a695d2606dee53d625c55c63022642f2f093e191b5a44
```

## Reporting a signing issue

If a signature does not verify, **do not run the binary**.  Email
[zs.01117875692@gmail.com](mailto:zs.01117875692@gmail.com) with the
failing command output and the SHA-256 of the tarball you downloaded.
