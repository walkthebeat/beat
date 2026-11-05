# Third-party software in the sensor's image

This repository's own code is Apache-2.0 (`LICENSE`, `NOTICE`). The release's `beat-sensor.raw` is a squashfs of the
sensor's Nix closure, so it also contains the software below, unmodified unless noted, each under its own licence.

Versions are those of the image built from this commit's `flake.lock`; licences are as the pinned nixpkgs declares them
(`meta.license`). To list what an image holds: `unsquashfs -ls -d 2 beat-sensor.raw`.

## Corresponding source

Every package is built from source by a recipe in nixpkgs, at the revision in this repository's `flake.lock`. To get
the source of one: `nix build --no-link --print-out-paths github:NixOS/nixpkgs/REVISION#PACKAGE.src` (the patches
applied are in the same revision's recipe). If you cannot get a source you need that way, ask at support@walkthebeat.dev and we will send it to you.

## Native packages

| Package | Licence |
|---|---|
| acl, attr, keyutils | GPL-2.0-or-later |
| bash, coreutils | GPL-3.0-or-later |
| brotli, json-c, krb5, libpsl, nghttp2, nghttp3, ngtcp2 | MIT |
| bzip2 | bzip2-1.0.6 |
| curl | curl |
| elfutils | GPL-2.0-only, GPL-3.0-or-later, LGPL-3.0-or-later |
| gcc runtime libraries (libgcc, libstdc++) | GPL-3.0-or-later with the GCC Runtime Library Exception |
| glibc | LGPL-2.0-or-later |
| gmp | LGPL-3.0-only or GPL-2.0-only |
| libbpf-tools (from bcc; libbpf inside) | Apache-2.0; libbpf is LGPL-2.1 or BSD-2-Clause |
| libidn2 | LGPL-3.0-or-later or GPL-2.0-or-later (its tools GPL-3.0-or-later) |
| libssh2, zstd | BSD-3-Clause |
| libunistring | LGPL-3.0-or-later |
| nss-cacert, publicsuffix-list | MPL-2.0 |
| openssl | Apache-2.0 |
| osquery | GPL-2.0-only or Apache-2.0 |
| xz | GPL-2.0-or-later, LGPL-2.1-or-later |
| zlib | Zlib |

## Tools built for WebAssembly

| Package | Licence |
|---|---|
| uutils coreutils (upstream's own release; `LICENSE` in the image) | MIT |
| jaq (`jq.wasm`) | MIT |
| goawk (`awk.wasm`) | MIT |

## Rust crates

`sensor/Cargo.lock` and `probe/Cargo.lock` name every crate in `beat-sensor` and `beat-probe`, among them wasmtime
(Apache-2.0 WITH LLVM-exception) and starlark (Apache-2.0). They are under permissive licences: MIT, Apache-2.0, BSD,
ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0, CC0-1.0 and Unlicense, most with a choice among these.

## Secret rules

`probe/rules/betterleaks.json` comes from Betterleaks: `probe/rules/LICENSE.betterleaks`.
