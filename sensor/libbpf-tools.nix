# libbpf-tools from bcc's source: B. Gregg's tools as CO-RE programs (compiled once, relocated against the target's
# BTF at load; no LLVM or kernel headers on the target). The catalog behind trace() (probe/src/catalog.rs,
# docs/probes.md [B11c]) runs them.
# nixpkgs packages bcc (Python + LLVM at run time, which failed on kernel 7.0), not these. The tarball lacks
# bcc's git submodules, so libbpf's source and bpftool come from nixpkgs. Only the catalog's tools are built.
{ stdenv, bcc, libbpf, bpftools, llvmPackages, linuxHeaders, elfutils, zlib, which, coreutils }:
stdenv.mkDerivation {
  pname = "libbpf-tools";
  inherit (bcc) version src;
  nativeBuildInputs = [ llvmPackages.clang-unwrapped llvmPackages.llvm bpftools which ];
  buildInputs = [ elfutils zlib ];
  postUnpack = ''
    rmdir $sourceRoot/src/cc/libbpf
    cp -r ${libbpf.src} $sourceRoot/src/cc/libbpf && chmod -R u+w $sourceRoot/src/cc/libbpf
  '';
  # The BPF objects are built by unwrapped clang for the bpf target: no stack protector there, and the kernel's uapi
  # headers (asm-generic/errno.h) after the source's own.
  hardeningDisable = [ "all" ];
  # Each catalog entry names one of these (probe/src/catalog.rs).
  apps = "biolatency runqlat execsnoop opensnoop tcpconnect tcplife offcputime cpudist syscount";
  buildPhase = ''
    cd libbpf-tools
    make -j$NIX_BUILD_CORES V=1 USE_BLAZESYM=0 BPFTOOL=bpftool CLANG="clang -idirafter ${linuxHeaders}/include" LLVM_STRIP=llvm-strip APPS="$apps" APP_ALIASES=
  '';
  installPhase = ''
    mkdir -p $out/bin
    for a in $apps; do install -m 0755 $a $out/bin/; done
    # The event tools run until interrupted, and print what they buffered on SIGINT (a kill would lose it): the
    # catalog stops them with `timeout -s INT`, from this directory.
    ln -s ${coreutils}/bin/timeout $out/bin/timeout
  '';
}
