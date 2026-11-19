# The seccomp filters of a sensor that sandboxes with bubblewrap (seccomp.c, sensor/src/bwrap.rs): $out/question and
# $out/capture, BPF for bwrap --seccomp.
{ pkgs }:
pkgs.runCommandCC "beat-sensor-seccomp" { buildInputs = [ pkgs.libseccomp ]; } ''
  $CC -O2 -o mk ${./seccomp.c} -lseccomp
  mkdir $out
  ./mk > $out/question
  ./mk capture > $out/capture
''
