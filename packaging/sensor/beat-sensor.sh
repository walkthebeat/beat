#!/bin/sh
# beat-sensor on the host (configure, enroll, keygen): runs this image's beat-sensor in a transient unit with the
# image mounted at /nix/store, as the service runs, so the host needs no /nix. Build: @out@
image=@image@
[ -t 0 ] && io=--pty || io=--pipe
# Through the host's /bin/sh: an older systemd-run (249, Ubuntu 22.04) looks for the program on the host, where
# /nix/store is not.
exec /usr/bin/systemd-run --quiet --wait --collect $io -p "MountImages=$image:/nix/store" \
  -p WorkingDirectory="$PWD" /bin/sh -c 'exec "$0" "$@"' @sensor@ "$@"
