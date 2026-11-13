#!/bin/bash
# Records tls-curl.pcap and tls-s_client.pcap (tests/pcap/README.md) on loopback; tcpdump needs root (sudo).
# Usage: tls.sh OUTDIR
set -u
OUT=$1
W=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$W"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=db.lab -days 2 \
  -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null
srv() { openssl s_server -quiet -www -accept 18443 -cert "$W/cert.pem" -key "$W/key.pem" "$@" >/dev/null 2>&1 & SRV=$!; sleep 0.7; }
c() { curl -s --resolve db.lab:18443:127.0.0.1 --max-time 2 -o /dev/null "$@"; }

sudo timeout 14 tcpdump -i lo -s 4096 -U -w "$OUT/tls-curl.pcap" 'tcp port 18443' 2>/dev/null & CAP=$!; sleep 1.5
srv
c -k https://db.lab:18443/              # TLS 1.3, SNI, ALPN
c --tls-max 1.2 https://db.lab:18443/   # untrusted: this curl finishes the handshake, then resets (no alert)
c https://db.lab:18443/                 # untrusted, TLS 1.3: no plaintext alert
c http://db.lab:18443/                  # not TLS
kill $SRV; wait $SRV 2>/dev/null
srv -tls1_2
c -k --tlsv1.3 https://db.lab:18443/    # protocol_version from the server
kill $SRV; wait $CAP

srv
sudo timeout 5 tcpdump -i lo -s 4096 -U -w "$OUT/tls-s_client.pcap" 'tcp port 18443' 2>/dev/null & CAP=$!; sleep 1.5
for v in -tls1_2 -tls1_3; do   # untrusted: s_client sends unknown_ca in plaintext, in both versions
  echo | timeout 3 openssl s_client -connect 127.0.0.1:18443 -servername db.lab $v -verify_return_error >/dev/null 2>&1
done
wait $CAP
