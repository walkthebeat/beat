#!/bin/bash
# Records the capture scenarios' faults in network namespaces (run as root): cli -- rtr -- srv, veth links.
#   cli 10.99.1.2 --(1500; the router's side 1400)-- 10.99.1.1 rtr 10.99.2.1 --(mtu 1500)-- 10.99.2.2 srv
# Nothing touches the host's own interfaces. Usage: lab.sh OUTDIR
set -u
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
PY=/usr/bin/python3
N="ip netns exec"

down() {
  for ns in bc-cli bc-rtr bc-srv; do
    ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $ns 2>/dev/null
  done
  rm -rf /etc/netns/bc-cli /tmp/bc-www
  rmdir /etc/netns 2>/dev/null
}
trap down EXIT
down

up() {
  for ns in bc-cli bc-rtr bc-srv; do ip netns add $ns; $N $ns ip link set lo up; done
  ip link add bc-c type veth peer name bc-rc
  ip link add bc-s type veth peer name bc-rs
  ip link set bc-c netns bc-cli; ip link set bc-rc netns bc-rtr
  ip link set bc-s netns bc-srv; ip link set bc-rs netns bc-rtr
  $N bc-cli ip addr add 10.99.1.2/24 dev bc-c; $N bc-cli ip link set bc-c mtu 1500 up
  $N bc-rtr ip addr add 10.99.1.1/24 dev bc-rc; $N bc-rtr ip link set bc-rc mtu 1400 up
  $N bc-rtr ip addr add 10.99.2.1/24 dev bc-rs; $N bc-rtr ip link set bc-rs up
  $N bc-srv ip addr add 10.99.2.2/24 dev bc-s; $N bc-srv ip link set bc-s up
  $N bc-cli ip route add default via 10.99.1.1
  $N bc-srv ip route add default via 10.99.2.1
  $N bc-rtr sysctl -qw net.ipv4.ip_forward=1
  mkdir -p /etc/netns/bc-cli
  echo "nameserver 10.99.2.2" > /etc/netns/bc-cli/resolv.conf
  echo "options timeout:2 attempts:1" >> /etc/netns/bc-cli/resolv.conf
}

# cap NS IFACE NAME SECONDS: tcpdump in the namespace, headers and a DNS question (snaplen 128)
cap() {
  $N $1 timeout $4 tcpdump -i $2 -s 128 -U -w $OUT/$3.pcap 2>/dev/null &
  CAP=$!
  sleep 1
}

web() { # a server for big responses
  mkdir -p /tmp/bc-www && head -c 300000 /dev/urandom > /tmp/bc-www/big && echo small > /tmp/bc-www/small
  $N bc-srv $PY -m http.server 8080 --bind 10.99.2.2 --directory /tmp/bc-www >/dev/null 2>&1 &
  sleep 1
}

up
web

echo "== mtu: ICMP frag-needed dropped by the router"
$N bc-rtr iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP
cap bc-srv bc-s mtu-blackhole 12
$N bc-cli curl -s --max-time 2 -o /dev/null http://10.99.2.2:8080/small
$N bc-cli curl -s --max-time 8 -o /dev/null http://10.99.2.2:8080/big; echo "big: curl $?"
wait $CAP
$N bc-rtr iptables -F OUTPUT

echo "== mtu control: ICMP allowed (PMTU discovery works)"
$N bc-srv ip route flush cache
cap bc-srv bc-s mtu-control 6
$N bc-cli curl -s --max-time 4 -o /dev/null http://10.99.2.2:8080/big; echo "big: curl $?"
wait $CAP

echo "== loss: 3% on the server's egress"
$N bc-srv tc qdisc add dev bc-s root netem loss 3%
cap bc-cli bc-c loss 10
for i in 1 2 3 4 5; do $N bc-cli curl -s --max-time 4 -o /dev/null http://10.99.2.2:8080/big; done
wait $CAP
$N bc-srv tc qdisc del dev bc-s root

echo "== listen queue: a server that never accepts, backlog 1"
$N bc-srv $PY "$HERE/stuck.py" 10.99.2.2 9000 &
sleep 1
cap bc-cli bc-c listen-queue 10
CL=""
for i in 1 2 3 4 5 6; do $N bc-cli timeout 7 $PY -c "import socket; s=socket.create_connection(('10.99.2.2',9000),timeout=6); s.recv(1)" 2>/dev/null & CL="$CL $!"; done
wait $CL $CAP

echo "== dns: A answered, AAAA never"
$N bc-srv $PY "$HERE/dns.py" 10.99.2.2 &
sleep 1
cap bc-cli bc-c aaaa-blackhole 9
$N bc-cli bash -c 'time getent ahosts db.lab' 2>&1 | tail -4
$N bc-cli getent ahostsv4 api.lab
wait $CAP
echo done
