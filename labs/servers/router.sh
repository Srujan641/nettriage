#!/bin/sh
# Lab router. Usage: router.sh <remote-subnet> <next-hop>
# Forwards between its two networks and (the deliberate fault) refuses to send the
# ICMP "fragmentation needed" errors that path-MTU discovery depends on.
set -eu
ip route add "$1" via "$2"
if ! iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP 2>/dev/null; then
  iptables-legacy -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP
fi
echo "router up: $1 via $2; ICMP type 3 code 4 is dropped"
exec sleep infinity
