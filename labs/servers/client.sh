#!/bin/sh
# Diagnostic client: trust the lab CA, learn the route to the far network, then idle.
set -eu
cp /certs/ca.crt /usr/local/share/ca-certificates/nettriage-lab.crt
update-ca-certificates >/dev/null 2>&1
ip route add 10.78.0.0/24 via 10.77.0.2
ip route add 10.79.0.0/24 via 10.77.0.2
touch /tmp/ready
exec sleep infinity
