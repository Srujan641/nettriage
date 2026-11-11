#!/bin/sh
# Lab PKI: a throwaway root CA plus server certificates. Keys live only in a Docker volume.
set -eu
cd /certs
[ -f ca.crt ] && [ -f legacy-tls.lab.crt ] && { echo "certificates already present"; exit 0; }
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 90 \
  -subj "/O=NetTriage Lab/CN=NetTriage Lab Root CA" 2>/dev/null
for name in healthy.lab legacy-tls.lab; do
  openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/O=NetTriage Lab/CN=$name" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$name" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$name.crt" -days 60 -extfile "$name.ext" 2>/dev/null
done
chmod 644 ./*.key
echo "lab certificates generated"
