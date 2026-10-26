#!/usr/bin/env bash
# Disposable test credentials, never use these identities in production.
set -euo pipefail
output=$1
hostname=${2:-localhost}
mkdir -p "$output"
cd "$output"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Test CA' -keyout ca.key -out ca.pem
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Wrong CA' -keyout wrong-ca.key -out wrong-ca.pem
openssl req -newkey rsa:2048 -nodes -subj "/CN=$hostname" -keyout server.key -out server.csr
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$hostname" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.pem
openssl req -newkey rsa:2048 -nodes -subj '/CN=fastnetmon' -keyout client.key -out client.csr
printf 'subjectAltName=URI:rustbgpd://operator/fastnetmon\nextendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile client.ext -out client.pem
rm ca.key wrong-ca.key ca.srl server.csr client.csr server.ext client.ext
