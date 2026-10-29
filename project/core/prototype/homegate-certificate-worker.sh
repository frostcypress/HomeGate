#!/bin/sh
# Validates only fixed private candidate material, inside the existing watchdog.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin;export PATH LC_ALL=C TZ=UTC0
unset OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES RANDFILE SSL_CERT_DIR SSL_CERT_FILE
[ "$#" -eq 1 ] || exit 2
id=$1;case "$id" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac;[ "${#id}" -le 64 ] || exit 2
base=/etc/homegate/certs/$id/.pending
dir=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 1
lua "$dir/homegate-certificate.lua" material "$id" || exit 1
openssl pkey -in "$base/privkey.pem" -passin pass: -pubout -outform DER -out "$base/keypub.der" >/dev/null 2>/dev/null || exit 1
openssl x509 -in "$base/leaf.pem" -pubkey -noout > "$base/certpub.pem" 2>/dev/null || exit 1
openssl pkey -pubin -in "$base/certpub.pem" -outform DER -out "$base/certpub.der" >/dev/null 2>/dev/null || exit 1
a=$(sha256sum "$base/keypub.der") && b=$(sha256sum "$base/certpub.der") && [ "${a%% *}" = "${b%% *}" ] || exit 1
openssl crl2pkcs7 -nocrl -certfile "$base/fullchain.pem" -out "$base/chain.p7b" >/dev/null 2>/dev/null || exit 1
openssl pkcs7 -in "$base/chain.p7b" -print_certs -noout >/dev/null 2>/dev/null || exit 1
openssl x509 -in "$base/leaf.pem" -noout -startdate -enddate > "$base/dates" 2>/dev/null || exit 1
openssl x509 -in "$base/leaf.pem" -noout -ext subjectAltName > "$base/san" 2>/dev/null || exit 1
lua "$dir/homegate-certificate.lua" validated "$id" >&3
