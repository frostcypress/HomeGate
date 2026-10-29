#!/bin/sh
dns_homegate_add() { printf '%s\n%s\n' "$1" "$2" | ash /usr/libexec/homegate/project/core/prototype/homegate-acme-dns.sh add; }
dns_homegate_rm() { printf '%s\n%s\n' "$1" "$2" | ash /usr/libexec/homegate/project/core/prototype/homegate-acme-dns.sh remove; }
