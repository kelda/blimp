#!/bin/bash
set -e

manager_cert_path="$1"
manager_key_path="$2"
manager_ip="$3"

mkdir -p certs

if [[ -n "${MANAGER_CERT_BASE64}" ]]  && [[ -n "${MANAGER_KEY_BASE64}" ]]; then
	base64 -d <<< "${MANAGER_CERT_BASE64}" > ${manager_cert_path}
	base64 -d <<< "${MANAGER_KEY_BASE64}" > ${manager_key_path}
else
    cat > /tmp/openssl.conf <<-EOF
[req]
prompt = no
distinguished_name = dn

[dn]
C=US
ST=California
L=Berkeley
O=Kelda Inc
OU=Kelda Blimp Manager
CN=localhost

[ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = ${manager_ip}
DNS.1 = localhost
EOF

	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-keyout ${manager_key_path} \
		-out ${manager_cert_path} \
		-days 365 \
		-nodes \
		-extensions ext \
		-config /tmp/openssl.conf
fi
