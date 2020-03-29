#!/bin/bash
set -e

manager_cert_path="$1"
manager_key_path="$2"

mkdir -p certs

if [[ -n "${MANAGER_CERT_BASE64}" ]]  && [[ -n "${MANAGER_KEY_BASE64}" ]]; then
	base64 -D <<< "${MANAGER_CERT_BASE64}" > ${manager_cert_path}
	base64 -D <<< "${MANAGER_KEY_BASE64}" > ${manager_key_path}
else
	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-keyout ${manager_key_path} \
		-out ${manager_cert_path} \
		-days 365 \
		-nodes \
		-subj "/C=US/ST=California/L=Berkeley/O=Kelda Inc/OU=Kelda Blimp Manager/CN=localhost"
fi
