#!/bin/sh
set -e

if [ ! -r cert.pem ]; then
    openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes \
    -subj "/O=openssl_lite/CN=localhost"
fi

cargo run --features=cmd s_server 0.0.0.0:8443 <<EOF
HTTP/1.1 200 OK
Content-Length: 19
Connection: close

Deathwing awakens!
EOF
