#!/bin/sh
cargo run --features=cmd s_client 127.0.0.1:443 <<EOF
GET / HTTP/1.1
Host: 127.0.0.1
Connection: close

EOF
