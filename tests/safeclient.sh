#!/bin/sh
cargo run --features=cmd s_client example.com:443 <<EOF
GET / HTTP/1.1
Host: example.com
Connection: close

EOF
