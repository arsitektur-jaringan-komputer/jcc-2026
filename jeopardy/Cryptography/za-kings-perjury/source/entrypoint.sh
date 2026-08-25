#!/bin/bash

echo "$GZCTF_FLAG" > /app/flag.txt
chmod 444 /app/flag.txt

unset GZCTF_FLAG

exec python3 -u server.py