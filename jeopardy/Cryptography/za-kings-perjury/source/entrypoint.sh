#!/bin/bash

echo $GZCTF_FLAG > /flag.txt
chmod 444 /flag.txt

unset GZCTF_FLAG

exec python3 -u server.py