#!/bin/bash

echo $GZCTF_FLAG > /home/ctfflag.txt
chmod 444 /home/ctf/flag.txt

unset GZCTF_FLAG
exec socat TCP-LISTEN:4009,reuseaddr,fork,nodelay EXEC:'timeout 180 /home/ctf/chall'