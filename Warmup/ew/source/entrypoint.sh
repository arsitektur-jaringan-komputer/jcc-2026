#!/bin/bash

echo $GZCTF_FLAG > /home/ctf/flag.txt
chmod 444 /home/ctf/flag.txt

unset GZCTF_FLAG
exec socat TCP-LISTEN:1337,reuseaddr,fork,nodelay EXEC:'timeout 180 /home/ctf/chall'