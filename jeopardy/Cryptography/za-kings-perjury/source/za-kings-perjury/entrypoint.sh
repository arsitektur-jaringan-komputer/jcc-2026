#!/bin/bash

# FLAG="random token from infra"
# FLAG_INIT="JCC{ZKP_50undn3ss_3rr0r_[UUID]}"
# FLAG=${FLAG_INIT//'[UUID]'/$FLAG}

echo $GCZTF_FLAG > /flag.txt
chmod 444 /flag.txt

unset FLAG_INIT
unset FLAG

exec python3 -u server.py