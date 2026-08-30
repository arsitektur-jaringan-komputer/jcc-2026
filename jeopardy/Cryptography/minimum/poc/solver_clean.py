#!/usr/bin/env python3

from pwn import *
import json

HOST = "localhost"
PORT = 13424

io = remote(HOST, PORT)
io.recvuntil(b"\n")

def msg(obj):
    io.sendline(json.dumps(obj).encode())
    return json.loads(io.readline())

data = msg({"option": "encrypt"})

known_cmd  = data["command"].encode()
nonce      = bytes.fromhex(data["nonce"])
ct         = bytes.fromhex(data["ciphertext"])
tag_hex    = data["tag"]
num_blocks = data["blocks"]

def split(bs, n=16):
    return [bs[i:i+n] for i in range(0, len(bs), n)]

def swap_blocks(ct_bytes, i, j):
    blks = split(ct_bytes)
    blks[i], blks[j] = blks[j], blks[i]
    return b"".join(blks)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def verify(ct_bytes):
    r = msg({
        "option":     "verify",
        "ciphertext": ct_bytes.hex(),
        "tag":        tag_hex,
    })
    return r.get("valid", False)

order = None
for d in range(1, num_blocks):
    valid = verify(swap_blocks(ct, 0, d))
    if valid:
        order = d
        break

TARGET_CMD = b"GIVEMETHEFLAG___"

delta = xor_bytes(known_cmd.ljust(16, b"\x00"), TARGET_CMD)

blks = split(ct)
blks[0]     = xor_bytes(blks[0],     delta)
blks[order] = xor_bytes(blks[order], delta)
forged_ct   = b"".join(blks)

result = msg({
    "option":     "execute",
    "ciphertext": forged_ct.hex(),
    "tag":        tag_hex,
})

log.success(f"FLAG: {result['flag']}")
io.close()
