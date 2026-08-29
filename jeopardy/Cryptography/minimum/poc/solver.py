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

log.info(f"Known command : {known_cmd}")
log.info(f"Blocks        : {num_blocks}")


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

log.info("Probing multiplicative order of H …")

d1 = verify(swap_blocks(ct, 0, 1))
log.info(f"  swap distance 1 → {'valid' if d1 else 'invalid'}")

if d1:
    order = 1
else:
    d3 = verify(swap_blocks(ct, 0, 3))
    log.info(f"  swap distance 3 → {'valid' if d3 else 'invalid'}")

    d5 = verify(swap_blocks(ct, 0, 5))
    log.info(f"  swap distance 5 → {'valid' if d5 else 'invalid'}")

    if d3:
        order = 3
    elif d5:
        order = 5
    else:
        order = 15

log.success(f"ord(H) = {order}")

TARGET_CMD = b"GIVEMETHEFLAG___"

delta = xor_bytes(known_cmd.ljust(16, b"\x00"), TARGET_CMD)

blks = split(ct)
blks[0]     = xor_bytes(blks[0],     delta)
blks[order] = xor_bytes(blks[order], delta)
forged_ct   = b"".join(blks)

log.info("Forged ciphertext built — submitting …")

result = msg({
    "option":     "execute",
    "ciphertext": forged_ct.hex(),
    "tag":        tag_hex,
})

if "flag" in result:
    log.success(f"FLAG: {result['flag']}")
else:
    log.failure(f"Unexpected response: {result}")

io.close()
