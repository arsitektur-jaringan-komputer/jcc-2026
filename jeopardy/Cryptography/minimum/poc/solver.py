#!/usr/bin/env python3
"""
Solver for minimum.

Attack: GCM / GHASH cycling attack (Saarinen 2011/202)
========================================================
The server uses a custom GCM whose GHASH key H has a small
multiplicative order in GF(2^128).

Because  H^n = 1  (where n = ord(H)), modifying two ciphertext
blocks that are exactly n positions apart by the SAME delta leaves
the GHASH polynomial, and therefore the authentication tag,
unchanged.

Steps
-----
1. Obtain (nonce, ct, tag) and the known plaintext command.
2. Determine ord(H) by swapping ciphertext blocks at increasing
   distances d=1, 2, 3, ... and checking tag validity with the
   verify oracle.  The smallest d where the swap is accepted
   equals ord(H).
3. Compute delta = KNOWN_CMD ^ TARGET_CMD  (first block only).
4. Apply delta to blocks 0 and 0+ord(H) -> tag stays valid,
   but block 0 now decrypts to the target command.
5. Submit the forged ciphertext via "execute" to get the flag.
"""

from pwn import *
import json

# -- connection ------------------------------------------------

HOST = "localhost"
PORT = 13424

io = remote(HOST, PORT)
io.recvuntil(b"\n")


def msg(obj):
    io.sendline(json.dumps(obj).encode())
    return json.loads(io.readline())

# -- step 1: get the encrypted message ------------------------

data = msg({"option": "encrypt"})

known_cmd  = data["command"].encode()
nonce      = bytes.fromhex(data["nonce"])
ct         = bytes.fromhex(data["ciphertext"])
tag_hex    = data["tag"]
num_blocks = data["blocks"]

log.info(f"Known command : {known_cmd}")
log.info(f"Blocks        : {num_blocks}")

# -- helpers ---------------------------------------------------

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

# -- step 2: determine ord(H) ---------------------------------
#
# Swapping blocks at distance d preserves the tag iff ord(H) | d.
# Therefore the SMALLEST d where the swap is accepted = ord(H).
#
# We test d = 1, 2, 3, ... up to num_blocks - 1.
# This requires no prior knowledge of which orders are possible.

log.info("Probing multiplicative order of H ...")

order = None
for d in range(1, num_blocks):
    valid = verify(swap_blocks(ct, 0, d))
    log.info(f"  swap distance {d} -> {'valid' if valid else 'invalid'}")
    if valid:
        order = d
        break

if order is None:
    log.failure("Could not determine ord(H) within block range")
    io.close()
    exit(1)

log.success(f"ord(H) = {order}")

# -- step 3: forge the target command --------------------------
#
# delta = KNOWN_CMD ^ TARGET_CMD   (block 0 only, 16 bytes)
#
# Modify ciphertext blocks  0  and  0 + ord(H)  by delta.
# Because  H^{ord(H)} = 1, the two modifications cancel
# in the GHASH polynomial, so the original tag remains valid.
# In CTR mode, block 0 now decrypts to TARGET_CMD.

TARGET_CMD = b"GIVEMETHEFLAG___"

delta = xor_bytes(known_cmd.ljust(16, b"\x00"), TARGET_CMD)

blks = split(ct)
blks[0]     = xor_bytes(blks[0],     delta)
blks[order] = xor_bytes(blks[order], delta)
forged_ct   = b"".join(blks)

log.info("Forged ciphertext built, submitting ...")

# -- step 4: execute the forged command ------------------------

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
