#!/usr/bin/env python3

from Crypto.Cipher import AES
from os import urandom
import struct

from utils import listener
from secret import gen_auth_key

FLAG = 'JCC{?????????????????????????????????}'

R_POLY = 0xe1 << 120

def gf_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R_POLY
        else:
            v >>= 1
    return z

def ghash(H, blocks):
    y = 0
    for b in blocks:
        y = gf_mul(y ^ b, H)
    return y

def ctr_crypt(key, nonce, data):
    ecb = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    for i in range((len(data) + 15) // 16):
        ctr_block = nonce + struct.pack(">I", i + 2)
        ks = ecb.encrypt(ctr_block)
        chunk = data[i * 16 : (i + 1) * 16]
        out.extend(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)

def _tag(key, H, nonce, ct):
    ct_ints = [int.from_bytes(ct[i:i+16], "big")
               for i in range(0, len(ct), 16)]
    len_block = int.from_bytes(struct.pack(">QQ", 0, len(ct) * 8), "big")
    ct_ints.append(len_block)
    ecb = AES.new(key, AES.MODE_ECB)
    j0  = nonce + struct.pack(">I", 1)
    mask = int.from_bytes(ecb.encrypt(j0), "big")
    return (ghash(H, ct_ints) ^ mask).to_bytes(16, "big")

def gcm_encrypt(key, H, nonce, pt):
    ct  = ctr_crypt(key, nonce, pt)
    tag = _tag(key, H, nonce, ct)
    return ct, tag

def gcm_verify(key, H, nonce, ct, tag):
    return _tag(key, H, nonce, ct) == tag

NUM_BLOCKS = 20
MSG_LEN    = NUM_BLOCKS * 16

KNOWN_CMD  = b"STATUS_REPORT___"
TARGET_CMD = b"GIVEMETHEFLAG___"


class Challenge:
    def __init__(self):
        self.before_input = (
            "=== minimum ===\n"
        )
        self.key   = urandom(16)
        self.nonce = urandom(12)
        self.H     = gen_auth_key()

        self.plaintext = KNOWN_CMD + b"\x00" * (MSG_LEN - len(KNOWN_CMD))
        self.ct, self.tag = gcm_encrypt(
            self.key, self.H, self.nonce, self.plaintext
        )

        self.encrypt_count = 0
        self.verify_count  = 0
        self.max_verifies  = 100

    def challenge(self, msg):
        opt = msg.get("option")
        if opt not in ("encrypt", "verify", "execute"):
            return {"error": "option must be one of: encrypt, verify, execute"}

        if opt == "encrypt":
            return self._encrypt()
        if opt == "verify":
            return self._verify(msg)
        if opt == "execute":
            return self._execute(msg)

    def _encrypt(self):
        if self.encrypt_count >= 1:
            return {"error": "encryption already issued"}
        self.encrypt_count += 1
        return {
            "command":    KNOWN_CMD.decode(),
            "nonce":      self.nonce.hex(),
            "ciphertext": self.ct.hex(),
            "tag":        self.tag.hex(),
            "blocks":     NUM_BLOCKS,
        }

    def _verify(self, msg):
        if self.verify_count >= self.max_verifies:
            self.exit = True
            return {"error": "verification limit reached"}
        self.verify_count += 1
        try:
            ct  = bytes.fromhex(msg["ciphertext"])
            tag = bytes.fromhex(msg["tag"])
        except (KeyError, ValueError):
            return {"error": "provide 'ciphertext' and 'tag' as hex strings"}
        if len(ct) != MSG_LEN or len(tag) != 16:
            return {"error": f"expected {MSG_LEN}-byte ciphertext and 16-byte tag"}
        return {"valid": gcm_verify(self.key, self.H, self.nonce, ct, tag)}

    def _execute(self, msg):
        try:
            ct  = bytes.fromhex(msg["ciphertext"])
            tag = bytes.fromhex(msg["tag"])
        except (KeyError, ValueError):
            return {"error": "provide 'ciphertext' and 'tag' as hex strings"}
        if len(ct) != MSG_LEN or len(tag) != 16:
            return {"error": f"expected {MSG_LEN}-byte ciphertext and 16-byte tag"}
        if not gcm_verify(self.key, self.H, self.nonce, ct, tag):
            return {"error": "authentication failed - access denied"}
        pt = ctr_crypt(self.key, self.nonce, ct)
        if pt[:16] == TARGET_CMD:
            self.exit = True
            return {"flag": FLAG}
        return {"result": "authenticated, but unrecognised command"}


import builtins; builtins.Challenge = Challenge
listener.start_server(port=13424)
