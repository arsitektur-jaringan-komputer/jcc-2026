encrypted = bytes.fromhex(
    "4B CA BB 9F AA AB 69 DB AF BF AA CA AB 69 AF 1A "
    "DB 69 CA 4A 69 AF FB 8F EA 69 BB AF FB AF 7A 69 "
    "CB 2A 9F DA CB AB 2B A8 A8 38"
)

reversed_bytes = bytes(reversed(encrypted))
key = (1337 * 7 + 13) % 256
xored = bytes(b ^ key for b in reversed_bytes)
flag = bytes(((b >> 4) | ((b & 0x0F) << 4)) & 0xFF for b in xored)

print(flag.decode("ascii"))