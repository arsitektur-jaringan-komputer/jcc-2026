encrypted = bytes.fromhex(
    "10 53 10 6B 18 6D 09 39 52 27 78 16 25 53 60 12 "
    "4D 2A 1B 6D 5E 01 6C 09 56 22 4A 79 26 55 30 53 "
    "61 52 26 79 0A 69 59 2B 4E 33"
)

previous = 0x5A
decoded = bytearray()
for value in encrypted:
    decoded.append(value ^ previous)
    previous = value

print(decoded.decode("ascii"))