from Crypto.Util.strxor import strxor
from binascii import unhexlify

cipher_hex = "d2db5b9be8f47983fdf0778cfcfd6a9d" # change me
cipher = unhexlify(cipher_hex)

known_prefix = b"JCC{"

key = strxor(cipher[:4], known_prefix)

expanded_key = (key * ((len(cipher) // len(key)) + 1))[:len(cipher)]

plaintext = strxor(cipher, expanded_key)
print(expanded_key)
print("Recovered flag:", plaintext.decode())