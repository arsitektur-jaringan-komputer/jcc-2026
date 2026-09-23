# https://github.com/shreyanshkansara20/Digital-Signature-Forgery/blob/master/DSForge.py
from pwn import *
import hashlib
from sympy.ntheory.residue_ntheory import nthroot_mod
from libnum import nroot, solve_crt
from Crypto.Util.number import long_to_bytes as to_bytes, bytes_to_long as from_bytes
import os
import rsa
import json
import ast
from Crypto.Cipher import AES

def forge(target_message):
    target_hash = hashlib.sha256(target_message).digest()

    # nonce = 0
    # while True:
    #     target_message = f"{target_message}{nonce}".encode()
    #     target_hash = hashlib.sha256(target_message).digest()
            
    #     if target_hash[-1] % 2 == 1:
    #         print(f"Payload: '{target_message.decode()}'")
    #         print(f"Byte terakhir hash: {hex(target_hash[-1])} (Ganjil!)")
    #         break
    #     nonce += 1

    # asn1_magic = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    # asn1_magic = b'010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '
    asn1_magic =  rsa.pkcs1.HASH_ASN1['SHA-256']

    suffix_bytes = b'\x00' + asn1_magic + target_hash
    suffix_int = int.from_bytes(suffix_bytes, byteorder='big')

    k = len(suffix_bytes) * 8  # 52 bytes = 416 bits

    new_sig_suffix = nthroot_mod(suffix_int, 3, 2**k)

    while True:
        # os.urandom for getting Random Bytes of specific length suitable for cryptography
        new_sig_prefix=b'\x00\x01'+os.urandom(2048//8 - 2)
    
        
        # Generating Prefix and taking the prefix upto the length of suffix    
        new_sig_prefix=to_bytes(nroot(from_bytes(new_sig_prefix), 3))[:-len(suffix_bytes)]    
        
        new_sig=new_sig_prefix+to_bytes(new_sig_suffix)
        
        # We want length to be 85, because 256/3 is almost 85.
        # if len(new_sig) > 85:
            # new_sig=new_sig_prefix[:-(len(new_sig)-85)]+to_bytes(new_sig_suffix)
        if len(new_sig) < 85:
            new_sig=new_sig_prefix+b'\xFF'*(85-len(new_sig))+to_bytes(new_sig_suffix)
        else:
            new_sig=new_sig_prefix+to_bytes(new_sig_suffix)
            
        #There should be no \x00 in the cube of the signature otherwise verify function will fail 
        if b'\x00' not in to_bytes(from_bytes(new_sig)**3)[2:-len(suffix_bytes)]:
            print(new_sig.hex())
            #print(len(to_bytes(from_bytes(new_sig)**3)))
            break

    # new_sig = to_bytes(from_bytes(new_sig)**3)
    # signature_b64 = base64.b64encode(new_sig).decode('utf-8')
    # return signature_b64
    return new_sig.hex()


def get_ticket(user,r):
    payload = {"command": "get", "user": user}
    r.sendline(json.dumps(payload).encode())
    r.recvuntil(b'save your ticket: ')
    return r.recvline().decode()

def craft_ticket(key, r):
    payload = {"timestamp": "Thu Jun  6 00:00:00 2024", "user": "adminaaaaa", "role": "admin", "access": True}
    payload = json.dumps(payload).encode()
    cipher = AES.new(key, AES.MODE_CBC, key)
    ciphertext = cipher.encrypt(payload)
    return ciphertext.hex()

def recover_key(r):
    ct_forge = bytes(32).hex()
    new_sig = forge(ct_forge.encode())
    payload = {"command": "claim", "ticket": ct_forge, "signature": new_sig}
    r.sendline(json.dumps(payload).encode())
    r.recvuntil(b'ticket confirmation: ')
    result = r.recvline().decode()
    # print(result)
    result = ast.literal_eval(result)
    key = xor(result[:16], result[16:32])
    return key

# r = process(["/usr/bin/python3", "../src/app.py"])
r = remote("localhost", 6969)
print(r.recvline())
print(r.recvline())
print(r.recvline())
# exec("res = " + get_ticket("asd", r))
key = recover_key(r)
print(key.hex())
ticket = craft_ticket(key, r)
payload = {"command": "claim", "ticket": ticket, "signature": forge(ticket.encode())}
r.sendline(json.dumps(payload).encode())
# print(r.recvline())
r.interactive()
