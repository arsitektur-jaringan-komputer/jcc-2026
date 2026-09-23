import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from time import ctime
import json
from pathlib import Path

KEY = os.urandom(16)
FLAG_FILE = Path("/flag")

rsakey = RSA.generate(2048, e=3)
private_key = rsa.PrivateKey(rsakey.n, rsakey.e, rsakey.d, rsakey.p, rsakey.q)
public_key = rsa.PublicKey(rsakey.n, rsakey.e)

def read_flag():
    try:
        with open(FLAG_FILE, 'r') as flag_file:
            return flag_file.read().strip()
    except OSError:
        return None

def encrypt(plaintext):
    pt = bytes.fromhex(plaintext)
    cipher = AES.new(KEY, AES.MODE_CBC, KEY)    
    ct = cipher.encrypt(pt)
    return ct.hex()

def decrypt(ciphertext):
    ct = bytes.fromhex(ciphertext)
    cipher = AES.new(KEY, AES.MODE_CBC, KEY)
    pt = cipher.decrypt(ct)
    return pt.hex()

def sign(message, private_key):    
    return rsa.sign(message, private_key, "SHA-256")

def verify(message, signature, public_key):
    try:
        rsa.verify(message, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

def create_ticket(user):
    ticket = json.dumps({"timestamp": ctime(), "user": user, "role": "guest", "access": False})
    ticket = encrypt(ticket.encode().hex())
    signature = sign(ticket.encode(), private_key)
    return {"ticket": ticket, "signature": signature.hex()}

def read_ticket(ticket, signature):
    if not verify(ticket.encode(), bytes.fromhex(signature), public_key):        
        return "Invalid signature"    

    ticket = bytes.fromhex(decrypt(ticket))    
    return ticket

def request_handler(req):    
    req = json.loads(req)    
    if not "command" in req:
        print("Invalid request")
        return

    command = req.get("command")
    if not command in ["claim", "get"]:
        print("Invalid command")
        return

    if command in ["claim", "get"] and not (("ticket" and "signature" in req) or "user" in req):
        print("need arguments")
        return

    if command == "claim" and ("ticket" in req and "signature" in req):
        readable_ticket = read_ticket(req.get("ticket"), req.get("signature"))
        if readable_ticket == "Invalid signature":
            print("Invalid signature")
            return

        print("ticket confirmation:", readable_ticket)        
        check = json.loads(readable_ticket)
        if check.get("role") == "admin" and check.get("access") == True:            
            flag = read_flag()
            if flag:
                print(f"save your flag: {flag}")
            else:
                print("flag is not ready yet")
            return
        else:
            print("not for you, sorry")
            return

    if command == "get" and "user" in req:
        ticket = create_ticket(req.get("user"))
        print(f"save your ticket: {ticket}")
        return    
    
def main():
    print(f"""
        Playground        
    """)
    while True:
        req = str(input(""))
        if req == "exit":
            break
        try:
            request_handler(req)
        except Exception as e:
            print("Something went wrong, please try again.")                      



if __name__ == "__main__":
    main()
