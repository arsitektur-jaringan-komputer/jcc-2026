from Crypto.Cipher import AES
import os
import json
from time import ctime

KEY = os.urandom(16)
FLAG_FILE = 'flag.txt'

def read_flag():
    try:
        with open(FLAG_FILE, 'r') as flag_file:
            return flag_file.read().strip()
    except OSError:
        return None

def encrypt(key, plaintext):    
    cipher = AES.new(key, AES.MODE_CBC, key)    
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()

def decrypt(key, ciphertext):
    ciphertext = bytes.fromhex(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def create_ticket(user):
    ticket = json.dumps({"timestamp": ctime(), "user": user, "role": "guest", "access": False})
    ticket = encrypt(KEY, ticket.encode())
    return ticket

def read_ticket(ticket):
    ticket = decrypt(KEY, ticket)
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

    if command in ["claim", "get"] and not ("ticket" in req or "user" in req):
        print("need arguments")
        return

    if command == "claim" and "ticket" in req:
        readable_ticket = read_ticket(req.get("ticket"))
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
        Freeflag as a Service        
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
