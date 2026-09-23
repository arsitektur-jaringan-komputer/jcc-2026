import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import fcntl
import os
import tempfile
from time import ctime
import json
from pathlib import Path

FLAG_FILE = Path("/flag")
RUNTIME_DIR = Path(os.environ.get("PLAYGROUND_RUNTIME_DIR", "/run/playground"))
AES_KEY_FILE = RUNTIME_DIR / "aes.key"
RSA_KEY_FILE = RUNTIME_DIR / "rsa.pem"


def _atomic_write(path, data):
    with tempfile.NamedTemporaryFile(dir=RUNTIME_DIR, delete=False) as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
        temporary_path = output.name
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)


def load_or_create_key_material():
    """Create unique key material once per pod, then load it for each session."""
    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (RUNTIME_DIR / "key.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            key = AES_KEY_FILE.read_bytes()
            rsakey = RSA.import_key(RSA_KEY_FILE.read_bytes())
            if len(key) != 16 or not rsakey.has_private():
                raise ValueError("invalid key material")
        except (OSError, ValueError, IndexError, TypeError):
            key = os.urandom(16)
            rsakey = RSA.generate(2048, e=3)
            _atomic_write(AES_KEY_FILE, key)
            _atomic_write(RSA_KEY_FILE, rsakey.export_key(format="PEM"))
        return key, rsakey


KEY, rsakey = load_or_create_key_material()
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

    if command == "claim" and not ("ticket" in req and "signature" in req):
        print("need arguments")
        return

    if command == "get" and "user" not in req:
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
