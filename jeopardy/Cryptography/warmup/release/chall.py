from Crypto.Util.number import *
import json

flag= bytes_to_long(open('flag.txt','rb').read())
seed = getRandomNBitInteger(384)

def next_seed(seed):
        a = getPrime(384)
        b = getPrime(200)
        return a*seed+b

def genPrime(seed):
    if seed.bit_length() < 512:
      while True:
        a = getPrime(seed.bit_length()//2)
        b = getPrime(seed.bit_length()//2)
        p = a * seed + b
        if isPrime(p):
            return p
    else:
      return getPrime(512)


p,q = genPrime(seed),genPrime(seed)
n = p*q
e = 0x10001
msg = json.dumps({
                "c":pow(flag,e,n),
                "e":e,
                "n":n
        })

counter = 0
print(msg)
while counter < 5:
        user_seed = next_seed(seed)        
        n = genPrime(user_seed)*genPrime(user_seed)
        m = bytes_to_long(str(input("your message: ")).encode())        
        msg = json.dumps({
                "c": pow(m,e,n),
                "seed": user_seed
        })
        print(msg)
        counter+=1
