# Attack

This folder contains the intended exploit for the Playground challenge. Run it
only against the challenge container.

## Vulnerability: RSA signature forgery with low exponent

The vulnerable code is in `src/app.py`:

```python
rsakey = RSA.generate(2048, e=3)

def verify(message, signature, public_key):
		try:
				rsa.verify(message, signature, public_key)
				return True
		except rsa.VerificationError:
				return False
```

The application signs the hex-encoded encrypted ticket:

```python
signature = sign(ticket.encode(), private_key)
```

The public exponent is `e=3`, and the verifier accepts a forged PKCS#1 v1.5
signature whose cube contains the expected SHA-256 digest but does not contain
strict, complete padding. The `forge()` function in `attack/sv.py` constructs
this signature using an integer cube-root attack.
`https://nvd.nist.gov/vuln/detail/cve-2016-1494`

## Vulnerability: AES-CBC key as IV

The vulnerable encryption code in `src/app.py` uses the same random value as
both the AES key and the CBC initialization vector:

```python
KEY = os.urandom(16)
cipher = AES.new(KEY, AES.MODE_CBC, KEY)
```

For CBC decryption, the first two plaintext blocks are:

```text
P1 = AES_decrypt(C1) XOR IV
P2 = AES_decrypt(C2) XOR C1
```

The attack chooses `C1 = C2 = 0`. Because `IV = KEY`, this gives:

```text
P1 = AES_decrypt(0) XOR KEY
P2 = AES_decrypt(0) XOR 0
KEY = P1 XOR P2
```

The AES weakness is only exploitable because the RSA signature forgery lets the
attacker submit this chosen ciphertext to `claim` and receive its decrypted
plaintext.


## Attack chain

```text
forge a signature for a chosen ciphertext
	-> submit forged claim
	-> application verifies the forged signature
	-> application decrypts attacker-chosen ciphertext
	-> recover the AES key from two CBC plaintext blocks
	-> encrypt an admin ticket with the recovered key
	-> forge a signature for the admin ciphertext
	-> claim the flag
```

## Stage 1: spoof a valid signature and recover the AES key

The exploit first creates a signature forgery for the attacker-controlled
ciphertext:

```python
ct_forge = bytes(32).hex()
new_sig = forge(ct_forge.encode())
payload = {
	"command": "claim",
	"ticket": ct_forge,
	"signature": new_sig,
}
```

`forge()` spoofs a signature that the vulnerable RSA verifier accepts as valid
for the chosen ciphertext. This is the first essential stage: without this
signature bypass, the application will reject the ciphertext before reaching
AES decryption.

`ct_forge` is a 32-byte, two-block ciphertext consisting of zero bytes. Since
the application uses AES-CBC with the key as both the key and IV, decrypting
the two zero blocks produces the relationship:

```text
P1 = AES_decrypt(0) XOR KEY
P2 = AES_decrypt(0) XOR 0
KEY = P1 XOR P2
```

The application prints the decrypted bytes in `ticket confirmation:`. The
exploit parses those two blocks and XORs them to recover `KEY` in
`recover_key()`.

## Stage 2: forge an admin ticket

Using the recovered key, `craft_ticket()` encrypts a JSON ticket with the
privileged fields:

```json
{"timestamp":"Thu Jun  6 00:00:00 2024","user":"adminaaaaa","role":"admin","access":true}
```

The plaintext is chosen to be AES-block aligned because the application does
not apply padding before encryption. The exploit then calls `forge()` for the
hex-encoded ciphertext and submits:

```json
{"command":"claim","ticket":"<forged ciphertext>","signature":"<forged signature>"}
```

The forged decrypted ticket satisfies the authorization check and the service
returns the flag.


## Usage

The script connects to the deployed service at `localhost:6969`, matching the
port configured in `challenge.yml` and `src/supervisord.conf`.

Install the dependencies used by `attack/sv.py`, then run:

```sh
pip install pwntools sympy libnum rsa pycryptodome
python3 attack/sv.py
```

The script prints the recovered AES key and leaves the connection interactive;
the final response contains the flag.
