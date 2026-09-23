# Defense

This document maps each vulnerable code path to a concrete remediation for the
Playground challenge.

The JSON request format, ticket fields, command flow, and return messages must
remain compatible with `src/app.py`.

## 1. Patch RSA signature forgery in `app.py`

### Vulnerable code

```python
rsakey = RSA.generate(2048, e=3)

def verify(message, signature, public_key):
	try:
		rsa.verify(message, signature, public_key)
		return True
	except rsa.VerificationError:
		return False
```

The low public exponent makes the cube-root forgery in `attack/sv.py`
practical when the PKCS#1 v1.5 encoded message is not checked strictly. The
forged signature is accepted for attacker-controlled ciphertext and the
application decrypts it during `claim`.

### Minimum parameter patch (low priority)

Change only the public exponent:

```python
rsakey = RSA.generate(2048, e=65537)
```

This is a **minimal patch**. It prevents the specific low-exponent attack used
by this challenge, but it does not fix a permissive signature verification
implementation. Changing only this parameter receives the minimum patch
priority.

### Safer design: correct signature verification (high priority)

Use a strict PKCS#1 v1.5 verifier and keep signature verification mandatory:

```python
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def verify(message, signature, public_key):
	try:
		pkcs1_15.verify(public_key, SHA256.new(message), signature)
		return True
	except (ValueError, TypeError):
		return False
```

The complete DigestInfo and padding are verified. Modified tickets and forged
signatures are rejected with the unchanged `Invalid signature` message.
This is the preferred RSA fix and receives higher priority than changing the
key parameter alone. Keeping `e=3` while making verification strict fixes the
verification vulnerability at its root; changing the exponent alone does not.

## 2. Patch AES-CBC key reuse as IV in `app.py`

### Vulnerable code

```python
cipher = AES.new(KEY, AES.MODE_CBC, KEY)
```

Using the encryption key as the IV allows an attacker who can submit chosen
ciphertext for decryption to recover the key with two CBC plaintext blocks:

```text
P1 = AES_decrypt(C1) XOR KEY
P2 = AES_decrypt(C2) XOR C1
```

Choosing `C1 = C2 = 0` gives `KEY = P1 XOR P2`. The RSA forgery supplies the
chosen ciphertext and exposes the decrypted blocks in `ticket confirmation:`.

### Patch (high priority)

Generate a fresh IV for every encryption, prefix it to the ciphertext, and
use authenticated integrity protection where possible. The current patch
keeps the existing ticket fields and uses strict padding validation:

```python
iv = os.urandom(AES.block_size)
cipher = AES.new(KEY, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
return (iv + ciphertext).hex()
```

`decrypt()` extracts the prefixed IV, validates PKCS#7 padding, and returns the
original ticket bytes. The signature covers the complete IV+ciphertext value,
so changing either part is rejected before decryption. This is a
**high-priority** patch because it removes the key-recovery primitive itself.

## 3. Preserve the application contract

The patch must preserve the original JSON request shapes:

```json
{"command":"get","user":"<user>"}
```

```json
{"command":"claim","ticket":"<ticket>","signature":"<signature>"}
```

The ticket remains an object with exactly `ticket` and `signature` fields. The
decrypted ticket retains `timestamp`, `user`, `role`, and `access`. These
messages must remain unchanged:

- `Invalid request`
- `Invalid command`
- `need arguments`
- `Invalid signature`
- `ticket confirmation:`
- `not for you, sorry`
- `flag is not ready yet`
- `save your flag: <flag>`
- `Something went wrong, please try again.`

## Regression tests

The defense should verify:

1. A normal `get` request returns a decryptable guest ticket.
2. A normal `claim` request accepts the ticket and returns `not for you, sorry`.
3. A changed ticket or signature returns `Invalid signature`.
4. The cube-root forged signature from `attack/sv.py` is rejected.
5. A chosen two-block ciphertext cannot be decrypted to recover the AES key.
6. Missing fields and malformed JSON preserve the original error messages.
7. The ticket and decrypted ticket field structures remain unchanged.

## Full implementation

The complete remediation applies strict RSA signature verification, uses a
separate random AES-CBC IV with padding validation, and preserves the original
application contract. The deployment remains compatible with the TCP service
exposed on port `6969` through `socat`.
