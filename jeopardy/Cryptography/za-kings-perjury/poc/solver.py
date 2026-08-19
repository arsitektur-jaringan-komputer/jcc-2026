import socket
import re
import secrets
import sys
import time


def full_recv(sock, timeout=5):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="replace")


def parse_params(welcome_text):
    Y = int(re.search(r"public key is (\d+)", welcome_text).group(1))
    g = int(re.search(r"g is (\d+)", welcome_text).group(1))
    p = int(re.search(r"modulus\) is (\d+)", welcome_text).group(1))
    return g, p, Y


def attempt(host, port, verbose=True):
    s = socket.create_connection((host, port), timeout=10)
    transcript = []

    welcome = full_recv(s)
    transcript.append(welcome)
    g, p, Y = parse_params(welcome)

    e_guess = secrets.randbelow(5) + 1
    z = secrets.randbelow(p - 2) + 1  

    Y_inv = pow(Y, -1, p)
    R = (pow(g, z, p) * pow(Y_inv, e_guess, p)) % p

    s.sendall((str(R) + "\n").encode())

    challenge_msg = full_recv(s)
    transcript.append(challenge_msg)
    m = re.search(r"e = (\d+)", challenge_msg)
    if not m:
        s.close()
        return False, None, "\n".join(transcript) + "\n[!] couldn't parse challenge"

    real_e = int(m.group(1))

    s.sendall((str(z) + "\n").encode())

    result = full_recv(s)
    transcript.append(result)
    s.close()

    if verbose:
        match = "MATCH" if real_e == e_guess else "no match"
        print(f"    guessed e={e_guess}, real e={real_e} ({match})")

    flag_match = re.search(r"(JCC\{[^}]*\})", result)
    if flag_match:
        return True, flag_match.group(1), "\n".join(transcript)
    return False, None, "\n".join(transcript)


def solve(host, port, max_attempts=200):
    print(f"[*] Target: {host}:{port}")
    print("[*] Exploiting tiny challenge space (e in 1..5) -- no secret key needed\n")

    for i in range(1, max_attempts + 1):
        print(f"[*] Attempt {i}...")
        try:
            success, flag, transcript = attempt(host, port)
        except (ConnectionError, OSError, socket.timeout) as exc:
            print(f"    connection error: {exc}, retrying...")
            time.sleep(0.5)
            continue

        if success:
            print(f"\n[+] Success after {i} attempt(s)!")
            print(f"[+] FLAG: {flag}")
            return flag

    print(f"[-] Failed to solve after {max_attempts} attempts (very unlucky, try again).")
    return None


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} HOST PORT")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    solve(host, port)


if __name__ == "__main__":
    main()