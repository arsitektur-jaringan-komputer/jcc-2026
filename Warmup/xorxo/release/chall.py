import os
import socketserver

from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

FLAG = os.environ.get("GZCTF_FLAG", r"JCC{placeholder}")

# To test locally, run this file then connect with "nc (or ncat) localhost 5000"

class ChallengeHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            key = os.urandom(4) * 9

            flag_bytes = FLAG.encode()

            c = strxor(flag_bytes, key[: len(flag_bytes)])

            self.wfile.write((c.hex() + "\n").encode())
        except Exception as e:
            try:
                self.wfile.write(f"error: {e}\n".encode())
            except Exception:
                pass


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    host = "0.0.0.0"
    port = 5000
    with ThreadingTCPServer((host, port), ChallengeHandler) as server:
        print(f"Listening on {host}:{port}")
        server.serve_forever()


if __name__ == "__main__":
    main()