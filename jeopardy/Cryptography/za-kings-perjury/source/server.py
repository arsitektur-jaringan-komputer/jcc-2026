import socket
import socketserver
import secrets
import traceback

P = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
G = 2
Y = 274874358782026484564369405979564522613983446581679468997993914416001091024634792450442978317525604196013158474955705669603032114771850959023049592856173977350555584182625570527217916362857361336764201600924815750632361824270928904286642599862707606475587398526004432615048851120537662786015761249339901357982193937490881757851531756303297251594435556980344294001510286397764172932528669542803585367014739212775402816424416942165054056309939880767320250514544915384277108824782598150158590100774614090515471199314202453266626470336947587956903822809957110421269343530973291287106459718705

with open("flag.txt", "r") as file:
    FLAG = file.read().strip()

HOST = "0.0.0.0"
PORT = 6000
CONN_TIMEOUT = 30 


class SchnorrHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.request.settimeout(CONN_TIMEOUT)
        self.rfile = self.request.makefile("rb", buffering=0)

    def send(self, text: str):
        self.request.sendall(text.encode())

    def recv_line(self):
        try:
            line = self.rfile.readline()
        except (socket.timeout, ConnectionError, OSError):
            return None
        if not line:
            return None
        return line.decode(errors="replace").strip()

    def recv_int(self):
        line = self.recv_line()
        if line is None:
            return None
        try:
            return int(line)
        except ValueError:
            return None

    def fail(self, reason_shown_to_user=True):
        if reason_shown_to_user:
            self.send("Hmm.. that doesnt sound right.. Bye bye!\n")

    def handle(self):
        try:
            self.run_protocol()
        except (ConnectionError, OSError, socket.timeout):
            pass
        except Exception:
            traceback.print_exc()

    def run_protocol(self):
        welcome = (
            "welcome! \n"
            f"so your public key is {Y}, that means you know the secret key? \n"
            "fantastic! let's run a standard Schnorr's Protocol. send me your "
            f"commitment R = g^r mod p, where g is {G} and p (modulus) is {P}, "
            "and r is any number you choose!\n"
        )
        self.send(welcome)

        R = self.recv_int()
        if R is None:
            self.fail()
            return
        R = R % P

        e = secrets.randbelow(5) + 1  
        self.send(
            f"Excellent! here's my challenge number: e = {e}. "
            "Compute Z = r + e*x (mod p), where x is your secret key, then send me Z!\n"
        )

        Z = self.recv_int()
        if Z is None:
            self.fail()
            return

        self.send("Okay I'm going to verify this first...\n")

        lhs = pow(G, Z, P)
        rhs = (R * pow(Y, e, P)) % P

        if lhs == rhs:
            self.send(f"I'm convinced! here's your flag: {FLAG}\n")
        else:
            self.fail()

    def finish(self):
        try:
            self.rfile.close()
        except Exception:
            pass
        try:
            self.request.close()
        except Exception:
            pass


class ThreadingTCPServerReuse(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    with ThreadingTCPServerReuse((HOST, PORT), SchnorrHandler) as server:
        print(f"listening on {HOST}:{PORT}")
        server.serve_forever()


if __name__ == "__main__":
    main()