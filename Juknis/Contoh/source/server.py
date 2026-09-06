import socket
import threading
import os

HOST = "0.0.0.0"
PORT = 8080
MESSAGE = os.getenv("GZCTF_FLAG", "Flag")


def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        conn.sendall(MESSAGE.encode())
    except Exception as e:
        print(f"[!] Error sending to {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Closed connection from {addr}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    main()