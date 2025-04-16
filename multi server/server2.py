# server1.py
import socket
import threading

def handle_client(sock, addr):
    print(f"[Server1] {addr} connected.")
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            print(f"[Server1] {addr} said: {data.decode()}")
            sock.sendall(b"[Server1 ACK] " + data)
    except Exception as e:
        print(f"[Server1 ERROR] {e}")
    finally:
        sock.close()

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8001))
    s.listen()
    print("[Server1] Listening on port 8001")
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    main()
