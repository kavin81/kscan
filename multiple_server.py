import socket
import threading

def handle_client(sock, address):
    print(f"[{address}] connected.")
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            print(f"[{address}] said: {data.decode()}")
            sock.sendall(b"ACK: " + data)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        sock.close()

def start_server_on_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    print(f"[SERVER] Listening on port {port}")
    while True:
        client_sock, addr = s.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock, addr))
        thread.start()

def main():
    ports = [8000, 8001, 8002]
    for port in ports:
        threading.Thread(target=start_server_on_port, args=(port,), daemon=True).start()
    input("Servers running... Press Enter to stop.\n")

if __name__ == "__main__":
    main()
