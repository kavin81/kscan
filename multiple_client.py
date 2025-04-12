import socket
import threading

def connect_to_server(id, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", port))
        msg = f"Hello from client {id} to port {port}"
        s.sendall(msg.encode())
        reply = s.recv(1024)
        print(f"[Client {id}] got: {reply.decode()}")
    except Exception as e:
        print(f"[Client {id}] error: {e}")
    finally:
        s.close()

def main():
    ports = [8000, 8001, 8002]
    for i, port in enumerate(ports):
        threading.Thread(target=connect_to_server, args=(i, port)).start()

if __name__ == "__main__":
    main()
