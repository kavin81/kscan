import socket
import ssl
import os
import threading
import datetime
import sys

HTTP_PORT = 8080
HTTPS_PORT = 8443
SERVER_CERT = "./kserver/server.crt"
SERVER_KEY = "./kserver/server.key"


def log_request(client_addr, request_type, path, protocol):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {client_addr[0]}:{client_addr[1]} - {protocol} - {request_type} {path}"
    print(log_message)

    with open("server.log", "a") as log_file:
        log_file.write(log_message + "\n")


def parse_request(request_data):
    request_lines = request_data.split("\r\n")
    if not request_lines:
        return None, None

    # Extract request method and path
    request_line = request_lines[0]
    method, path, _ = request_line.split(" ", 2)

    return method, path


def generate_response(status_code, content_type, content):
    """Generate an HTTP response with the given status code and content"""
    status_messages = {200: "OK", 404: "Not Found", 500: "Internal Server Error"}

    status_message = status_messages.get(status_code, "Unknown")
    response = f"HTTP/1.1 {status_code} {status_message}\r\n"
    response += f"Content-Type: {content_type}\r\n"
    response += f"Content-Length: {len(content)}\r\n"
    response += "Connection: close\r\n"
    response += "\r\n"

    return response.encode("utf-8") + content


def serve_file(path):
    if path == "/":
        path = "/index.html"

    file_path = os.path.join(os.path.dirname(__file__), path[1:])

    try:
        with open(file_path, "rb") as file:
            content = file.read()

        _, ext = os.path.splitext(file_path)
        content_type = "text/html"

        return generate_response(200, content_type, content)
    except FileNotFoundError:
        not_found = b"<html><body><h1>404 Not Found</h1></body></html>"
        return generate_response(404, "text/html", not_found)
    except Exception as e:
        error_message = f"<html><body><h1>500 Internal Server Error</h1><p>{str(e)}</p></body></html>"
        return generate_response(500, "text/html", error_message.encode("utf-8"))


def handle_client(client_socket, client_addr, protocol):
    """Handle a client connection"""
    try:
        # Receive the request data
        request_data = client_socket.recv(4096).decode("utf-8")
        if not request_data:
            return

        # Parse the request
        method, path = parse_request(request_data)

        if not method or not path:
            return

        # Log the request
        log_request(client_addr, method, path, protocol)

        # Serve the requested file
        response = serve_file(path)

        # Send the response
        client_socket.sendall(response)
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()


def start_http_server():
    """Start the HTTP server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(("", HTTP_PORT))
        server_socket.listen(5)
        print(f"HTTP server started on port {HTTP_PORT}")

        while True:
            client_socket, client_addr = server_socket.accept()
            # Handle client in a separate thread
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, client_addr, "HTTP")
            )
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Error in HTTP server: {e}")
    finally:
        server_socket.close()


def start_https_server():
    # Check if certificate and key files exist
    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
        print(f"SSL certificate ({SERVER_CERT}) and/or key ({SERVER_KEY}) not found.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Wrap the socket with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    try:
        server_socket.bind(("", HTTPS_PORT))
        server_socket.listen(5)
        https_socket = context.wrap_socket(server_socket, server_side=True)

        print(f"HTTPS server started on port {HTTPS_PORT}")

        while True:
            client_socket, client_addr = https_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, client_addr, "HTTPS")
            )
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Error in HTTPS server: {e}")
    finally:
        server_socket.close()


def main():
    # Create a default index.html if it doesn't exist
    if not os.path.exists("index.html"):
        with open("index.html", "w") as f:
            f.write(
                "<html><body><h1>Welcome to the Python Socket Server</h1></body></html>"
            )

    # Start HTTP and HTTPS servers in separate threads
    http_thread = threading.Thread(target=start_http_server)
    http_thread.daemon = True
    http_thread.start()

    https_thread = threading.Thread(target=start_https_server)
    https_thread.daemon = True
    https_thread.start()

    try:
        # Keep the main thread alive
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\nShutting down the server...")
        sys.exit(0)


if __name__ == "__main__":
    main()
