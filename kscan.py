### File Handling ###
import csv
import json

### Threading ###
import threading
import socket
import ssl
import concurrent.futures

### Signal Handling ###
import signal
import sys

### CLI ###
import argparse
from time import time
from typing import Any

### GUI ###
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

__author__ = "Kavin & Kaushal"
__license__ = "MIT"
__version__ = "1.0.1"

# Colorize output for better visibility
def color(text, color) -> str:
    COLOR_MAP = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "cyan": "36",
    }
    return f"\033[{COLOR_MAP[color]}m{text}\033[0m"

# Load CSV port data
def load_ports(csv_file) -> list[Any]:
    ports = []
    try:
        with open(csv_file, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 3:
                    ports.append((row[0], row[1], int(row[2])))  # (service, protocol, port)
        return ports
    except FileNotFoundError:
        print(f"[ERROR] CSV file '{csv_file}' not found!")
        sys.exit(1)

# Resolve hostname to IP
def resolve_host(host) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[ERROR] Unable to resolve {color(host, 'red')}")
        sys.exit(1)

# Scan a single port with SSL detection
def scan_port(ip, service, protocol, port):
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    proto_type = socket.IPPROTO_TCP if protocol == "tcp" else socket.IPPROTO_UDP

    with socket.socket(socket.AF_INET, sock_type, proto_type) as s:
        s.settimeout(1)
        try:
            if protocol == "tcp":
                result = s.connect_ex((ip, port))
                if result == 0:
                    ssl_supported = False
                    try:
                        context = ssl.create_default_context()
                        with context.wrap_socket(s, server_hostname=ip) as ssl_sock:
                            ssl_sock.settimeout(1)
                            ssl_sock.do_handshake()
                            ssl_supported = True
                    except (ssl.SSLError, ssl.SSLWantReadError, ssl.SSLWantWriteError, ConnectionResetError, OSError):
                        pass

                    msg = f"[INFO] Open port discovered {color(port, 'green')}/{color(service, 'cyan')} via {color(protocol, 'blue')} on {color(ip, 'yellow')}"
                    if ssl_supported:
                        msg += f" ({color('SSL', 'red')})"
                    print(msg)

                    return {
                        "port": port,
                        "service": service,
                        "protocol": protocol,
                        "ssl": ssl_supported,
                    }

            else:
                s.sendto(b"\x00", (ip, port))
                s.recvfrom(1024)
                print(
                    f"[INFO] Open port discovered {color(port, 'green')}/{color(service, 'cyan')} via {color(protocol, 'blue')} on {color(ip, 'yellow')}"
                )
                return {"port": port, "service": service, "protocol": protocol, "ssl": False}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

# Save scan results to a JSON file
def save_results(open_ports, output_file, ip, start_time):
    end_time = time()
    print("-" * 50)
    print(f"[INFO] Scan complete for {color(ip, 'yellow')}.")
    print(
        f"[INFO] Found {color(len(open_ports), 'green')} open ports in {color(f'{end_time - start_time:.2f}s', 'cyan')}"
    )

    if output_file:
        with open(output_file, "w") as f:
            json.dump(open_ports, f, indent=4)
        print(f"[INFO] Scan results saved to {color(output_file, 'blue')}")

    sys.exit(0)

# Scan a target for open ports
def scan_target(ip, ports, output_file):
    print(f"Scanning {color(ip, 'yellow')} for open ports...")
    start_time = time()
    open_ports = []

    exiting = threading.Event()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)

    def signal_handler(sig, frame):
        print("\n[INFO] Scan interrupted. Saving partial results...")
        exiting.set()
        executor.shutdown(wait=True, cancel_futures=False)
        save_results(open_ports, output_file, ip, start_time)

    signal.signal(signal.SIGINT, signal_handler)

    futures = [
        executor.submit(scan_port, ip, service, protocol, port)
        for service, protocol, port in ports
    ]

    try:
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    save_results(open_ports, output_file, ip, start_time)

# GUI Launch
def launch_gui():
    def start_scan():
        target = entry_target.get().strip()
        output_file = entry_output.get().strip()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return

        try:
            target_ip = resolve_host(target)
            ports = load_ports("output.csv")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        text_output.delete(1.0, tk.END)

        def gui_scan():
            start_time = time()
            open_ports = []
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)

            def update_text(message):
                text_output.insert(tk.END, message + "\n")
                text_output.see(tk.END)

            def scan_and_update(service, protocol, port):
                result = scan_port(target_ip, service, protocol, port)
                if result:
                    open_ports.append(result)
                    ssl_note = " (SSL)" if result.get("ssl") else ""
                    update_text(
                        f"Open port: {port}/{service} via {protocol} on {target_ip}{ssl_note}"
                    )

            futures = [
                executor.submit(scan_and_update, service, protocol, port)
                for service, protocol, port in ports
            ]

            concurrent.futures.wait(futures)
            executor.shutdown()

            end_time = time()
            update_text("-" * 40)
            update_text(f"Scan complete for {target_ip}")
            update_text(f"Found {len(open_ports)} open ports in {end_time - start_time:.2f}s")

            if output_file:
                with open(output_file, "w") as f:
                    json.dump(open_ports, f, indent=4)
                update_text(f"Results saved to {output_file}")

        threading.Thread(target=gui_scan, daemon=True).start()

    root = tk.Tk()
    root.title("Concurrent Port Scanner")

    frame = ttk.Frame(root, padding=10)
    frame.grid(row=0, column=0, sticky="NSEW")

    ttk.Label(frame, text="Target IP / Hostname:").grid(row=0, column=0, sticky="W")
    entry_target = ttk.Entry(frame, width=40)
    entry_target.grid(row=0, column=1, pady=5)

    ttk.Label(frame, text="Output File (Optional):").grid(row=1, column=0, sticky="W")
    entry_output = ttk.Entry(frame, width=40)
    entry_output.grid(row=1, column=1, pady=5)

    btn_start = ttk.Button(frame, text="Start Scan", command=start_scan)
    btn_start.grid(row=2, column=0, columnspan=2, pady=10)

    text_output = ScrolledText(frame, width=70, height=20)
    text_output.grid(row=3, column=0, columnspan=2)

    root.mainloop()

# CLI entry point
def main():
    parser = argparse.ArgumentParser(description="Concurrent Port Scanner")
    parser.add_argument("target", help="IP or hostname to scan")
    parser.add_argument("--output", help="Save results to a JSON file", type=str, default=None)
    args = parser.parse_args()

    csv_file = "output.csv"
    ports = load_ports(csv_file)
    target_ip = resolve_host(args.target)
    scan_target(target_ip, ports, args.output)

# Run GUI if executed directly
if __name__ == "__main__":
    launch_gui()
