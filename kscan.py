### file handling ###
import csv
import json

### threading ###
import threading
import socket
import concurrent.futures

### signal handling ###
import signal
import sys

### CLI ###
import argparse
from time import time
from typing import Any


__author__ = "Kavin & Kaushal"
__license__ = "MIT"
__version__ = "1.0.0"


# colorize the output
def color(text, color) -> str:
    COLOR_MAP = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "cyan": "36",
    }

    return f"\033[{COLOR_MAP[color]}m{text}\033[0m"


# parse CSV port data
def load_ports(csv_file) -> list[Any]:
    ports = []
    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) == 3:
                ports.append((row[0], row[1], int(row[2])))  # (service, protocol, port)
    return ports


# hostname -> IP
def resolve_host(host) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"[ERROR] Unable to resolve {color(host, 'red')}")
        sys.exit(1)


def scan_port(ip, service, protocol, port):
    with socket.socket(
        family=socket.AF_INET,
        proto=socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM,
    ) as s:
        s.settimeout(1)
        try:
            if protocol == "tcp":
                result = s.connect_ex((ip, port))
                if result == 0:
                    print(
                        f"[INFO] Open port discovered {color(port, 'green')}/{color(service, 'cyan')} via {color(protocol, 'blue')} on {color(ip, 'yellow')}"
                    )
                    return {"port": port, "service": service, "protocol": protocol}
            else:
                # UDP scan
                s.sendto(b"\x00", (ip, port))  # Send a dummy packet
                s.recvfrom(1024)  # Wait for a response
                print(
                    f"[INFO] Open port discovered {color(port, 'green')}/{color(service, 'cyan')} via {color(protocol, 'blue')} on {color(ip, 'yellow')}"
                )  # If no exception is raised, the port is open

                return {"port": port, "service": service, "protocol": protocol}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None


def save_results(open_ports, output_file, ip, start_time):
    end_time = time()
    print("-" * 50)
    print(f"[INFO] Scan complete for {color(ip, 'yellow')}.")
    print(
        f"[INFO] Found {color(len(open_ports), 'green')} open ports in {color(f'{end_time - start_time:.2f}s', 'cyan')}"
    )

    # if output flag is active
    if output_file:
        with open(output_file, "w") as f:
            json.dump(open_ports, f, indent=4)
        print(f"[INFO] Scan results saved to {color(output_file, 'blue')}")

    sys.exit(0)


def scan_target(ip, ports, output_file):

    print(f"Scanning {color(ip, 'yellow')} for open ports...")
    start_time = time()
    open_ports = []

    exiting = threading.Event()  # Event to signal the threads to exit
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=100
    )  # no context manager used due to signal handling

    # Handle `SIGINT`
    def signal_handler(sig, frame):
        print("\n[INFO] Scan interrupted. Saving partial results...")
        exiting.set()
        executor.shutdown(wait=False, cancel_futures=True)
        save_results(open_ports, output_file, ip, start_time)

    signal.signal(signal.SIGINT, signal_handler)

    # task submission to `executor`
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


def main():
    parser = argparse.ArgumentParser(description="Concurrent Port Scanner")
    parser.add_argument("target", help="IP or hostname to scan")
    parser.add_argument(
        "--output", help="Save results to a JSON file", type=str, default=None
    )
    args = parser.parse_args()

    csv_file = "output.csv"  # The generated CSV file with ports
    ports = load_ports(csv_file)
    target_ip = resolve_host(args.target)
    scan_target(target_ip, ports, args.output)


if __name__ == "__main__":
    main()
