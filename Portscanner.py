#! /usr/bin/env python
import argparse

from colorama import Fore, init
from scapy.all import IP, TCP, sr

# Colorama init
init(autoreset=True)


class PortScanner:
    def __init__(self, target_ip, ports):
        self.target_ip = target_ip
        self.ports = ports

    # Proccess a range of ports inputted by the user
    def parse_ports(self, port_input):
        ports = set()
        for part in port_input.split(","):
            if "-" in part:
                start_port, end_port = part.split("-")
                ports.update(range(int(start_port), int(end_port) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    # Scans the ports of the target IP
    def scan(self):
        print(Fore.YELLOW + f"Scanning {self.target_ip} for open ports..")
        for port in self.ports:
            response = sr(
                IP(dst=self.target_ip) / TCP(dport=port, flags="S"),
                timeout=1,
                verbose=0,
            )[0]
            if response:
                for sent, recieved in response:
                    if (
                        recieved.haslayer(TCP) and recieved[TCP].flags == 18
                    ):  # SYN-ACK OPEN PORT
                        print(Fore.GREEN + f"Port {port} is open...")
                    elif (
                        recieved.haslayer(TCP) and recieved[TCP].flags == 20
                    ):  # SYN-ACK CLOSED PORT
                        print(Fore.RED + f"Port {port} is closed...")
        else:
            print(Fore.BLUE + f"Port {port} is filtered or no response")


def main():
    parser = argparse.ArgumentParser(description="TCP port scan")
    parser.add_argument(
        "--target", "-t", type=str, required=True, help="Target IP adress or hostname"
    )
    parser.add_argument(
        "--port",
        "-p",
        type=str,
        help="Lists of ports to scan. Default scans first 50 ports",
    )

    args = parser.parse_args()

    if args.port:
        scanner = PortScanner(
            args.target, PortScanner(args.target, []).parse_ports(args.port)
        )
    else:
        default_ports = range(1, 50)
        scanner = PortScanner(args.target, default_ports)

    scanner.scan()


if __name__ == "__main__":
    main()
