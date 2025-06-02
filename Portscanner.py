#! /usr/bin/env python
import argparse

from colorama import init
from scapy.all import *

# Colorama init
init(autoreset=True)


class PortScanner:
    def __init__(self, target_ip, ports):
        self.target_ip = target_ip
        self.ports = ports


def parse_ports(self, port_input):
    ports = set()
    for ports in port_input.split(","):
        if "-" in part:
            start_port, end_port = part.split("-")
            ports.update(range(int(start_port), int(end_port) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
