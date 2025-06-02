# Simple Portscanner

Simple portscanner using python that is built with [Scapy](https://pypi.org/project/scapy/), it will scan and check for ports
that are open.

### Requirments
```
Python 3+ 
Scapy
colorama
```

### Installation
*Linux users please check your respective distro for any specific installations of libraries*
```
Windows/Linux
pip install scapy
pip install colorama

Arch
yay -S python-scapy
yay -S python-colorama
```

### Usage
To scan for target port you would use -t or --target argument. The target can take IP and website addresses
```
sudo Portscanner.py -t 8.8.8.8

sudo Portsaanner.py -t www.google.com
```

To scan for a specific port you would use -p or --port argument. If there is no port specified it will default to checking the first
50 ports. *As of current state doing large scans can be very slow. It is best to check for a single port or a shorter range of scans*
```
sudo Portscanner.py -t 8.8.8.8 -p 53 

sudo Portscanner.py -t www.google.com -p 53
```

To scan a range of ports you would add a "-" in between the numbers
```
sudo Portscanner.py -t 8.8.8.8 -p 1-10

sudo Portscanner.py -t www.google.com -p 1-10
```

To scan multiple specific ports you use a comma, be sure to not put spaces between the comma.
```
sudo Portscanner.py -t 8.8.8.8 -p 22,53,23,8080

sudo Portscanner.py -t www.google.com -p 22,53,23,8080
```

### Disclamer 
***THIS IS INTENDED FOR EDUCATIONAL PURPOSES ONLY***. This project was written
to better understand of port scanning and networks.
