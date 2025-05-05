#! usr/bin/env python

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress

# Check target

def handle_hostname(target: str):
    # Reference: https://stackoverflow.com/questions/36138209/python-socket-gethostname
    #            https://docs.python.org/3/library/socket.html#socket.gethostbyname
    #            https://docs.python.org/3/library/ipaddress.html
    try:
        # If target is a IP -> return the IP
        ipaddress.ip_address(target)
        return target
    
    except ValueError:
        # If target is a hostname -> convert it to IP and return the IP
        try:
            host_to_ip = socket.gethostbyname(target)
            return host_to_ip
        
        except ValueError:
            return "Invalid Hostname"

# Port Scanning

def connect_scan(target_ip, port):
    # Make full connection to each OPEN port
    # If connection is established -> Port open
    # If connection fails -> Port closed
    pass

# The list of ports will be all ports or well-known ports from argparse
def syn_scan(target_ip, ports):
    # No full connection
    # Send a SYN request and waiting for response
    # If response == SYN/ACK -> port open
    pass

def udp_scan():
    pass


def main():
    target = "glasgow.smith.edu"
    

if __name__ == "__main__":
    main()

