#! usr/bin/env python

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress
# import arguments
import sys
import argparse

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
    # Reference: https://www.geeksforgeeks.org/command-line-arguments-in-python/ 
    # General Set up

    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("hostname", help="The name of the file to process")
    args = parser.parse_args()

    print(args.hostname)
    
    # target = "glasgow.smith.edu"
    target = args.hostname
    host_ip = handle_hostname(target)
    print(host_ip)

    ans, unans = sr(IP(dst=host_ip)/ICMP())
    print(ans)
    print(unans)

    if len(ans) !=1:
        pass
    else:
        print("Target unreachable")
        return


if __name__ == "__main__":
    main()

