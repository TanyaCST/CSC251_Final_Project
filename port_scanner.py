#! usr/bin/env python

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress
import itertools
import sys
import argparse
import time

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

# Port Scanning (Scan individual port)

def connect_scan(target_ip, port):
    # Make full connection to each OPEN port
    # If connection is established -> Port open
    # If connection fails -> Port closed

    # ans, unans = sr(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)
    ans = sr1(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)

    # for sent, receive in ans:
    if ans != None:
        if ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            # Send back a ACK response
            ack = IP(dst = target_ip)/TCP(flags="A", dport=port)
            send(ack, verbose=False)

            print(".", end="")
            return port
    
        else:
            print(".", end="")
            return
    else:
        print(".", end="")
        return 


def syn_scan(target_ip, port):
    # No full connection
    # Send a SYN request and waiting for response
    # If response == SYN/ACK -> port open

    # Reference: https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning
    ans = sr1(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)

    if ans != None:
        if ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            # Send back a RST response
            rst = IP(dst = target_ip)/TCP(flags="R", dport=port)
            send(rst, verbose=False)

            print(".", end="")
            return port
    
        else:
            print(".", end="")
            return  
    else:
        print(".", end="")
        return  

# check for closed ports with udp scan
def udp_scan(target_ip, port):
    
    ans = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=1, verbose=False)
    # print(ans)

    if ans != None:
        if ans.haslayer(UDP):
            print(".", end="")
            return 
        # If port is closed, ie. sends back an ICMP error, return port. 
        elif ans.haslayer(ICMP):
            print(".", end="")
            return port
    else:
        print(".", end="")
        return 




def main():
    # Reference: https://www.geeksforgeeks.org/command-line-arguments-in-python/ 
    # General Set up

    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("-mode", help="Scan hosts using TCP-connect scan, TCP-SYN scan, or UDP scan", choices=["connect", "syn", "udp"], required=True)
    parser.add_argument("-order", help="Scan ports in default sequential or random order", choices=["order", "random"], default="order")
    parser.add_argument("-ports", help="Scan default known ports or all ports", choices=["all", "known"], default="known")
    parser.add_argument("hostname", help="The host to scan")
    args = parser.parse_args()

    port_list = []

    if args.ports == "all":
        port_list = list(range(0,65536))
    else:
        port_list = list(range(0,1024))

    print(args.hostname)
    
    # target = "glasgow.smith.edu"
    target = args.hostname
    host_ip = handle_hostname(target)
    # print(host_ip)
    ans = sr1(IP(dst=host_ip)/ICMP(), verbose=False)

    if len(ans) !=0:
        pass
    else:
        print("Target unreachable")
        return

    #values = [8443, 21, 22, 53, 80, 443, 8000]
    open_ports = []
    closed_ports = []

    if args.order == "random":
        random.shuffle(port_list)

    if args.mode == "connect":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(connect_scan, itertools.repeat(host_ip), port_list))

            for result in results:
                if result != None:
                    open_ports.append(result)

        print(open_ports)
        print()
    elif args.mode == "syn":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(syn_scan, itertools.repeat(host_ip), port_list))

            for result in results:
                if result != None:
                    open_ports.append(result)
                    
        print(open_ports)
        print()
    else:
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(udp_scan, itertools.repeat(host_ip), port_list))

            for result in results:
                if result != None:
                    closed_ports.append(result)

        print(closed_ports)
        print()




if __name__ == "__main__":
    main()

