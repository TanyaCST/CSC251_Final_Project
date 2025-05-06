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

# Port Scanning (Scan individual port)

def connect_scan(target_ip, port):
    # Make full connection to each OPEN port
    # If connection is established -> Port open
    # If connection fails -> Port closed
    ans, unans = sr(IP(dst = target_ip)/TCP(flags="S", dport=port), verbose=False)

    for sent, receive in ans:
        if receive.haslayer(TCP) and receive[TCP].flags == 0x12:
            # Send back a ACK response
            ack = IP(dst = target_ip)/TCP(flags="A", dport=port)
            send(ack, verbose=False)

            print(".", end="")
            return port
    
        else:
            print(".", end="")
            return


def syn_scan(target_ip, port):
    # No full connection
    # Send a SYN request and waiting for response
    # If response == SYN/ACK -> port open

    # Reference: https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning
    ans, unans = sr(IP(dst = target_ip)/TCP(flags="S", dport=port), verbose=False)

    for sent, receive in ans:
        if receive.haslayer(TCP) and receive[TCP].flags == 0x12:
            # Send back a RST response
            rst = IP(dst = target_ip)/TCP(flags="R", dport=port)
            send(rst, verbose=False)

            print(".", end="")
            return port
    
        else:
            print(".", end="")
            return     

def udp_scan(target_ip, port):
    
    ans = sr1(IP(dst=target_ip)/UDP(sport= port, dport=port), timeout=0.1, verbose=False)
    
    if ans is None:
        print(".", end="")
        return port
    elif ans.haslayer(ICMP):
        print(".", end="")
        return "Closed"




def main():
    # Reference: https://www.geeksforgeeks.org/command-line-arguments-in-python/ 
    # General Set up

    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("-mode", help="Scan hosts using TCP-connect scan, TCP-SYN scan, or UDP scan", choices=["connect", "syn", "udp"], required=True)
    parser.add_argument("-order", help="Scan ports in default sequential or random order", choices=["order, random"], default="order")
    parser.add_argument("-ports", help="Scan default known ports or all ports", choices=["all, known"], default="known")
    parser.add_argument("hostname", help="The host to scan")
    args = parser.parse_args()

    # Add Options

    print(args.hostname)
    
    # target = "glasgow.smith.edu"
    target = args.hostname
    host_ip = handle_hostname(target)
    # print(host_ip)

    ans = sr1(IP(dst=host_ip)/ICMP(), verbose=False)
    # print(ans)
    # print(unans)


    # ans.summary()

    if len(ans) !=0:
        pass
    else:
        print("Target unreachable")
        return
    

    # udp_scan(host_ip, 0)
    # ans = sr1( IP(dst=host_ip)/UDP(dport=123) )
    # print(ans)

    # print(udp_scan(host_ip, 80))
    # ans = sr1(IP(dst=host_ip)/UDP(dport=80), timeout=1)
    # print(ans)
    # print(udp_scan(host_ip, 123))

    udp_scan(host_ip, 80)
    udp_scan(host_ip, 123)
    if args.mode == "connect":
        connect_scan(host_ip, 80)
    print()
    # print(syn_scan(host_ip, 80))
    #ans = sr1(IP(dst = host_ip)/TCP(flags="S", dport=80))
    #print(ans)



if __name__ == "__main__":
    main()

