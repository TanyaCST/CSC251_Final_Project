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

            print(port)
            print(".", end="")
            return port
    
        else:
            print(port)
            print(".", end="")
            return
    else:
        print(port)
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

            print(port)
            print(".", end="")
            return port
    
        else:
            print(None)
            print(".", end="")
            return     

def udp_scan(target_ip, port):
    
    ans = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=1, verbose=False)
    print(ans)

    if ans is None:
        print(".", end="")
        return port
    elif ans.haslayer(ICMP):
        print(".", end="")
        return
    else:
        print(".", end="")
        return
    
    # if ans != None:
    #     if ans.haslayer(ICMP):
    #         print("Not none")
    #         print(".", end="")
    #         return
    # # elif ans == None:
    # #     print(port)
    # #     print(".", end="")
    # #     return port
    
    #     # if ans.haslayer(UDP):
    #     #     print(port)
    #     #     print(".", end="")
    #     #     return port
    # else:
    #     print(port)
    #     print(".", end="")
    #     return port


        




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
    print(host_ip)

    ans = sr1(IP(dst=host_ip)/ICMP(), verbose=False)
    # print(ans)
    # print(unans)


    # ans.summary()

    if len(ans) !=0:
        pass
    else:
        print("Target unreachable")
        return


    values = [8443, 21, 22, 53, 80, 443, 8000]
    open = []
    # host_list = host_ip*len(values)
    # print(host_list)

    ans = sr1(IP(dst=host_ip)/UDP(dport=8443), timeout=1)
    ans2 = sr1(IP(dst=host_ip)/UDP(dport=8000), timeout=1)
    udp_scan(host_ip, 8443)
    udp_scan(host_ip, 8000)

    # ans.summary()

    print(ans)
    print(ans2)

    


    if args.mode == "connect":
        with ThreadPoolExecutor(max_workers=len(values)) as exe:
            exe.map(connect_scan, itertools.repeat(host_ip), values)
        print()
    elif args.mode == "syn":
        with ThreadPoolExecutor(max_workers=len(values)) as exe:
            exe.map(syn_scan, itertools.repeat(host_ip), values)
        print()
    else:
        with ThreadPoolExecutor(max_workers=len(values)) as exe:
            results = list(exe.map(udp_scan, itertools.repeat(host_ip), values))

            for result in results:
                if result != None:
                    open.append(result)

            
        print()

    print(open)



if __name__ == "__main__":
    main()

