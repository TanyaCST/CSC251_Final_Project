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

    print(".", end="")
    # Reference: https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning
    ans = sr1(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)


    if ans != None:
        if ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            # Send back a RST response
            rst = IP(dst = target_ip)/TCP(flags="R", dport=port)
            send(rst, verbose=False)
            return port
    
        else:
            return  
    else:
        return  

# check for closed ports with udp scan
def udp_scan(target_ip, port):
    print(".", end="")
    
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

    start_time = time.time()
    end_time = 0
    # print(f"Starting port scan \t \t at {time.ctime(start_time)}")

    if args.ports == "all":
        port_list = list(range(0,65536))
    else:
        port_list = list(range(0,1024))

    if args.order == "random":
        random.shuffle(port_list)

    target = args.hostname
    host_ip = handle_hostname(target)

    # Ping the target host with an ICMP packet, return and print Target unreachable if no response
    ans = sr1(IP(dst=host_ip)/ICMP(), verbose=False)
    if len(ans) !=0:
        pass
    else:
        print("Target unreachable")
        return

    open_ports = []
    closed_ports = []

    if args.mode == "connect":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(connect_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    open_ports.append(result)

        print()
        print(open_ports)
    elif args.mode == "syn":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(syn_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    open_ports.append(result)
                    
        print()
        print(open_ports)
    else:
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(udp_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    closed_ports.append(result)

        print()
        print(closed_ports)

    
    # socket resolve server from port 
    print(f"Starting port scan \t \t at {time.ctime(start_time)}")
    print(f"Interesting ports on {host_ip}:")

    port_mode = "tcp"
    if args.mode == "udp":
        port_mode = "udp"
        print(f"Not shown: {len(port_list) - len(closed_ports)} open|filtered ports")
    else:
        print(f"Not shown: {len(port_list) - len(open_ports)} closed ports")

    print(f"PORT \t STATE \t SERVICE")


    if open_ports:
        for port in open_ports:
            service = socket.getservbyport(port)
            print(f"{port}/{port_mode} \t open \t {service}")
    else:
        for port in closed_ports:
            print(f"{port}/{port_mode} \t closed \t {service}")

    print(f"scan done! 1 IP adress (1 host up) scanned in {end_time - start_time} seconds")





if __name__ == "__main__":
    main()

