#! usr/bin/env python

from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress
import itertools
import sys
import argparse
import time

# Return IP address if target is an IP, if not convert hostname to IP and return
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

# Check if one specified port on the target IP address is open by establishing a full TCP connection on the port. Returns open port number.
def connect_scan(target_ip, port):
    # Reference: https://www.geeksforgeeks.org/how-to-disable-output-buffering-in-python/ 

    # Print a dot "." every time the function is called/every time a port is scanned. 
    # Clear python buffer so that a dot appears with every function call, not just all at the end
    print(".", end="")
    sys.stdout.flush()

    # Send packet to target IP and specified port with SYN flag and capture only the first answer received
    # Stop waiting for a response after 1 second. 
    ans = sr1(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)

    # If there is a response, check that it is an SYN/ACK packet from the server. If so, send back ACK to complete the connection and return the port number. 
    # If not a SYN/ACK packet or no response, return nothing. 
    if ans != None:
        if ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            # Send back a ACK response
            ack = IP(dst = target_ip)/TCP(flags="A", dport=port)
            send(ack, verbose=False)

            return port
        else:
            return
    else:
        return 

# Check if one specified port on the target IP is open by sending a SYN packet and then terminating the connection. Returns open port number.
def syn_scan(target_ip, port):
    # Reference: https://scapy.readthedocs.io/en/latest/usage.html#tcp-port-scanning

    # Print a dot "." every time the function is called/every time a port is scanned. 
    # Clear python buffer so that a dot appears with every function call, not just all at the end
    print(".", end="")
    sys.stdout.flush()

    # Send packet to target IP and specified port with SYN flag and capture only first the answer received
    # Stop waiting for a response after 1 second. 
    ans = sr1(IP(dst = target_ip)/TCP(flags="S", dport=port), timeout=1, verbose=False)

    # If there is a response, check that it is an SYN/ACK packet from the server. If it is, send back an RST to terminate the connection and return the port number. 
    # If not a SYN/ACK packet or no response, return nothing. 
    if ans != None:
        if ans.haslayer(TCP) and ans[TCP].flags == 0x12:
            rst = IP(dst = target_ip)/TCP(flags="R", dport=port)
            send(rst, verbose=False)
            return port
    
        else:
            return  
    else:
        return  

# Check if one specified port on the target IP is CLOSED by sending a UDP packet to the port and returns closed port number.
def udp_scan(target_ip, port):
    # Reference: https://scapy.readthedocs.io/en/latest/usage.html#udp-ping 

    # Print a dot "." every time the function is called/every time a port is scanned. 
    # Clear python buffer so that a dot appears with every function call, not just all at the end
    print(".", end="")
    sys.stdout.flush()

    # Send a UDP packet to the target IP and specified port and capture only the first answer received. 
    ans = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=1, verbose=False)

    # If you recieve an answer, check if it is a UDP response. If it is or if port did not respoond, the ports are likely open. Return nothing.
    # Keep track of closed UDP ports by returning port if the response has ICMP unreachable error (ICMP layer). 
    if ans != None:
        if ans.haslayer(UDP):
            return 
        # If port is closed, ie. sends back an ICMP error, return port. 
        elif ans.haslayer(ICMP):
            return port
    else:
        return 




def main():
    # Reference: https://www.geeksforgeeks.org/command-line-arguments-in-python/ 

    # Initialize the parser and add arguments and options for -mode, -order, -ports and the hostname. Set default values of -order and -ports and make mode required. 
    # Add description and details for the --help flag to show. Parse the inputted args
    parser = argparse.ArgumentParser(description="TCP/UDP port scanner")
    parser.add_argument("-mode", help="Scan hosts using TCP-Connect scan, TCP-SYN scan, or UDP scan", choices=["connect", "syn", "udp"], required=True)
    parser.add_argument("-order", help="Scan ports in default sequential or random order", choices=["order", "random"], default="order")
    parser.add_argument("-ports", help="Scan default known ports or all ports", choices=["all", "known"], default="known")
    parser.add_argument("hostname", help="The host to scan")
    args = parser.parse_args()

    # lists to keep track of which ports scanned, and where to store the open/closed ports for the different scans.
    port_list = []
    open_ports = []
    closed_ports = []

    # Based on chosen options for -order and -ports, update the number of ports to be scanned and shuffle port numbers if random. 
    if args.ports == "all":
        port_list = list(range(0,65536))
    else:
        port_list = list(range(0,1024))

    if args.order == "random":
        random.shuffle(port_list)

    # Resolve the inputted hostname to IP address if not already 
    target = args.hostname
    host_ip = handle_hostname(target)

    # Ping the target host with an ICMP packet, return and print Target unreachable if no response.
    ans = sr1(IP(dst=host_ip)/ICMP(), timeout=1, verbose=False)
    if len(ans) !=0:
        pass
    else:
        print("Target Unreachable")
        return

    # Record the time the scan is beginning, initialize the end_time to 0 (to be updated on completion of the scan). 
    start_time = time.time()
    end_time = 0

    # Based on the user's option for the -mode argument, run the corresponding scan method on max as many threads as there are ports to be scanned
    # Record the time at the end of scanning all ports
    # For TCP-connect and TCP-SYN scan, record the open ports as the ports that are not none (ie function returned their open port number)
    # For UDP scan, record closed ports (ie function returned the closed port number)
    if args.mode == "connect":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(connect_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    open_ports.append(result)

        print()
    elif args.mode == "syn":
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(syn_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    open_ports.append(result)
                    
        print()
    else:
        with ThreadPoolExecutor(max_workers=len(port_list)) as exe:
            results = list(exe.map(udp_scan, itertools.repeat(host_ip), port_list))
            end_time = time.time()

            for result in results:
                if result != None:
                    closed_ports.append(result)

        print()

    # Format scan output. Get current start time. 
    print(f"Starting port scan \t \t at {time.ctime(start_time)}")
    print(f"Interesting ports on {host_ip}:")

    # Update variables in output depending on the -mode option chosen. Print out corresponding text. 
    port_mode = "tcp"
    port_status = "open"
    if args.mode == "udp":
        port_mode = "udp"
        port_status = "closed"
        print(f"Not shown: {len(port_list) - len(closed_ports)} open ports")
    else:
        print(f"Not shown: {len(port_list) - len(open_ports)} closed ports")

    print(f"PORT \t STATE \t SERVICE")

    # For each port in open/closed port lists (depending on TCP vs UDP scans), print the status and service.
    if open_ports:
        for port in open_ports:
            service = socket.getservbyport(port)

            if len(str(port)) == 3:
                print(f"{port}/{port_mode}  {port_status} \t {service}")
            elif len(str(port)) == 4:
                print(f"{port}/{port_mode} {port_status} \t {service}")
            elif len(str(port)) >= 5:
                print(f"{port}/{port_mode}{port_status} \t {service}")
            else:
                print(f"{port}/{port_mode} \t {port_status} \t {service}")
    else:
        for port in closed_ports:
            service = socket.getservbyport(port)

            if len(str(port)) == 3:
                print(f"{port}/{port_mode}  {port_status} \t {service}")
            elif len(str(port)) == 4:
                print(f"{port}/{port_mode} {port_status} \t {service}")
            elif len(str(port)) >= 5:
                print(f"{port}/{port_mode}{port_status} \t {service}")
            else:
                print(f"{port}/{port_mode} \t {port_status} \t {service}")
    

    # Print time scan took
    print(f"scan done! 1 IP adress (1 host up) scanned in {(end_time - start_time):.2f} seconds")



if __name__ == "__main__":
    main()

