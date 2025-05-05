
from concurrent.futures import ThreadPoolExecutor
import socket
import ipaddress

# Check target
# If target is a hostname -> convert it to IP

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
        host_to_ip = socket.gethostbyname(target)
        return host_to_ip
    

# Check if IP is reachable
# Send a ping to the IP addr -> How to send a ping

# Port Scanning


def main():
    # General Set up
    target = input("What is your target?")
    print(handle_hostname(target))

if __name__ == "__main__":
    main()
