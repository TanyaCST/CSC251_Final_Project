# CSC251 Final Project: TCP Port Scanner

## Files included
1. README.md
2. port_scanner.py

## Instructions: How to run this project
1. Open your terminal
2. Enter python3 port_scanner.py [-options] target
3. The target can be an IP address or a host name.
4. [-options] includes: 
   a. - mode [connect/syn/udp]: **Required argument** To scan hosts using TCP-connect scan, TCP-SYN scan, or UDP scan.
   b. - order [order/random]: **Optional argument** To scan ports in default sequential or random order.
   c. - ports [all/known]: **Optional argument** To scan default known ports or all ports.


## Example output
### TCP-Connect Scan

### TCP-SYN Scan

### UDP Scan

## Discussion
### The significant challenge we faced and how you solved it
Tanya: From my perspective, the most significant challenge for this project is to implement the scanning functions that generate corresponding open ports. While implement scanning functions, sometimes a TCP scanning method consider a UDP port open while it should be closed and vice versa. What we did was searching for the port number online to check whether it is a TCP port, a UDP port, or both. Then, we review our code for corresponding function and debug.

### Describe each person's contributions to the project
Tanya: We were working collaboratively in this project and it is difficult to specify our individual contributions. I wrote handle_hostname function, connect_scan function, and syn_scan function, modified udp_scan function a little bit, and combined all arguments together to return open ports. 
