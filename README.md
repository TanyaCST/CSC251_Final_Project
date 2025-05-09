# CSC251 Final Project: TCP Port Scanner

## Files included
1. README.md
2. port_scanner.py

## Instructions: How to run this project
1. Open your terminal, navigate to the correct folder containing port_scanner.py
2. Enter python3 port_scanner.py [-options] target
3. The target can be an IP address or a host name.
4. [-options] includes: 
   a. - mode [connect/syn/udp]: **Required argument** To scan hosts using TCP-connect scan, TCP-SYN scan, or UDP scan.
   b. - order [order/random]: **Optional argument** To scan ports in default sequential or random order.
   c. - ports [all/known]: **Optional argument** To scan default known ports or all ports.


## Example output
**Not including the approximately 1000 dots ( . ) produced before the shown output during each scan.**
### TCP-Connect Scan

**Example Input:**
```
$ python3 port_scanner.py -mode connect -order order -ports known glasgow.smith.edu
```

**Connect scan output:**
```
Starting port scan               at Thu May  8 16:10:02 2025
Interesting ports on 131.229.72.13:
Not shown: 1021 closed ports
PORT     STATE   SERVICE
22/tcp   open    ssh
80/tcp   open    http
443/tcp  open    https
scan done! 1 IP adress (1 host up) scanned in 16.54 seconds
```

### TCP-SYN Scan
**Example Input**
```
$ python3 port_scanner.py -mode syn glasgow.smith.edu
```

**SYN scan output:**
```
Starting port scan               at Thu May  8 16:11:47 2025
Interesting ports on 131.229.72.13:
Not shown: 1021 closed ports
PORT     STATE   SERVICE
22/tcp   open    ssh
80/tcp   open    http
443/tcp  open    https
scan done! 1 IP adress (1 host up) scanned in 14.24 seconds
```

### UDP Scan

**Example Input:**
```
$ port_scanner.py -mode udp -order random glasgow.smith.edu
```
**UDP scan output:**

```
Starting port scan               at Thu May  8 15:57:26 2025
Interesting ports on 131.229.72.13:
Not shown: 1019 open ports
PORT     STATE   SERVICE
443/udp  closed          https
21/udp   closed          ftp
80/udp   closed          http
22/udp   closed          ssh
53/udp   closed          domain
scan done! 1 IP adress (1 host up) scanned in 14.34 seconds
```

## Discussion
### The significant challenge we faced and how we solved it
Tanya: From my perspective, the most significant challenge for this project is to implement the scanning functions that generate corresponding open ports. While implementing the scanning functions, sometimes a TCP scanning method consider a UDP port open while it should be closed and vice versa. What we did was searching for the port number online to check whether it is a TCP port, a UDP port, or both. Then, we review our code for corresponding function and debug.

Lucy: We definitely faced some issues when encountering ports that were not behaving the way we expected, most specifically port 21. For whatever reason, on this host the port was not responsive to our original versions of the SYN and connect scans. We originally lacked a little bit of error handling for the edge case of if the server never responds to the original SYN packet from the host. We implemented timeouts in all of the sr1() calls for all of our scan functions, which allowed the scan to continue after reaching the 1 second timeout, and returned a closed port for the SYN and connect scan if no response was heard within that time on the port. We definitely were doing some cross checking with the services of some of these ports to better grasp if our handling of all ports was correct. I found it helpful to read a lot fo the scapy and socket documentation, as well as the Python documentation too. I sometimes feel less confident with pythan as a language, so its helpful to double check things and read more about the Python modules/methods/etc. while working. Specifically I was trying to debug why all of our dots were printing out as one at the end and that even when I tried running the scan methods sequentially in a for loop the output would come at the end, not when each function was called. I got to read up about the sys module and about 'flushing' the buffer so that each print statement appeared when it was called, not on completion of a loop (or in this case, threading). I found that very interesting and I personally love learning more about the mechanisms of why certain things work the way they do, so I enjoyed fixing that challenge as well and learning more about some Python defaults. 

### Describe each person's contributions to the project
Tanya: We were working collaboratively in this project and it is difficult to specify our individual contributions. I wrote handle_hostname function, connect_scan function, and syn_scan function, modified udp_scan function a little bit, and combined all arguments together to return open ports. 

Lucy: We both worked together to figure out the threading and debug the project together. I wrote the udp_scan function, modified the connect_scan and syn_scan functions, set up the argparse functionality, and did the output formatting and corrected the dot output. 