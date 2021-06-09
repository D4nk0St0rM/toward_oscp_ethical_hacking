### Scanning


#### netcat
```
nc -z -v {host-name-here} {port-range-here}
nc -z -v host-name-here ssh
nc -z -v host-name-here 22
nc -w 1 -z -v server-name-here port-Number-here
 ```
 
#### scan 1 to 1023 ports
```
nc -zv host-name-here 1-1023
```

#### Ping sweep
```
for i in {1..254}; do ping -c 1 -W 1 10.1.1.$i | grep 'from'; done

for i in `seq 1 255`; do ping -c 1 10.10.10.$i | tr \\n ' ' | awk '/1 received/ {print $2}'; done

(prefix="10.59.21" && for i in `seq 254`; do (sleep 0.5 && ping -c1 -w1 $prefix.$i &> /dev/null && arp -n | awk ' /'$prefix'.'$i' / { print $1 " " $3 } ') & done; wait)

prefix="169.254" && for i in {0..254}; do echo $prefix.$i/8; for j in {1..254}; do sh -c "ping -m 1 -c 1 -t 1 $prefix.$i.$j | grep \"icmp\" &" ; done; done

prefix="10.0.0" && for i in `seq 25`; do ping -c 1 $prefix.$i &> /dev/null && echo "Answer from: $prefix.$i" ; done
```

## nmap

- [Firewall Rules](https://nmap.org/book/determining-firewall-rules.html)
- [Bypass Firewalls](https://nmap.org/book/firewall-subversion.html)


### nmap port scanning

Ping scan - The ping scan fails to find any responsive hosts
```
nmap -n -sn -PE -T4 10.10.10.0/24

```

Packet Trace - one IP on that network & TCP SYN scan on subnet &  -sA for an ACK scan
```
nmap -vv -n -sn -PE -T4 --packet-trace 10.10.10.7
nmap -vv -n -sS -T4 -Pn --reason 10.10.10.0/24

```
Idle scan - bouncing scans off known boxes in network using the IPID Idle scan
Check box works as a zombie by testing it against 10.10.6.60 - a known-responsive machine with port 25 open
```
nmap -vv -n -Pn -sI 10.10.6.30:445 -p 25 10.10.6.60
```

Source routing
```
nmap -n -sn -PE --ip-options "L 10.10.6.60" --reason 10.10.6.30
```

SYN scan - 10.10.10.0/24 and 10.10.5.0/24 subnets are on different VLANs - SYN scan 10.10.10.7 
```
nmap -vv -n -sS -Pn --ip-options "L 10.10.6.60" --reason 10.10.10.7
```

Bypass scan time protection
```
for target in 205.217.153.53 205.217.153.54 205.217.153.62; \
do nmap --scan-delay 1075ms -p21,22,23,25,53 $target; \
usleep 1075000; \
done
```

Randomisation
```
 --randomize-hosts option which splits up the target networks into blocks of 16384 IPs, then randomizes the hosts in each block. 
Generate the target IP list with a list scan (-sL -n -oN <filename>), randomize it with a Perl script, then provide the whole list to Nmap with -iL. 
```

DNS proxy
```
nmap --dns-servers 4.2.2.1,4.2.2.2 -sL 205.206.231.12/28
```


TCP Connect scanning for localhost and network 192.168.0.0/24
```
# nmap -v -sT localhost
# nmap -v -sT 192.168.0.0/24
```
nmap TCP SYN (half-open) scanning
```
# nmap -v -sS localhost
# nmap -v -sS 192.168.0.0/24
```
nmap TCP FIN scanning
```
# nmap -v -sF localhost
# nmap -v -sF 192.168.0.0/24
```
nmap TCP Xmas tree scanning

Useful to see if firewall protecting against this kind of attack or not:
```
# nmap -v -sX localhost
# nmap -v -sX 192.168.0.0/24
```
nmap TCP Null scanning

Useful to see if firewall protecting against this kind attack or not:
```
# nmap -v -sN localhost
# nmap -v -sN 192.168.0.0/24
```
nmap TCP Windows scanning
```
# nmap -v -sW localhost
# nmap -v -sW 192.168.0.0/24
```
nmap TCP RPC scanning

Useful to find out RPC (such as portmap) services
```
# nmap -v -sR localhost
# nmap -v -sR 192.168.0.0/24
```
nmap UDP scanning

Useful to find out UDP ports
```
# nmap -v -O localhost
# nmap -v -O 192.168.0.0/24
```

nmap remote software version scanning

You can also find out what software version opening the port.

```
# nmap -v -sV localhost
# nmap -v -sV 192.168.0.0/24

```
