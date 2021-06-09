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

### nmap port scanning

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
