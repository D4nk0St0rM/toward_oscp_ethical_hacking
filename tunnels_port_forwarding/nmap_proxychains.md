#### Example nmap 

```
seq 1 254 | xargs -P 50 -I{} proxychains nmap -p 80,443,3389,445,22 -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap --append-output IP1.IP2.IP3.{}

seq 1 1000 | xargs -P 50 -I{} proxychains nmap -p {} -sT -Pn --open -n -T4 --min-parallelism 100 --min-rate 1 --oG proxychains_nmap --append-output <IP Address>

```


