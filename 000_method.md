
Looking to build my own, I have taken the start point from https://github.com/botesjuan/PenTestMethodology2020 to reduce some work starting from scratch.

## Reconnaissance

* Scanning 
  * netdiscover
  * nmap
    * network discovery
    * UDP scans
    * List Target Ports
    * no response ICMP
    * full ignore
    * external scan 
    * all exploit scripts
    * nmap grepper
    * Fingerprint & Banner
    * help
  * autorecon
  * port knocking
  * wget
  * wordpress scan
  * masscan
  * packet sniffing
    * wireshark
      * wireshark filters
      * dhcp traffic
      * device models & OS
      * Windows User Account
      * String Search
      * OSI Models
      * SShdump
    * tcpdump
    * OSI Model Layers
    * network challenges
    * tshark
* OSINT
  * maltego
  * Google Dork
  * shodan
  * Collections
  * WayBack Machines Web Archives
  * Google Cached
  * Netcraft
  * bug bounty hunting
  * TheHarvester
  * whois
* Human Manual Task to gather information

## Enumeration


* 21 FTP
* 22 SSH
  * login with private key
  * ShellShock
  * SSH directo to bin/sh
  * SSH local port Forwarding
  * nmap
  * OpenSSH private key
* 23 Telnet
* 25 SMTP
  * nmap
  * hunter online
  * connect
  * python
* 53 DNS
  * DIG DNS
  * brute
  * host enum
  * dnsenum
  * nmap dns
* 80/443 HTTP
  * wfuzz
  * gobuster
  * dirb
  * dirsearch
  * wordpress
  * nikto
  * CEWL
  * wget
  * curl
  * Browsing
    * wappalyzer
    * httpOnly False
    * javascript
    * back ticks
    * login page
    * robots.txt
    * domain names
    * source code & Dev Tools
  * whatweb
  * owasp-zap
  * skipfish
  * uniscan
* 88 Kerberost
  * GetNPUsers
  * kerbrute
  * GetUserSPNs
* 110 POP3
  * pop3 alt port
* 111 NFS
* 123 NTP
* 135 RPC
* 139/445 SMB
  * nmap smb
  * msfconsole
  * crackmapexec smb
  * smbclient
    * smbclient null
    * smbpasswd
    * mount smb
    * enum shares
    * smbget
  * smbmap
  * rpcclient
    * rpclient help
    * enum printers
    * bash query RID
  * enum4linux
* 143 IMAP
* 161 SNMP
* 389/3269 LDAP
* 554 RTSP
* 593 RPC over HTTP
* 631 Printers
* 636 LDAP
* 1056 Trojan / Virus
* 1433 SQL
  * SQLMAP
* 1521 Oracle
* 2049 NFS
  * show mount
* 3268 GlobalCat
* 3306 MYSQL
  * msfconsole
  * SQLMAP
  * mysql with creds
* 3389 RDP
  * xfreerdo
  * remmina
* 4386 HQK
* 5060 SIP
* 5601 Kibana
* 5666 NRPE (Nagios)
* 5901 VNC
* 5985 WinRM
  * crackmapexec winrm
  * Evil-WinRM
* 6379 REDIS
* 6667 irc
* 6699 napster
* 8080 Web Servers
  * HttpFileServer HFS
  * Jenkins/Jetty
* 8291 MikroTik
* 8443 NetGear
* 8500 FMTP Coldfusion
* 8834 nessus
* 9191 Printer PaperCut
* 9256 Achat
* 9389 AD Web
* 11211 memcached
* 13327 CrossFire
* 50000 Jetty


## Exploitation 


* Default Credentials
* Hosting
  * samba smbd
  * SMBserver
  * python2 HTTP
  * python3 http
  * FTP hosting
  * PHP
* File transfer
  * PowerShell
  * CURL
  * certutil
  * wget
  * ftp file transfers
  * smbclient
  * scp
  * netcat
  * VBscript
* Payloads
  * exiftool
  * PayloadsAllTheThings
  * msfvenom
    * Windows 32bit
    * Windows 64bit
    * Linux
    * Mobile
  * XSS Payloads
  * SQL Injections Input
  * Windows Commands
* Compilers & Debuggers
  * dnSpy
  * gcc
    * gcc mingw w64
    * gcc help
  * Immunity Debugger
  * fpm compiler
  * Visual Studio Code
  * minGW
  * jDoodle
* Connect Shells
  * NC
  * NetCat Windows
  * Python
  * pwncat
  * socat
  * bash shell
  * PowerShell Reverse Shell
  * PowerCat
* Cracking
  * identify hash
    * hashid
  * Active Crack
    * hydra
      * ssh
      * ftp
      * pop3
      * http-post-form
      * http-get
    * medusa
    * wordpress
    * crackmapexec
    * Python brute force
  * Offline Cracking
    * hashcat GPU host
      * md5
      * NTLM
      * NTLMv2
      * Kerberos
      * sha512 1800
      * bcrypt 3200
      * sha2-256 1400
      * SHA-1
      * sha1(pass:salt)
      * hmac-sha1
    * base64
    * VNC reg decryt
    * John
      * keepass db
      * shadow.bak
      * zip2john
      * ssh2john
      * netNTLMv2
      * Raw-MD5
      * pgp & asc
      * Raw-SHA256
      * responder logs
      * John GPU host
      * sha512 dynamic
      * Gost Hash
    * BASH brute force
    * Burp Suite Decoder
    * Python scripts
    * fcrackzip
    * gpp-decrypt
    * hex crack xxd
  * Online Websites Decrypt Services
* Metasploit
  * metasploit help
    * msfconsole
  * msf Reconnaissance
    * smtp
    * smb metasploit
    * wordpress login
  * msf Exploitation
    * reverse_tcp
    * multi/handler 1 line
    * libreNMS
    * msfconsole psexec
    * bluekeep
    * HFS HttpFileServer
    * webmin
    * TomCat
    * ms17-010 eternalblue
    * wordpress 5 core
    * nostromo
    * smb_login brute
    * add custom module
    * Struts
  * msf post exploitation
    * background msf
    * privelege escalation
    * exploit-suggest
    * looting
    * persistence
    * Metasploit PowerShell
  * msf pivoting
* AV Bypass
* Exploits & Low Shell
  * Exploiting
    * ftp
      * Example FTP Script
      * telnet 21
      * ProFTPd exploit
      * ftp upload sh
    * ssh
      * login using priv&pub key
      * custom port and noprofile
      * ssh-keygen
      * ssh port forwarding
      * ssh log poisoning
      * SSH Tunnels
    * LFI / RFI
      * LFI wordlist
      * ColdFusion
      * win.ini
      * LFI example5
      * lfi domain search
      * php parameter
      * php filter LFI
      * Kibana Logs
    * RCE
      * umbracp webapp
      * curl upload
      * curl command injection
      * openEMR
      * Drupal 7
      * tomcat9
      * moodle rce
      * RCE BlogEngine
      * dvwa
      * icecast
      * Jenkins   
    * SMB
      * smbmap
      * smbclient
      * crackmapexec
      * mount smb
    * CMS
      * CMS Made Simple
      * WordPress
      * Fuel CMS
      * joomla CMS
      * Gila CMS
      * Cuppa CMS
      * bolt CMS
    * JsonPickle Exploitation
    * Arbitrary File upload
    * Impacket MSSQLclient
    * VHD Hyper-V
    * ntp
    * OpenSSL heartbleed
    * REDIS
    * Shellshock HTTP
    * phpMyAdmin
    * nginx   
    * jserv Apache
    * blind back tick
      * node.js
      * ${ifs}
    * .htpasswd
    * MSSQL cmdshell
    * file uploads
      * client side
      * Extensions
      * Magic Numbers
      * Challenge
      * RCE & overwrite
      * Bypass Client side filter
  * Linux Reverse Shell
    * bash
    * python reverse shell
    * full interactive shells
    * NetCat
    * HTTP force Browsing
    * php excution
    * Kernel OS
  * Windows Reverse Shell
    * Evil-WinRm
    * Kerberoasting
    * PowerShell
    * iis aspx
    * psexec.py
    * coldfusion
    * MSSQL cmdshell
    * Rejetto HTTP file server
    * Windows Kernel Exploits
    * Windows REG
    * Jenkins
* Buffer Overflow - Windows
  * fuzz - pattern - EIP - JMP ESP - bad characters - NOP sled - Payload
* Buffer Overflow - Linux
  * fuzz - pattern - EIP - JMP ESP - bad characters - NOP sled - Payload
* Extractions!
  * Reversing
    * r2
      * r2 debug
    * ghidra
    * source code
      * html
      * web request
      * user agent
      * referer
      * drop down+1
      * javascript
      * edit HTML
      * curl post
      * image size
  * Crypto
    * base 16 32 64
    * rot13
    * base58
    * XOR operation
    * Vigenere Cipher
    * Cistercian Monks Numrals
    * Numbers > Dec > Hex > Ascii
    * CyberChef
    * fernet
    * Integrity Check Files
    * volatility
    * RSA Chinese Remainder
    * Chiffre de Bacon
    * old mobile keyboard
  * Stego
    * binwalk
    * zsteg
    * steghide
    * stegCracker
    * exiftool
    * pngcheck
    * jsteg
    * multimon-ng
    * stegSNOW
    * Homoglyphs
    * binary image
    * steg_brute.py
    * stegsolve.jar
    * hexdump
    * QR codes
    * reverse image search
  * forensics
    * usbrip
    * Microsoft Docs
    * volatility
    * packet capture
      * WireShark
    * readpst
    * VHD
    * web archives
  * Mobile
    * mobile backup
    * apk
  * OSINT
    * phishing emails
    * username locations
    * WayBack Machine
    * sherlock

## POST Exploitation


* Windows
  * Enumerate to privilege escalate
    * Windows cmds
    * winPEAS
    * SherLock
    * Watson 
    * JAWS
    * Windows Exploit Suggester
    * seatbelt
    * SharpUp
    * rpcclient
    * PowerShell Enum
    * Registry
    * icacls
    * SysInternals
    * PowerUp
  * Privilege Escalation Windows
    * dnscmd
    * evil-winrm
    * CapCom.sys
    * Port Forwarding
      * socat tunnel
      * plink putty
      * SSH Tunnel forwarding
    * Windows SubSystem Linux
    * Windows Privileges
      * hot patato
      * Potato Impersonation
      * SeImpersonatePrivilege
    * Alternate Stream
      * PowerShell Stream
      * smb allinfo
    * runAS
    * Services
      * Service escalate registry
      * Service Escalate Executable
      * Service Unquoted Service Path
      * Service Binary Path
    * StartUp Apps
    * Windows Kernel Exploits
    * psExec.py PrivEsc
    * User Account Control (UAC)

* Linux
  * Enumerate inside Linux Shell
    * Linux Enum Commands
      * System Enum
        * ps
        * cron jobs
        * scheduled cron jobs
      * User Enum
        * history
        * enum4linux
      * Network Enum
        * netstat
        * tcpdump
        * ss
      * find weak perm
        * SUID
      * password hunting
    * LinPEAS
    * LinEnum
    * pspy    
    * Linux Exploit Suggester
    * Linux Priv Checker
    * Access MDB
    * Capabilities
  * Linux Priv Esc to increase rights in low shell
    * Weka File Perm
    * Kernel Exploits
    * Stored Passwords
    * sudo
      * shell escaping
      * intended function
      * LD_Preload
      * pwfeedback
      * systemctl
      * dpkg
      * perl scripts
      * zip
    * Python Lib HiJack
    * SSH Keys
    * psexec 
    * PenTestMonkeys
    * Full Interactive Shell
    * SUID
      * Shared Object Injection
      * Symlinks
      * Envrionment Variables
      * sysinfo
      * Statuscheck
      * logrotate
    * Capabilities PrivEsc
    * Schedule Cron Jobs
    * NFS Root Squashing
    * Docker
    * Lxd Privilege Escalation
      * lxc/lxd privesc


## Web Apps

### OWASP Web Application Testing Attack Guide
* Info Recon(INFO)
  * Tools & Methods
    * gobuster
    * unshorten tiny URL
    * directory Brute Force
    * robots.txt
    * cookies
    * DNS
    * dirb
    * Burp Suite
    * curl
  * Fingerprint Web Server-INFO002
  * Fingerprint Web App-INFO009
* Configuration (CONFIG)
  * Sensitive Information-CONFIG004
  * Admin Interfaces-CONFIG005
* Identity (IDENT)
  * User Registration-IDENT002
* Authentication (AUTHN)
  * account lock-AUTHN003
  * Weak password policy-AUTHN007
  * Weak password change reset-AUTHN009
* Authorization (AUTHZ)
  * IDOR-AUTHZ004
* Session (SESS)
  * Session Manage Schema SESS001
* Input Validation (INPVAL)
  * reflected XSS-INPVAL001
  * SQL Injection-INPVAL005
    * SQLMAP
    * SQLi Payloads
    * UNION Attacks
  * XSS-INPVAL009
  * Code Injection-INPVAL012
  * Server-side template injection
  * Splitting/Smuggling-INPVAL016
* Error Handling (ERR)
* Weak Cryptography (CRYPST)
  * Padding Oracle CRYPST002
* Business Logic (BUSLOGIC)
  * Work Flows-BUSLOGIC006
* Client Side (Client)
  * DOM Cross site scripting-CLIENT001
  * Resouce Manipulation CLIENT006
  * CORS CLIENT007
  * ClickJacking CLIENT009


## Attack Systems 

* Active Directory
  * LLMNR Poison
  * HashCat
  * SMB Relay
  * msfconsole 
  * impacket psexec
  * IPv6 Attack
  * PowerView
  * BloodHound
  * AD Attack POST Compromise
* EMail
* Printers
* DNS
* Pivoting Networks
* SQL
  * mysql
    * mySQL commands
  * Microsoft SQL
  * postgreSQL
  * RogueSQL MIM
  * SQLite
* Oracle
* Wireless
  * aircrack-ng

## Reporting 

* Introduction
* Executive Summary
* Findings
* Risk Matrix
* Recommendations
* Remediation
