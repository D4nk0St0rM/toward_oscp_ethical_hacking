[source](https://hackerifg.com/buffer-overflows/)

### Buffer Overflows

#### Programs needed:
- Windows
- Immunity Debugger

#### The Stack:
Extended Stack Pointer (ESP)
Buffer Space
Extended Base Pointer (EBP)
Extended Instruction Pointer (EIP)
Return Address

#### The Process:
- 1 Spiking
- 2 Fuzzing
- 3 Finding the Offset
- 4 Overwriting the EIP
- 5 Finding Bad Characters
- 6 Finding the Right Module
- 7 Generating Shellcode
- 8 Gain Root Access

#### To Dos:
##### On Windows
- Turn off Real-time protection
     - This is because of Windows Defender
- Turn off Virus & threat protection
- Download 'vulnserver.exe' onto Windows
     - found on GitHub, google vulnserver
     - Download and install 'Immunity Debugger'
     - from Immunity Inc.
     - can run a program through the debugger
     - after triggering exploit, can see results
     - Don't need to give them real info to download
- Run vulnserver as admin
- Run Immunity as admin

###### Immunity:
- File --> Attach
- look for vulnserver, attach
- Hit the play button on top

##### Kali:
