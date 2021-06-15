```
cat /etc/issue
cat /etc/*-release
uname -a
cat /etc/passwd
cat /etc/group
ps -auxxx | grep root
dpkg -l
rpm -qa
find /etc/ -name *.conf
crontab -l
ls -alh /var/spool/cron
ls -al /etc/cron*
cat /etc/cron*
hostname
/sbin/ifconfig -a
/sbin/route
arp -a 
netstat -antup
sudo -l 2> /dev/null
cat /etc/sudoers
ls -ahl /root/
ls -ahl /home/
find /home/ -name authorized_keys 
find /home/ -name id_*
find /root/ -name authorized_keys 
find /root/ -name id_*
ls -lah /root/.ssh/
ls -alh /var/www/
echo "python -c 'import pty;pty.spawn("/bin/bash")'"
echo "echo os.system('/bin/bash')"
echo "/bin/sh -i"
cat /etc/fstab
find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lh {} \; 2> /dev/null
which perl
which gcc
which g++
which python
which php
which cc
which go
which node
which wget
which nc
which netcat
which scp
which ftp
which tftp
which curl
```
