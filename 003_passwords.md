### :panda_face: Wordlists
Generate a custom wordlist
cewl -w createWordlist.txt -m <min password length> https://www.example.com

### :panda_face: Hashes
https://hashes.org/search.php

john the ripper
john --wordlist=/user/share/wordlists/rockyou.txt hash.txt

Hashcat << check type online - hashcat sample hash
hashcat -m\<type> -a 0 /usr/share/wordlists/rockyou.txt hash.txt

### :panda_face: Web
HTTP post form

hydra -L <wordlist> -P<password list> <IP> http-post-form "<file path>:username=^USER^&password=^PASS^&Login=Login:<fail message>"
