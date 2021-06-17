example: [ippsec forest walkthrough](https://www.youtube.com/watch?v=H9FcE_FMZio)

```
January
February
March
April
May
June
July
August
September
October
November
December
Password
P@ssw0rd
Secret
123456
123456789
qwerty
111111
12345678
abc123
1234567
password1
12345
iloveyou
monkey
dragon
picture
autumn
winter
spring
summer
fall
letmein
secret
youdontknowthis
zxcvbnm
poiuytrewq
asdfghjkl
lkjhgfdsa
mnbvcxz
mypassword
mynameis
yellow
family
chelsea
liverpool
loveyou
pretty
basketball
angels
tweety
flower
playboy
hello
hottie
tinkerbell
barbie
lovers
teamo
666666
shadow
eminem
forever
family
987654321
computer
whatever
dragon
cookie
naruto
sweety
spongebob
softball
11111111
22222222
33333333
44444444
55555555
66666666
77777777
88888888
99999999
00000000

```

#### custom

```
for i in $(cat passwords); do echo $i; echo ${i}2020; done >  tmp; cp tmp passwords && rm tmp
for i in $(cat passwords); do echo $i; echo ${i}\!; done > tmp; cp tmp passwords && rm tmp
hashcat --force --stdout passwords -r /usr/share/hashcat/rules/best64.rule > password.list
cat password.list | sort -u > tmp; cp tmp password.list && rm tmp
cat password.list | awk 'length($0) > 8' > tmp; cp tmp password.list && rm tmp



```
