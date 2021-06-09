### Scanning


#### netcat
```
nc -z -v {host-name-here} {port-range-here}
nc -z -v host-name-here ssh
nc -z -v host-name-here 22
nc -w 1 -z -v server-name-here port-Number-here
 ```
 
#### scan 1 to 1023 ports
```
nc -zv host-name-here 1-1023
```
