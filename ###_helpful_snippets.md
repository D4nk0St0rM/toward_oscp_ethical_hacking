##### snippets that help 


nmap gnmap format - open ports
```
awk '{for(i=5;i<=NF;i++)if($i~"/open/"){sub("/.*","",$i); print $2" "$i}}'
``
