### snippets that help 


nmap banners and vulns
```
sudo nmap --script='vuln,banner'
```

nmap gnmap format - open ports
```
awk '{for(i=5;i<=NF;i++)if($i~"/open/"){sub("/.*","",$i); print $2" "$i}}'
```


