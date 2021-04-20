### bash add prefix

```
cat file.txt | awk '$0="Shell +="$0'
```




### python read a file line by line

```
with open(fname) as f:
content = f.readlines()

with open(fname) as f:
content = f.read().splitlines()
```

### python move file
```
os.rename(<filname>, dist_dir + os.path.sep + <filename>)
```
### python get working directory
```
PWD = os.getcwd()
```

### python write file 
```
RESOURCE = "filename.txt"
fr = open(RESOURCE, 'w')
fr.write("first line\n")
fr.close()
```

