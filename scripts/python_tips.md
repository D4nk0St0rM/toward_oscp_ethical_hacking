

### read a file line by line

```
with open(fname) as f:
content = f.readlines()

with open(fname) as f:
content = f.read().splitlines()
```

### move file
```
os.rename(<filname>, dist_dir + os.path.sep + <filename>)
```
### get working directory
```
PWD = os.getcwd()
```

### write file 
```
RESOURCE = "filename.txt"
fr = open(RESOURCE, 'w')
fr.write("first line\n")
fr.close()
```

