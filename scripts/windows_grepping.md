## Windows Grep / Grepping with Windows

### CMD
```
FINDSTR /i /r /c:"hello.*goodbye" /c:"goodbye.*hello" Demo.txt
FINDSTR -i -r -c:"hello.*goodbye" /c:"goodbye.*hello" Demo.txt
FINDSTR /irc:"hello.*goodbye" /c:"goodbye.*hello" Demo.txt
FINDSTR /ic:"hello" Demo.txt | findstr /ic:"goodbye" 
FINDSTR "granny Smith" Apples.txt Pears.txt
FINDSTR /C:"granny Smith" Contacts.txt
```
Search every file in the current folder and all subfolders for the word "Smith", regardless of upper/lower case, note that /S will only search below the current directory:
```
FINDSTR /s /i smith *.*
```
Join two files, return only the lines that they both have in common:
```
FINDSTR /g:"file1.txt" "file2.txt"
```
Search all the text files in the current folder for the string "fiona", display the filenames in White on Green.
```
FINDSTR /A:2F /C:fiona *.txt
```
Read the file Z:\source.txt, remove all the blank lines and write to Z:\result.txt
```
FINDSTR /v "^$" Z:\source.txt >Z:\result.txt
```
To find every line in novel.txt containing the word SMITH, preceeded by any number of spaces, and to prefix each line found with a consecutive number:
```
FINDSTR /b /n /c:" *smith" novel.txt
```
Finding a string only if surrounded by the standard delimiters
Find the word "computer", but not the words "supercomputer" or "computerise":
```
FINDSTR "\<computer\>" C:\work\inventory.txt
```
Find any words that begin with the letters 'comp', such as 'computerise' or 'compete'
```
FINDSTR "\<comp.*" C:\work\inventory.txt
```
Find any positive integers in the file sales.txt and include any lines that are a zero (0):
```
FINDSTR /r "^[1-9][0-9]*$ ^0$" Sales.txt
```

source: https://ss64.com/nt/findstr.html

### Powershell
```
Select-String -Path "Users\*.csv" -Pattern "Joe
Select-String -Path "Users\*.csv" -Pattern "Joe" | Select-Object * -First 1
Select-String -Path "Users\*.csv" -Pattern "Joe" | Select-Object -ExpandProperty Matches -First 1
Select-String -Path "Users\*.csv" -Pattern "Joe","Marti","Jerry"
Select-String -Path "Users\*.csv" -Pattern "Joe","Marti","Jerry" | Select-Object FileName, Pattern, Line
Select-String -Path "Users\*.csv" -Pattern '\\b[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b' | Select-Object -First 10
Select-String -Path "Users\*.csv" -Pattern '\d\d\d-\d\d-\d\d\d\d' | Select-Object -First 10
Select-String -Path "Users\*.csv" -Pattern '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' | Select-Object -First 10
Select-String -Path "Web\*.txt" -Pattern "suspendedpage.cgi" -Context 1 | Select-Object -First 1
Select-String -Path "Web\*.txt" -Pattern "suspendedpage.cgi" -Context 1 | Select-Object -ExpandProperty Context -First 1 | Format-List

```
source: https://adamtheautomator.com/powershell-grep/
