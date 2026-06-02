---
layout: blank
pagetitle: Networks and Firewalling
---

These aren't as polished as my other notes, as they're mostly meant to serve as notes for repeatable processes I've had to do in the past :)

## Configuring a Router with a 1:1 NAT

**1:1 NAT**
- A 1:1 NAT takes place when the router has multiple IPs and assigns each of them a direct IP mapping
  - For example, if our router is `192.168.55.15` on the external subnet, it could also have `192.168.55.16` as an IP address on the same NIC
    - Any traffic received on `192.168.55.16` would be forwarded to an internal IP, such as `172.16.10.11`
- Then, an `iptables` rule such as `-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` will allow inbound, stateful traffic to reach internal machines
  - If we wanted to allow the machines on the internal subnet to reach the internet through us, we'd add `NEW` to `--ctstate`
    - In order for external devices to then respond to the internal machines, we'd also need a rule like `-A POSTROUTING -s 172.16.1.0/24 -j MASQUERADE`
- Next, we need to make sure the `net.ipv4.ip_forward` kernel runtime param is set to `1`
  - To ensure it persists, add it like `echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-forwarding.conf` and reload with `sysctl --system`
  - Can also be done manually with `echo 1 > /proc/sys/net/ipv4/ip_forward`
- Finally, we need to set up DNAT/SNAT to allow two-way routing
  - Route everything destined for `.16` to the target: `-A PREROUTING -d 192.168.55.16/32 -j DNAT --to-destination 172.16.1.11`
  - Route everything from the target to a source of `.16`: `-A POSTROUTING -s 172.16.1.11/32 -j SNAT --to-source 192.168.55.16`
- For the internal machine, it would only need an internal IP (e.g. `172.16.10.11`) and a default route to the router
  - This can be set in `/etc/network/interfaces` with `gateway 172.16.1.10` or manually with something like `ip route add default via 172.16.1.10 dev {nic}`

**Ensuring the settings persist**
- For `iptables` rules, we can use something like `iptables-save`
  - `apt install iptables-persistent && iptables-save > /etc/iptables/rules.v4`
- For networking settings to persist, they need to be in `/etc/network/interfaces`
- The configuration is pretty standard for the router: 

```
auto ens37
iface ens37 inet static
    address 192.168.55.15
    netmask 255.255.255.0
    network 192.168.55.0
    broadcast 192.168.55.255
```
- To add additional IPs, we unfortunately can't just add another `address` line under our first network, we need a second one with `:0` to indicate it's another IP address on the same NIC

```
auto ens37:0
iface ens37:0 inet static
    address 192.168.55.16
    netmask 255.255.255.0
```

## Configure Managed Switch to Mirror Traffic

- On a Netgear GS305E switch, for example, it's possible to mirror traffic from one port on the switch to another
- This enables MITM attacks pretty easy, though you naturally have to be physically present to make it happen

**Setup**
- Let's say we're MITM-ing a firewall and a PC, which currently have a direct ethernet connection between one another
- Using the web GUI, configure the switch to mirror traffic from port 1 to port 5
- Plug firewall ethernet into port 1, and plug port 2 into the PC
  - Routing should be automatically handled, even if (and maybe only if) the IP range doesn't match the range of the switch itself
    - Switch is 192.168.0.239 by default, I changed mine to 172.16.1.239 just to avoid any conflicts
- Plug port 5 into attacker machine, and set IPv4 to disabled (setting it to passive mode, since it'll be a 1-way connection)
- Now we can just use something like WireShark to sniff the traffic on that network interface, which should essentially be like watching the original ethernet connection itself

**Issues**
- Macs might try to use switch over WiFi automatically, but you can go to the bottom of Networking settings and change the priority of each network interface
- Mac might even say the interface is "Not connected" after disabling IPv4, but we'll still be receiving the traffic on the interface, so WireShark will still work

## Firewalling

- Rules are usually taken in order, so first rules take precedence
  
**Iptables**
- Changes are automatically applied once rule is created
- `iptables --list-rules`
- Accept traffic on a port: `iptables -A {INPUT/OUTPUT/FORWARD} -p {tcp/udp} --dport {port} -j {ACCEPT/DROP/LOG}`
  - Can pass a specific table with `-t {table_like_NAT}`
  - `-s {IP}` to pass an IP (range) for allowing/denying
  - To delete a rule, replace `-A` with `-D` and keep the rest of the rule the same
- Flush all rules: `iptables -F INPUT/OUTPUT/FORWARD`

**ufw**
- `ufw {enable/disable}`
- Status of a rule `ufw status {rule_num}`
- Allow a port: `ufw allow 22/tcp`
- Allow from IP: `ufw allow from {IP}`
  - Can add `to any port 22`
- Deny all outgoing by default: `ufw default deny outgoing`
- `firewalld` is similar and present on RHEL

**nftables**
- Conf in `/etc/nftables.conf`
- `nft list ruleset` to list rules, flush with `nft flush ruleset`
- Add port with `nft add rule inet filter input tcp dport 80`
- Block IP with `nft add rule inet filter input ip saddr {IP} drop`
- Delete rule with `nft delete rule inet filter input handle {rule_number}`

**Windows**
- Allow a port: `New-NetFirewallRule -DisplayName "{name}" -Direction Inbound -LocalPort {port} -Protocol TCP -Action Allow`


## Misc

**Connecting to LAN over USB**
- Make sure to manually set IP and interface via Network settings after connecting via USB, if DHCP isn't set up
- Can then configure things like kali to use the interface, which will actually give kali its own IP on the network (rather than sharing the hosts)
  - Can be very handy when we need to host things on kali
- If we need to access multiple subnets within the LAN, we can use an alias
  - For example, accessing a 10.0.0.X IP within a different subnet: `sudo ifconfig <IFACE> alias 10.0.0.<desired_IP> netmask 255.255.0.0`
