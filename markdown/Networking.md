## Networking Notes

Not making networking its own section for a while


## Configure Managed Switch to Mirror Traffic

- On a Netgear GS305E switch, for example, it's possible to mirror traffic from one port on the switch to another
- This enables MITM attacks pretty easy, though you naturally have to be physically present to make it happen

**Setup**
- Let's say we're MITM-ing a firewall and a PC, which have a direct ethernet connection
- Configure the switch using the web GUI to mirror traffic from port 1 to port 5
- Plug firewall ethernet into port 1, and plug port 2 into the PC
  - Routing should be automatically handled, even if (and maybe only if) the IP range doesn't match the range of the switch itself
    - Switch is 192.168.0.239 by default, I changed mine to 172.16.1.239 just to avoid any conflicts
- Plug port 5 into attacker machine, and set IPv4 to disabled (setting it to passive mode, since it'll be a 1-way connection)
- Now we can just use something like WireShark to sniff the traffic on that network interface, which should essentially be like watching the original ethernet connection itself

**Issues**
- Macs might try to use switch over WiFi automatically, but you can go to the bottom of Networking settings and change the priority of each network interface
- Mac might even say the interface is "Not connected" after disabling IPv4, but we'll still be receiving the traffic on the interface, so WireShark will still work