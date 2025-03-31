---
layout: blank
---

[HTB Linux Privesc Checklist](https://khaelkugler.com/pdf/Linux_Privilege_Escalation_Module_Cheat_Sheet.pdf)
### Enumerating Linux

**Files and User Privileges**
- Each file has read, write, and execute
- Groups are owner, owner's group (/etc/group), and others (everybody else) group

**Manual Enumeration**
- Getting info about the system
	- Running `id` can tell use about the user context
	- Running `hostname` can give us, the, uh, hostname
	- Reading `/etc/issue` and `/etc/os-release` and `uname -a` can give us OS info for exploits
	- Explore processes with `ps aux`
	- Check out network adapters with `ip a` or `ifconfig`
	- Display routing tables with `route` or `routel`
	- Display active connections with `netstat -anp` or `ss -anp` 
- Getting info on the firewall (without root user -> iptables)
	- Can sometimes read `/etc/iptables` 
	- Can search for `iptables-save` output in that directory, ending in .v4 I think
- Check cron jobs with `ls -lah /etc/cron*`
	- Has sections showing what is run at what intervals (e.g. hourly)
		- We can then check those folders to see what's running (e.g. `/etc/cron.hourly/`)
	- If we have sudo permissions ONLY for checking crontab, running `sudo crontab -l` will show scripts run by the root user
	- Can also check for running cron jobs with `grep "CRON" /var/log/syslog`
- Querying installed packages with `dpkg -l`
- Checking drives
	- `mount` will list all mounted filesystems
	- Can also check `/etc/fstab`
	- `lsblk` to list all available disks
- Check kernel modules with `lsmod`
	- To investigate certain modules, use `/sbin/modinfo {module_name}`
- Checking for `setuid` and `setgid` executables
	- These files can be executed by users with the rights of the owner or owner's group
	- Thus, getting commands through one of these executables allows privesc
	- Search for these files with `find / -perm -u=s -type f 2>/dev/null`
		- Then, check if usable with GTFO bins
		- `2>/dev/null` sends all errors to null

**Automated Enumeration**
- `linpeas`
	- `https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh`
- `unix-privesc-check`
	- Checks for misconfigurations that can be used for privescs
	- Located in kali at /usr/bin/unix-privesc-check
	- `./unix-privesc-check standard > output.txt`
- `LinEnum` - apparently a developed tool listed alongside `LinPeas`
- `pspy` - https://github.com/DominicBreuker/pspy
	- Use static 64bit version
	- Checks for commands being executed on the host
	- Finds scripts
- `linux-exploit-suggester` (executed by linpeas)
	- https://github.com/jondonas/linux-exploit-suggester-2

### Exposed Confidential Information

**Checking User History Files**
- `.bashrc` can sometimes contains environment variables with credentials
- `echo $HISTFILE`
- Can check environment variables with `env`

**Inspecting User/System Trails for Credentials**
- Can use `watch -n 1`sudo to run something like `ps -aux | grep "pass"` to look for new processes spawned with "pass" somewhere in the command
- If TCPdump sudo permissions have already been given to us, we can use it to monitor network traffic, which isn't normally allowed
	- `sudo tcpdump -i lo -A | grep "pass"`


### Insecure File Permissions

**Abusing Insecure Cron Jobs/File Permissions**
- Checking for running cron jobs
	- `ls -lah /etc/cron*`
	- `grep "CRON" /var/log/syslog`
	- check `/var/log/cron.log`
- Find modifiable cron jobs and overwrite them with anything, really
- Find writable directories with `find / -writable -type d 2>/dev/null`
- Find writable files with `find / -writable -type f 2>/dev/null`
- Find readable files with `find /home -readable -type f 2>/dev/null`

**Abusing Password Authentication**
- `/etc/passwd` is considered valid for auth, even with existence of `/etc/shadow`, meaning that if we can write to `/etc/passwd` we can just set an arbitrary password for a user
	- Generate a new password with `openssl passwd {passwd}`, which returns crypt algo hash
	- Then, create a new user with that hash as their password in the following format:
		- `root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash` (creates new root2/w00t user)

### Abusing System Linux Components

**Abuse SUID Programs/Capabilities**
- Enumerate for binaries with capabilities:
	- `/usr/sbin/getcap -r / 2>/dev/null`
	- Check GTFOBins for UNIX binaries that can be misused for privesc

**Circumvent Special Sudo Permissions**
- `sudo -l` to see allowed commands
- "AppArmor" is a kernel module providing Mandatory Access Control; can prevent privesc
- Search up all sudo binaries in GTFOBins to see if they can be abused 

**Enumerate Kernel for CVEs**
- Get kernel info with `cat /etc/issue`, `uname -r`, and `arch`
- Then, use `searchsploit` to search for existing kernel exploits
	- `searchsploit "linux kernel {kernel type and version} Local Privilege Escalation"` and then grep for the version needed
		- `grep "4." | grep -v " < 4.4.4" | grep -v "4.8"`

### What to do once you have root?
* Look (yes, manually) around the filesystem for passwords
	* `/etc/shadow` for hashes
	* Application config files are great!
	* Log files (like apache)
	* All users' home directories for interesting files/bash history
* You want to use this to find credentials to use elsewhere