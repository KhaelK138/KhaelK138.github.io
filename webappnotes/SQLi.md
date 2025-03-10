### SQL Injection

Cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet

**What is SQL injection**
- Inserting into SQL queries (commonly SELECT, but sometimes others like UPDATE or INSERT)
- `https://insecure-website.com/products?category=Gifts` -> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
  - Often easiest to figure out hte query by trying to fill out the rest of the query ourselves (so something like `Gifts'--` to get the same data)

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

**Blind SQL Injection**
- Blind SQLi is when the neither database query NOR errors are present in the HTTP response 
- Can identify blind injection by getting normal results to appear with A SQL query `' AND '1'='1`
  - Not commented out since the 
- Error-based blind SQLi:
  - Do error-based character comparisons to figure out characters
  - `' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

**Bypassing Defenses**
- If single quotes are totally blacklisted, a `\` as the first parameter can actually unlock an apostrophe to use as part of the second payload
- Backslashes can also be used for bypassing single quotes being replaced with double quotes
- 