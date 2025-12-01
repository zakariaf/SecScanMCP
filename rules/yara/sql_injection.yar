/*
 * SQL Injection Detection Rules
 * Target: SQL/NoSQL injection attacks in MCP tool implementations
 * Author: secscanmcp (merged from Cisco mcp-scanner + custom patterns)
 * Version: 1.0
 */

rule SQL_Injection_Tautology {
    meta:
        description = "Detects SQL injection tautology patterns (always-true conditions)"
        severity = "CRITICAL"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Classic tautologies
        $taut1 = /\bOR\s+['"]?1['"]?\s*=\s*['"]?1['"]?\s*(--|#|\/\*|;)/i
        $taut2 = /\bOR\s+['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+['"]?\s*(--|#)/i
        $taut3 = /\bOR\s+1\s*=\s*1\b/i
        $taut4 = /\bOR\s+true\s*(--|#|;)/i
        $taut5 = /'\s*OR\s*'\s*'\s*=\s*'/i
        $taut6 = /"\s*OR\s*"\s*"\s*=\s*"/i

        // Boolean-based blind
        $bool1 = /\bAND\s+1\s*=\s*1\b/i
        $bool2 = /\bAND\s+1\s*=\s*2\b/i
        $bool3 = /\bAND\s+SUBSTRING\s*\(/i

        // Exclusion - legitimate SQL operations
        $exclude1 = /(query_builder|sql_builder|orm_query|parameterized_query)/i
        $exclude2 = /(example:|documentation|tutorial|test_data)/i

    condition:
        (any of ($taut*) or any of ($bool*)) and not any of ($exclude*)
}

rule SQL_Injection_Destructive {
    meta:
        description = "Detects destructive SQL injection (DROP, DELETE, TRUNCATE)"
        severity = "CRITICAL"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Drop table attacks
        $drop1 = /';\s*DROP\s+TABLE/i
        $drop2 = /";\s*DROP\s+TABLE/i
        $drop3 = /;\s*DROP\s+(TABLE|DATABASE|SCHEMA)\s+/i

        // Delete attacks
        $delete1 = /';\s*DELETE\s+FROM/i
        $delete2 = /;\s*DELETE\s+FROM\s+\w+\s*(WHERE\s+1\s*=\s*1|--)/i

        // Truncate attacks
        $truncate1 = /;\s*TRUNCATE\s+(TABLE\s+)?\w+/i

        // Update attacks
        $update1 = /;\s*UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1/i

        // Exclusion - migrations, legitimate DDL
        $exclude1 = /(migration|schema_version|alembic|flyway)/i

    condition:
        any of ($drop*, $delete*, $truncate*, $update*) and not $exclude1
}

rule SQL_Injection_Union_Based {
    meta:
        description = "Detects UNION-based SQL injection attacks"
        severity = "CRITICAL"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Union attacks
        $union1 = /UNION\s+(ALL\s+)?SELECT/i
        $union2 = /'\s*UNION\s+SELECT/i
        $union3 = /"\s*UNION\s+SELECT/i
        $union4 = /\)\s*UNION\s+(ALL\s+)?SELECT/i

        // Column enumeration
        $column1 = /ORDER\s+BY\s+\d+\s*(--|#)/i
        $column2 = /GROUP\s+BY\s+\d+\s*(--|#)/i

        // NULL-based column detection
        $null1 = /UNION\s+SELECT\s+NULL(,\s*NULL)*/i

        // Exclusion
        $exclude1 = /(prepared_statement|parameterized)/i

    condition:
        any of ($union*, $column*, $null*) and not $exclude1
}

rule SQL_Injection_Time_Based_Blind {
    meta:
        description = "Detects time-based blind SQL injection techniques"
        severity = "HIGH"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // MySQL time delays
        $mysql1 = /\bSLEEP\s*\(\s*\d+\s*\)/i
        $mysql2 = /\bBENCHMARK\s*\(\s*\d+\s*,/i

        // SQL Server delays
        $mssql1 = /WAITFOR\s+DELAY\s+['"]?\d+:\d+:\d+/i
        $mssql2 = /WAITFOR\s+TIME\s+/i

        // PostgreSQL delays
        $pg1 = /\bpg_sleep\s*\(\s*\d+\s*\)/i
        $pg2 = /\bpg_sleep_for\s*\(/i

        // Oracle delays
        $oracle1 = /\bDBMS_LOCK\.SLEEP\s*\(/i
        $oracle2 = /\bDBMS_PIPE\.RECEIVE_MESSAGE\s*\(/i

        // SQLite (no direct sleep, but commonly attempted)
        $sqlite1 = /\brandomblob\s*\(\s*\d{6,}\s*\)/i

    condition:
        any of them
}

rule SQL_Injection_Error_Based {
    meta:
        description = "Detects error-based SQL injection techniques"
        severity = "HIGH"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // MySQL error-based
        $mysql1 = /\bEXTRACTVALUE\s*\(/i
        $mysql2 = /\bUPDATEXML\s*\(/i
        $mysql3 = /\bEXP\s*\(\s*~\s*\(\s*SELECT/i
        $mysql4 = /\bGROUP\s+BY\s+.*\bHAVING\b/i

        // SQL Server error-based
        $mssql1 = /\bCONVERT\s*\(\s*int\s*,/i
        $mssql2 = /\bCAST\s*\(\s*\(/i

        // PostgreSQL error-based
        $pg1 = /\bCAST\s*\(\s*CHR\s*\(/i

        // Deliberate syntax errors for probing
        $syntax1 = /['"]--\s*$/
        $syntax2 = /'[^']*\bOR\b[^']*$/i

    condition:
        any of them
}

rule SQL_Injection_System_Access {
    meta:
        description = "Detects SQL injection attempts to access system objects"
        severity = "CRITICAL"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Information schema access
        $info1 = /\bSELECT\s+[^;]*\bFROM\s+information_schema\./i
        $info2 = /\binformation_schema\.(tables|columns|schemata)\b/i

        // MySQL system tables
        $mysql1 = /\bFROM\s+mysql\.user\b/i
        $mysql2 = /\bSELECT\s+[^;]*mysql\.(user|db|tables_priv)\b/i

        // SQL Server system
        $mssql1 = /\b(xp_cmdshell|sp_executesql)\s*\(/i
        $mssql2 = /\bOPENROWSET\s*\(/i
        $mssql3 = /\bsysobjects\b/i
        $mssql4 = /\bsyscolumns\b/i

        // Oracle system tables
        $oracle1 = /\bFROM\s+(dual|all_tables|user_tables)\b/i
        $oracle2 = /\bdbms_[a-z_]+\s*\(/i

        // File operations
        $file1 = /\bLOAD_FILE\s*\(\s*['"][^'"]*\.(config|passwd|shadow|key)\b/i
        $file2 = /\bINTO\s+OUTFILE\s+['"][^'"]*\.(txt|sql|php)\b/i
        $file3 = /\bINTO\s+DUMPFILE\b/i

    condition:
        any of them
}

rule SQL_Injection_Stacked_Queries {
    meta:
        description = "Detects stacked query SQL injection"
        severity = "HIGH"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Stacked query patterns
        $stack1 = /['"];\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s+/i
        $stack2 = /\);\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\s+/i

        // Multiple statement markers
        $multi1 = /;\s*--\s*(SELECT|DROP|DELETE)/i

        // Batch execution
        $batch1 = /\bEXEC\s+sp_/i
        $batch2 = /\bEXECUTE\s+IMMEDIATE\b/i

    condition:
        any of them
}

rule NoSQL_Injection_MongoDB {
    meta:
        description = "Detects MongoDB NoSQL injection patterns"
        severity = "HIGH"
        category = "nosql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // MongoDB operators in user input
        $mongo1 = /\$where\s*:\s*['"]/i
        $mongo2 = /\$regex\s*:\s*['"]/i
        $mongo3 = /\$ne\s*:\s*['"1null]/i
        $mongo4 = /\$gt\s*:\s*['"]/i
        $mongo5 = /\$lt\s*:\s*['"]/i
        $mongo6 = /\$or\s*:\s*\[/i
        $mongo7 = /\$and\s*:\s*\[/i

        // JavaScript injection in MongoDB
        $js1 = /\$where\s*:\s*['"]?function\s*\(/i
        $js2 = /\$where\s*:\s*['"]?this\./i

        // Type coercion attacks
        $type1 = /\{\s*['"]?\$type['""]?\s*:\s*\d+\s*\}/i

        // Code execution
        $exec1 = /db\.(eval|runCommand)\s*\(/i

    condition:
        any of them
}

rule NoSQL_Injection_Redis {
    meta:
        description = "Detects Redis injection patterns"
        severity = "HIGH"
        category = "nosql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Dangerous Redis commands
        $redis1 = /\bCONFIG\s+(GET|SET)\b/i
        $redis2 = /\bFLUSHALL\b/i
        $redis3 = /\bFLUSHDB\b/i
        $redis4 = /\bDEBUG\s+SEGFAULT\b/i
        $redis5 = /\bSLAVEOF\b/i
        $redis6 = /\bSHUTDOWN\b/i

        // Lua script injection
        $lua1 = /\bEVAL\s+['"]/i
        $lua2 = /\bEVALSHA\b/i

        // Key pattern attacks
        $key1 = /\bKEYS\s+\*/i

    condition:
        any of them
}

rule SQL_Injection_ORM_Bypass {
    meta:
        description = "Detects ORM injection and bypass patterns"
        severity = "MEDIUM"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Raw SQL in ORM context
        $raw1 = /\.raw\s*\(\s*['"`]/i
        $raw2 = /\.execute\s*\(\s*['"`]/i
        $raw3 = /RawSQL\s*\(/i

        // SQLAlchemy unsafe patterns
        $sqla1 = /text\s*\(\s*f['"`]/i
        $sqla2 = /\.filter\s*\(\s*['"`].*%s/i

        // Django unsafe patterns
        $django1 = /\.extra\s*\(\s*.*where\s*=/i
        $django2 = /RawSQL\s*\(/i

        // Sequelize unsafe patterns
        $seq1 = /sequelize\.query\s*\(\s*['"`]/i
        $seq2 = /\[Op\.and\]\s*:\s*sequelize\.literal/i

        // String formatting in queries (dangerous)
        $format1 = /\.format\s*\([^)]*\)\s*\)/
        $format2 = /%\s*\([^)]+\)\s*s.*SELECT/i

    condition:
        any of them
}

rule SQL_Injection_Comment_Bypass {
    meta:
        description = "Detects SQL comment-based injection bypass techniques"
        severity = "MEDIUM"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Comment obfuscation (high-confidence patterns)
        $obfusc1 = /\/\*\*\/SELECT/i
        $obfusc2 = /UN\/\*\*\/ION/i
        $obfusc3 = /SEL\/\*\*\/ECT/i

        // MySQL version comments (fingerprinting)
        $version1 = /\/\*!\d+.*\*\//

    condition:
        any of ($obfusc*) or $version1
}

rule SQL_Injection_Encoding_Bypass {
    meta:
        description = "Detects encoding-based SQL injection bypass attempts"
        severity = "HIGH"
        category = "sql_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // URL encoding
        $url1 = /%27.*%3D.*%27/i  // ' = '
        $url2 = /%22.*%3D.*%22/i  // " = "
        $url3 = /%55%4E%49%4F%4E/i  // UNION

        // Double URL encoding
        $double1 = /%2527/i  // '
        $double2 = /%2522/i  // "

        // Unicode encoding
        $unicode1 = /\\u0027/i  // '
        $unicode2 = /\\u0022/i  // "

        // Hex encoding
        $hex1 = /0x[0-9a-f]{2,}.*SELECT/i
        $hex2 = /CHAR\s*\(\s*0x/i

        // HTML entities
        $html1 = /&#39;/
        $html2 = /&#x27;/
        $html3 = /&apos;/

    condition:
        any of them
}
