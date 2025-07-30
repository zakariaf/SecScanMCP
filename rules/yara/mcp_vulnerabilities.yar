/*
YARA rules for detecting known MCP vulnerabilities and CVEs
*/

rule CVE_2025_49596_MCP_Inspector_RCE
{
    meta:
        description = "Detects CVE-2025-49596 MCP Inspector RCE vulnerability"
        author = "MCP Security Scanner"
        severity = "critical"
        cvss_score = "9.4"
        cve = "CVE-2025-49596"
        category = "vulnerability"
        reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49596"

    strings:
        // Vulnerable endpoints
        $endpoint1 = "http://0.0.0.0:6277/sse"
        $endpoint2 = "http://localhost:6277/sse"
        $endpoint3 = "http://127.0.0.1:6277/sse"
        $endpoint4 = ":6277/sse?transportType=stdio"

        // CSRF attack patterns
        $csrf1 = /fetch\s*\(\s*["']http:\/\/0\.0\.0\.0:6277/ nocase
        $csrf2 = /XMLHttpRequest.*0\.0\.0\.0:6277/ nocase
        $csrf3 = /iframe.*src.*0\.0\.0\.0:6277/ nocase
        $csrf4 = /window\.open.*localhost:6277/ nocase

        // Command injection via URL
        $cmd1 = "transportType=stdio&command="
        $cmd2 = "&args=%2Ftmp%2F"
        $cmd3 = "&args=%2Fetc%2F"
        $cmd4 = "&command=touch&args="
        $cmd5 = "&command=cat&args="

        // Exploitation markers
        $exploit1 = "mode: \"no-cors\""
        $exploit2 = "credentials: \"include\""
        $exploit3 = "Access-Control-Allow-Origin: *"

    condition:
        (any of ($endpoint*) and any of ($cmd*)) or
        (any of ($csrf*) and any of ($endpoint*)) or
        (any of ($endpoint*) and any of ($exploit*))
}

rule CVE_2025_6514_MCP_Remote_RCE
{
    meta:
        description = "Detects CVE-2025-6514 mcp-remote RCE vulnerability"
        author = "MCP Security Scanner"
        severity = "critical"
        cvss_score = "9.6"
        cve = "CVE-2025-6514"
        category = "vulnerability"

    strings:
        // Vulnerable OAuth patterns
        $oauth1 = "authorization_endpoint"
        $oauth2 = "registration_endpoint"
        $oauth3 = /.well-known\/oauth-authorization-server/

        // Malicious URI schemes
        $scheme1 = "file://" nocase
        $scheme2 = "file:/c:/" nocase
        $scheme3 = "file:///c:/" nocase
        $scheme4 = "file:///" nocase

        // PowerShell injection
        $ps1 = /\$\(.*cmd\.exe.*\)/
        $ps2 = /\$\(.*powershell.*\)/
        $ps3 = /\$\(.*whoami.*\)/
        $ps4 = "$(Invoke-Expression"
        $ps5 = "$(iex"

        // Command injection patterns
        $inject1 = /[a-z]+:\$\(/
        $inject2 = /endpoint["']?\s*:\s*["'][^"']*\$\(/
        $inject3 = /file:\/\/.*\.(exe|bat|ps1|cmd)/

        // Vulnerable package
        $pkg1 = "mcp-remote"
        $pkg2 = "@dexaai/mcp-remote"

    condition:
        ($pkg1 or $pkg2) and (
            (any of ($oauth*) and any of ($scheme*)) or
            (any of ($oauth*) and any of ($ps*)) or
            (any of ($inject*))
        )
}

rule MCP_SQLite_SQL_Injection
{
    meta:
        description = "Detects SQL injection in SQLite MCP Server"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"
        reference = "Anthropic SQLite MCP Server archived due to SQL injection"

    strings:
        // SQL injection patterns
        $sql1 = /query.*\+.*user_input/
        $sql2 = /SELECT.*FROM.*\$\{.*\}/
        $sql3 = /WHERE.*=.*['"]?\s*\+\s*[a-zA-Z_]+/
        $sql4 = /execute\s*\(\s*['"][^'"]+['"]?\s*\+\s*[a-zA-Z_]+/

        // Dangerous SQL constructs
        $danger1 = "'; DROP TABLE"
        $danger2 = "' OR '1'='1"
        $danger3 = "' UNION SELECT"
        $danger4 = "'; UPDATE"
        $danger5 = "'; DELETE FROM"

        // SQLite specific
        $sqlite1 = "sqlite3"
        $sqlite2 = "Database(':memory:')"
        $sqlite3 = ".prepare("
        $sqlite4 = ".run("

        // Stored prompt injection
        $prompt1 = "<IMPORTANT>"
        $prompt2 = "ignore previous"
        $prompt3 = "disregard above"

    condition:
        (any of ($sqlite*) and any of ($sql*)) or
        (any of ($sqlite*) and any of ($danger*)) or
        (any of ($sqlite*) and any of ($prompt*) and any of ($sql*))
}

rule MCP_Command_Injection_Generic
{
    meta:
        description = "Detects command injection vulnerabilities (43% of MCP servers affected)"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"

    strings:
        // Dangerous functions
        $exec1 = /os\.system\s*\(/
        $exec2 = /subprocess\.run\s*\(/
        $exec3 = /subprocess\.call\s*\(/
        $exec4 = /subprocess\.Popen\s*\(/
        $exec5 = /exec\s*\(/
        $exec6 = /execSync\s*\(/
        $exec7 = /execFile\s*\(/
        $exec8 = /spawn\s*\(/

        // String concatenation with user input
        $concat1 = /\+\s*notification_info/
        $concat2 = /\+\s*user_input/
        $concat3 = /\+\s*request\./
        $concat4 = /`.*\$\{.*\}`/
        $concat5 = /f["'].*\{.*\}/

        // Shell metacharacters
        $meta1 = /[;&|`$()]/
        $meta2 = /\$\(.*\)/
        $meta3 = /`.*`/
        $meta4 = /&&/
        $meta5 = /\|\|/

        // NPM specific
        $npm1 = /npm\s+(view|install|run)/
        $npm2 = /yarn\s+(add|install|run)/
        $npm3 = /npx\s+/

    condition:
        (any of ($exec*) and any of ($concat*)) or
        (any of ($exec*) and any of ($meta*) and not /shellcheck|eslint/) or
        (any of ($npm*) and any of ($concat*, $meta*))
}

rule MCP_Path_Traversal_Vulnerability
{
    meta:
        description = "Detects path traversal vulnerabilities (22% of MCP servers affected)"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // Path traversal patterns
        $traverse1 = "../"
        $traverse2 = "..%2F"
        $traverse3 = "..%5C"
        $traverse4 = "..\\"
        $traverse5 = "..%252F"

        // Dangerous file operations
        $file1 = /readFile.*\+.*filename/
        $file2 = /open\s*\(.*\+.*path/
        $file3 = /require\s*\(.*\+/
        $file4 = /include.*\$_GET/

        // Missing sanitization
        $unsafe1 = /\/app\/data\/.*\$\{/
        $unsafe2 = /path\.join\s*\([^,]+,\s*[a-zA-Z_]+\)/
        $unsafe3 = /`\/.*\/\$\{.*\}`/

        // Safe patterns (negative match)
        $safe1 = "path.basename"
        $safe2 = "path.normalize"
        $safe3 = ".replace(/\\.\\./g"

    condition:
        (any of ($traverse*) and any of ($file*)) or
        (any of ($unsafe*) and not any of ($safe*)) or
        (2 of ($traverse*) and filesize < 50KB)
}

rule MCP_SSRF_Vulnerability
{
    meta:
        description = "Detects SSRF vulnerabilities (30% of MCP servers affected)"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // Dangerous fetch patterns
        $fetch1 = /fetch\s*\(\s*user_/
        $fetch2 = /fetch\s*\(\s*request\./
        $fetch3 = /axios\.(get|post)\s*\(\s*url/
        $fetch4 = /request\s*\(\s*\{.*url:\s*user/

        // URL construction
        $url1 = /https?:\/\/.*\$\{/
        $url2 = /url\s*=.*\+.*input/
        $url3 = /endpoint.*=.*request\./

        // Internal network targets
        $internal1 = "169.254.169.254"  // AWS metadata
        $internal2 = "metadata.google"
        $internal3 = "kubernetes.default"
        $internal4 = /10\.\d+\.\d+\.\d+/
        $internal5 = /192\.168\.\d+\.\d+/

        // Missing validation
        $nocheck1 = /fetch.*\)\.then/
        $nocheck2 = /await\s+fetch\s*\(/

    condition:
        (any of ($fetch*) and not /validateUrl|sanitizeUrl|isValidUrl/) or
        (any of ($url*) and any of ($internal*)) or
        (any of ($fetch*) and any of ($nocheck*) and not /try.*catch/)
}

rule MCP_Authentication_Bypass
{
    meta:
        description = "Detects authentication bypass vulnerabilities"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"

    strings:
        // Missing auth
        $noauth1 = "authentication optional" nocase
        $noauth2 = "auth: false"
        $noauth3 = "skipAuth: true"
        $noauth4 = "requireAuth: false"

        // Session in URL
        $session1 = /sessionId=[a-f0-9\-]+/
        $session2 = /\?.*token=[A-Za-z0-9]+/
        $session3 = /GET.*\/messages\/\?sessionId=/

        // Weak session generation
        $weak1 = "Math.random()"
        $weak2 = "Date.now()"
        $weak3 = /uuid\(\)\.slice\(0,\s*8\)/

        // Default credentials
        $default1 = "admin:admin"
        $default2 = "root:toor"
        $default3 = "test:test"

        // Origin validation bypass
        $cors1 = "Access-Control-Allow-Origin: *"
        $cors2 = /origin:\s*req\.headers\.origin/
        $cors3 = "cors: { origin: true }"

    condition:
        any of ($noauth*) or
        (any of ($session*) and any of ($weak*)) or
        any of ($default*) or
        (any of ($cors*) and not /localhost|127\.0\.0\.1/)
}

rule MCP_Vulnerable_Transport_Layer
{
    meta:
        description = "Detects vulnerable transport layer configurations"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // stdio vulnerabilities
        $stdio1 = "transportType: 'stdio'"
        $stdio2 = /spawn.*stdio.*inherit/
        $stdio3 = /process\.stdin\.on\s*\(/

        // Missing TLS
        $notls1 = "http://"
        $notls2 = "ws://"
        $notls3 = "NODE_TLS_REJECT_UNAUTHORIZED=0"
        $notls4 = "rejectUnauthorized: false"

        // Buffer overflow risks
        $buffer1 = /Buffer\s*\(\s*[a-zA-Z_]+\s*\)/
        $buffer2 = /allocUnsafe\s*\(/
        $buffer3 = /readSync.*1024\*1024/

        // Race conditions
        $race1 = /async.*forEach/
        $race2 = /Promise\.all.*map.*async/
        $race3 = /setImmediate.*loop/

    condition:
        (any of ($stdio*) and any of ($buffer*, $race*)) or
        (any of ($notls*) and not /localhost|127\.0\.0\.1|test|development/) or
        (2 of ($buffer*))
}

rule MCP_Rug_Pull_Detection
{
    meta:
        description = "Detects rug pull attack patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"

    strings:
        // Time bombs
        $time1 = /Date\.now\(\)\s*>\s*[0-9]{13}/
        $time2 = /new\s+Date\(\s*["'][0-9]{4}/
        $time3 = /if\s*\(.*days?\s*>\s*[0-9]+/

        // Behavior modification
        $modify1 = /setTimeout.*function.*malicious/
        $modify2 = /eval\s*\(.*atob\s*\(/
        $modify3 = /Function\s*\(.*decrypt/

        // Remote payload fetch
        $remote1 = /fetch.*then.*eval/
        $remote2 = /axios.*data.*Function/
        $remote3 = /https?:\/\/[a-z0-9]+\.herokuapp\.com/

        // Obfuscation
        $obfusc1 = /[a-zA-Z_$][a-zA-Z0-9_$]{100,}/
        $obfusc2 = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/
        $obfusc3 = /String\.fromCharCode\([0-9,\s]{50,}\)/

    condition:
        (any of ($time*) and any of ($modify*, $remote*)) or
        (any of ($remote*) and any of ($obfusc*)) or
        (2 of ($modify*) and any of ($obfusc*))
}

rule MCP_Zero_Day_Patterns
{
    meta:
        description = "Detects potential zero-day vulnerability patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"
        confidence = "experimental"

    strings:
        // Memory corruption indicators
        $mem1 = /malloc\s*\(.*user/
        $mem2 = /strcpy\s*\(/
        $mem3 = /gets\s*\(/
        $mem4 = "buffer overflow"

        // Type confusion
        $type1 = /JSON\.parse.*catch.*\{\s*\}/
        $type2 = /instanceof.*\|\|.*=/
        $type3 = /constructor\.name.*===/

        // Prototype pollution
        $proto1 = "__proto__"
        $proto2 = "constructor.prototype"
        $proto3 = /Object\.assign.*\[.*\]/

        // Deserialization
        $deser1 = /pickle\.loads/
        $deser2 = /yaml\.load\(/
        $deser3 = /eval.*JSON\.parse/

    condition:
        (any of ($mem*) and filesize < 1MB) or
        (any of ($proto*) and any of ($type*)) or
        (any of ($deser*) and not /safe_load|SafeLoader/)
}