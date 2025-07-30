/*
YARA rules for detecting injection vulnerabilities in MCP implementations
*/

rule MCP_Command_Injection_Comprehensive
{
    meta:
        description = "Comprehensive command injection detection (43% of MCP servers affected)"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "injection"

    strings:
        // Dangerous execution functions
        $exec1 = /os\.system\s*\(/
        $exec2 = /subprocess\.(run|call|Popen|check_output)\s*\(/
        $exec3 = /exec\s*\(/
        $exec4 = /execSync\s*\(/
        $exec5 = /execFile\s*\(/
        $exec6 = /spawn\s*\(/
        $exec7 = /eval\s*\(/
        $exec8 = /__import__\(['"]os['"]\)\.system/

        // String concatenation patterns
        $concat1 = /\+\s*(request|req)\./
        $concat2 = /\+\s*user[_-]?input/
        $concat3 = /\+\s*params\./
        $concat4 = /`[^`]*\$\{[^}]+\}`/
        $concat5 = /f["'][^"']*\{[^}]+\}/
        $concat6 = /".*"\s*\+\s*[a-zA-Z_]+/

        // Shell metacharacters
        $shell1 = /[;&|]/
        $shell2 = /\$\(/
        $shell3 = /`/
        $shell4 = "&&"
        $shell5 = "||"
        $shell6 = ">>"
        $shell7 = "2>&1"

        // Common injection payloads
        $payload1 = "; cat /etc/passwd"
        $payload2 = "&& whoami"
        $payload3 = "| nc "
        $payload4 = "; curl "
        $payload5 = "&& wget "

    condition:
        (any of ($exec*) and any of ($concat*)) or
        (any of ($exec*) and 2 of ($shell*)) or
        any of ($payload*) or
        (any of ($exec*) and not /sanitize|escape|validate/)
}

rule MCP_SQL_Injection_Advanced
{
    meta:
        description = "Advanced SQL injection detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "injection"

    strings:
        // Dynamic query construction
        $query1 = /query\s*=.*\+.*user/
        $query2 = /sql\s*=.*\+.*request/
        $query3 = /SELECT.*FROM.*\$\{/
        $query4 = /WHERE.*=\s*['"]?\s*\+/
        $query5 = /INSERT.*VALUES.*\+/
        $query6 = /UPDATE.*SET.*\+/

        // Template string injection
        $template1 = /`SELECT.*\$\{[^}]+\}`/
        $template2 = /`INSERT.*\$\{[^}]+\}`/
        $template3 = /`DELETE.*\$\{[^}]+\}`/

        // NoSQL injection
        $nosql1 = /\$where.*user/
        $nosql2 = /\$gt.*req\./
        $nosql3 = /\$regex.*input/
        $nosql4 = /eval\s*\(.*query/

        // ORM injection
        $orm1 = /.findOne\s*\(\s*\{[^}]*\$[^}]*\}/
        $orm2 = /.where\s*\(.*\+.*\)/
        $orm3 = /.raw\s*\(/

        // Common payloads
        $payload1 = "' OR '1'='1"
        $payload2 = "'; DROP TABLE"
        $payload3 = "' UNION SELECT"
        $payload4 = "1=1"
        $payload5 = "admin'--"

    condition:
        any of ($query*) or
        any of ($template*) or
        any of ($nosql*) or
        any of ($orm*) or
        any of ($payload*)
}

rule MCP_LDAP_Injection
{
    meta:
        description = "Detects LDAP injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "injection"

    strings:
        // LDAP query construction
        $ldap1 = /\(\w+=/
        $ldap2 = /ldap.*search.*\+/
        $ldap3 = /filter\s*=.*\+.*user/
        $ldap4 = /cn=.*\$\{/
        $ldap5 = /uid=.*req\./

        // Dangerous patterns
        $danger1 = /\)\(\w+=/
        $danger2 = "*)(objectClass=*"
        $danger3 = /\|.*\(/
        $danger4 = "&(uid="

        // Missing escaping
        $noescape1 = /ldap.*[^\\]\(/
        $noescape2 = /filter.*[^\\]\*/
        $noescape3 = /search.*[^\\]\)/

    condition:
        (any of ($ldap*) and not /escape|sanitize/) or
        any of ($danger*) or
        any of ($noescape*)
}

rule MCP_XPath_Injection
{
    meta:
        description = "Detects XPath injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "injection"

    strings:
        // XPath construction
        $xpath1 = /\/\/.*\[.*=.*\+/
        $xpath2 = /xpath.*\+.*input/
        $xpath3 = /selectNodes.*\+/
        $xpath4 = /evaluate\s*\(.*\+/

        // Dangerous patterns
        $danger1 = "' or '1'='1"
        $danger2 = "] | //*["
        $danger3 = "1=1"
        $danger4 = /position\(\)=/

        // XML patterns
        $xml1 = ".parseXML("
        $xml2 = "DOMParser()"
        $xml3 = ".loadXML("

    condition:
        (any of ($xpath*) and any of ($xml*)) or
        (any of ($danger*) and any of ($xml*))
}

rule MCP_Header_Injection
{
    meta:
        description = "Detects HTTP header injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "injection"

    strings:
        // Header setting patterns
        $header1 = /setHeader.*req\./
        $header2 = /res\.set\(.*user/
        $header3 = /headers\[.*\]\s*=.*input/
        $header4 = /Location:.*\+/

        // CRLF injection
        $crlf1 = "\\r\\n"
        $crlf2 = "%0d%0a"
        $crlf3 = "%0D%0A"
        $crlf4 = "\r\n"

        // Response splitting
        $split1 = /Set-Cookie:.*\\r\\n/
        $split2 = /Content-Type:.*\\r\\n/
        $split3 = "HTTP/1.1 200"

    condition:
        (any of ($header*) and any of ($crlf*)) or
        (any of ($header*) and any of ($split*))
}

rule MCP_Template_Injection
{
    meta:
        description = "Detects template injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "injection"

    strings:
        // Template engines
        $engine1 = "Jinja2"
        $engine2 = "Handlebars"
        $engine3 = "EJS"
        $engine4 = "Pug"
        $engine5 = "Mustache"

        // Dangerous rendering
        $render1 = /render.*user.*input/
        $render2 = /compile\s*\(.*req\./
        $render3 = /template.*\+.*params/
        $render4 = /{{{.*}}}/

        // SSTI payloads
        $ssti1 = "{{7*7}}"
        $ssti2 = "${7*7}"
        $ssti3 = "<%= 7*7 %>"
        $ssti4 = "#{7*7}"

        // RCE patterns
        $rce1 = "__globals__"
        $rce2 = "__builtins__"
        $rce3 = "process.mainModule"
        $rce4 = "require('child_process')"

    condition:
        (any of ($engine*) and any of ($render*)) or
        any of ($ssti*) or
        (any of ($engine*) and any of ($rce*))
}

rule MCP_XXE_Injection
{
    meta:
        description = "Detects XML External Entity injection"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "injection"

    strings:
        // XXE patterns
        $xxe1 = "<!DOCTYPE"
        $xxe2 = "<!ENTITY"
        $xxe3 = "SYSTEM"
        $xxe4 = "file:///"
        $xxe5 = "http://"

        // Parser configuration
        $parser1 = "libxmljs"
        $parser2 = "xml2js"
        $parser3 = "parseXML"
        $parser4 = "DOMParser"

        // Dangerous features
        $feature1 = "setFeature"
        $feature2 = "external_general_entities"
        $feature3 = "load_external_dtd"
        $feature4 = "noent: true"

    condition:
        (any of ($xxe*) and any of ($parser*)) or
        (any of ($parser*) and not any of ($feature*))
}

rule MCP_Log_Injection
{
    meta:
        description = "Detects log injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "injection"

    strings:
        // Logging patterns
        $log1 = /console\.log.*req\./
        $log2 = /logger\.(info|warn|error).*user/
        $log3 = /winston.*input/
        $log4 = /log4j.*params/

        // CRLF in logs
        $crlf1 = /log.*\\r\\n/
        $crlf2 = /logger.*%0d%0a/

        // Log forging
        $forge1 = /\]\s*\[/
        $forge2 = "\\n\\d{4}-\\d{2}-\\d{2}"
        $forge3 = /INFO.*ERROR/

    condition:
        (any of ($log*) and any of ($crlf*)) or
        (any of ($log*) and any of ($forge*))
}

rule MCP_Email_Header_Injection
{
    meta:
        description = "Detects email header injection"
        author = "MCP Security Scanner"
        severity = "high"
        category = "injection"

    strings:
        // Email patterns
        $email1 = /sendMail.*to:.*req\./
        $email2 = /subject:.*user.*input/
        $email3 = /from:.*params\./

        // Header injection
        $inject1 = "\\nCc:"
        $inject2 = "\\nBcc:"
        $inject3 = "%0ACc:"
        $inject4 = "\\nContent-Type:"

        // Mail functions
        $mail1 = "nodemailer"
        $mail2 = "sendgrid"
        $mail3 = "mailgun"

    condition:
        (any of ($email*) and any of ($inject*)) or
        (any of ($mail*) and any of ($inject*))
}

rule MCP_Expression_Injection
{
    meta:
        description = "Detects expression language injection"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "injection"

    strings:
        // Expression patterns
        $expr1 = /eval\s*\(.*user/
        $expr2 = /Function\s*\(.*req\./
        $expr3 = /new Function.*input/
        $expr4 = "vm.runInNewContext"

        // Math expressions
        $math1 = /mathjs.*evaluate.*user/
        $math2 = /expr-eval.*compile.*req/
        $math3 = /formula.*parse.*input/

        // Sandbox escape
        $escape1 = "constructor.constructor"
        $escape2 = "process.mainModule"
        $escape3 = "__proto__"
        $escape4 = "require('child_process')"

    condition:
        any of ($expr*) or
        any of ($math*) or
        (any of ($expr*, $math*) and any of ($escape*))
}

rule MCP_GraphQL_Injection
{
    meta:
        description = "Detects GraphQL injection vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "injection"

    strings:
        // GraphQL patterns
        $gql1 = /query\s*{.*\$\{/
        $gql2 = /mutation.*\+.*input/
        $gql3 = /buildSchema.*user/
        $gql4 = "graphql-tag"

        // Dangerous queries
        $danger1 = "__schema"
        $danger2 = "__type"
        $danger3 = "introspection"
        $danger4 = /alias[0-9]+:/

        // Batching attacks
        $batch1 = /query.*\[.*\]/
        $batch2 = "operationName"
        $batch3 = "variables"

    condition:
        any of ($gql*) or
        (any of ($danger*) and /graphql|apollo|relay/) or
        (all of ($batch*) and /graphql/)
}