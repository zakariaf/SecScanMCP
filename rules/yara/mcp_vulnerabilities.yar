/*
YARA rules for detecting behavioral vulnerability patterns in MCP implementations
Focus: Generic patterns that indicate vulnerable coding practices in MCP context
*/

import "math"

rule MCP_Behavioral_Command_Injection
{
    meta:
        description = "MCP-specific command injection patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"

    strings:
        // MCP tool context
        $tool1 = /"tool":\s*"[^"]+"/
        $tool2 = "tool_handler"
        $tool3 = "execute_tool"
        $tool4 = "run_tool"

        // Dangerous parameter handling
        $param1 = /"parameters":\s*\{[^}]*\$\{/
        $param2 = /"args":\s*\[.*\+.*user/
        $param3 = /params\[['"][^'"]+['"]\]\s*\+/
        $param4 = /`.*\$\{.*tool.*\}`/

        // Unsafe execution
        $exec1 = /os\.system.*params/
        $exec2 = /subprocess\.run.*user_input/
        $exec3 = /exec.*request\./
        $exec4 = /eval.*tool_response/

        // Missing sanitization
        $unsafe1 = /execute.*without.*sanitize/
        $unsafe2 = /TODO.*validate.*input/
        $unsafe3 = /FIXME.*injection/

    condition:
        any of ($tool*) and (
            (any of ($param*) and any of ($exec*)) or
            (any of ($exec*) and not /sanitize|escape|validate|safe/) or
            any of ($unsafe*)
        )
}

rule MCP_SSRF_Via_Tool_URLs
{
    meta:
        description = "SSRF vulnerabilities in MCP tool implementations"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // URL construction from parameters
        $url1 = /url\s*=.*params\[/
        $url2 = /endpoint.*\+.*user_/
        $url3 = /https?:\/\/.*\$\{.*\}/
        $url4 = /"url":\s*user_input/

        // Dangerous fetch patterns
        $fetch1 = /fetch\(.*params\./
        $fetch2 = /axios\.get\(.*request\./
        $fetch3 = /requests\.get\(.*tool_input/

        // Internal network indicators
        $internal1 = "169.254.169.254"  // AWS metadata
        $internal2 = /10\.\d+\.\d+\.\d+/
        $internal3 = "kubernetes.default"
        $internal4 = "host.docker.internal"

        // Missing validation
        $nocheck1 = /fetch.*\)\.then/
        $nocheck2 = /await.*request.*\(/

    condition:
        (any of ($url*) and any of ($fetch*)) or
        (any of ($fetch*) and any of ($internal*)) or
        (any of ($fetch*) and any of ($nocheck*) and not /validateUrl|allowedHosts/)
}

rule MCP_Path_Traversal_In_Tools
{
    meta:
        description = "Path traversal in MCP file-handling tools"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // File operations in tool context
        $file1 = "readFile"
        $file2 = "writeFile"
        $file3 = "fs.readFileSync"
        $file4 = "open("

        // Path construction
        $path1 = /path\.join.*params/
        $path2 = /filename.*=.*request\./
        $path3 = /\+.*['"]\/['"]\s*\+/

        // Traversal patterns
        $traverse1 = "../"
        $traverse2 = "..%2F"
        $traverse3 = "..\\"

        // Missing sanitization
        $unsafe1 = /readFile.*\+/
        $unsafe2 = /open\s*\(.*user/

    condition:
        any of ($file*) and (
            any of ($traverse*) or
            (any of ($path*) and not /basename|normalize|sanitizePath/) or
            any of ($unsafe*)
        )
}

rule MCP_Weak_Authentication_Pattern
{
    meta:
        description = "Weak authentication in MCP servers"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "vulnerability"

    strings:
        // No auth patterns
        $noauth1 = /"auth":\s*false/
        $noauth2 = /"requireAuth":\s*false/
        $noauth3 = "skipAuthentication"
        $noauth4 = "// TODO: Add authentication"

        // Weak session handling
        $session1 = "Math.random()"
        $session2 = "Date.now()"
        $session3 = /sessionId.*substring\(0,\s*8\)/

        // Hardcoded credentials
        $creds1 = /"password":\s*"[^"]+"/
        $creds2 = "DEFAULT_API_KEY"
        $creds3 = /token\s*=\s*["']Bearer/

        // Insecure token handling
        $token1 = /token.*localStorage/
        $token2 = /cookie.*httpOnly:\s*false/
        $token3 = "access_token_in_url"

    condition:
        any of ($noauth*) or
        (any of ($session*) and /auth|session|token/) or
        any of ($creds*) or
        any of ($token*)
}

rule MCP_Race_Condition_Pattern
{
    meta:
        description = "Race condition vulnerabilities in MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // Async without proper locking
        $async1 = /async.*forEach/
        $async2 = /Promise\.all.*map.*async/
        $async3 = /parallel.*tool.*execution/

        // Shared state modification
        $state1 = "global_context"
        $state2 = "shared_tools"
        $state3 = "mcp_state"

        // Missing synchronization
        $nosync1 = /modify.*context.*async/
        $nosync2 = /update.*tool.*parallel/
        $nosync3 = "// FIXME: Race condition"

        // Time-of-check-time-of-use
        $toctou1 = /if.*exists.*then.*use/
        $toctou2 = /check.*permission.*execute/

    condition:
        (any of ($async*) and any of ($state*)) or
        any of ($nosync*) or
        (any of ($toctou*) and /async|await|Promise/)
}

rule MCP_Schema_Validation_Bypass
{
    meta:
        description = "Schema validation vulnerabilities in MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // Weak schema patterns
        $schema1 = /"additionalProperties":\s*true/
        $schema2 = /"type":\s*"any"/
        $schema3 = /schema\s*=\s*\{\s*\}/
        $schema4 = "// Skip validation"

        // Dynamic schema modification
        $dynamic1 = /schema\[.*\]\s*=/
        $dynamic2 = "Object.assign(schema"
        $dynamic3 = "merge_schemas"

        // Validation bypass
        $bypass1 = /validate.*catch.*continue/
        $bypass2 = /if.*!validate.*return\s+true/
        $bypass3 = "disable_validation"

    condition:
        any of ($schema*) or
        any of ($dynamic*) or
        any of ($bypass*)
}

rule MCP_Memory_Leak_Pattern
{
    meta:
        description = "Memory leak vulnerabilities in MCP servers"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "vulnerability"

    strings:
        // Unbounded collections
        $collect1 = /messages\.push.*while\s*\(true/
        $collect2 = /context\.append.*never.*clear/
        $collect3 = "unlimited_history"

        // Missing cleanup
        $leak1 = /setInterval.*no.*clear/
        $leak2 = /addEventListener.*no.*remove/
        $leak3 = "// TODO: Clean up listeners"

        // Resource exhaustion
        $exhaust1 = /buffer.*allocUnsafe.*loop/
        $exhaust2 = /cache.*no.*limit/
        $exhaust3 = "max_size = Infinity"

    condition:
        any of ($collect*) or
        any of ($leak*) or
        any of ($exhaust*)
}

rule MCP_Error_Information_Disclosure
{
    meta:
        description = "Information disclosure through error messages"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "vulnerability"

    strings:
        // Stack traces in responses
        $stack1 = /catch.*res\.json.*stack/
        $stack2 = /error\.stack.*send/
        $stack3 = "include_stack_trace: true"

        // Sensitive info in errors
        $info1 = /error.*password/
        $info2 = /catch.*api_key/
        $info3 = /exception.*connection_string/

        // Debug mode in production
        $debug1 = "DEBUG = true"
        $debug2 = "development === 'production'"
        $debug3 = "verbose_errors: true"

    condition:
        any of ($stack*) or
        any of ($info*) or
        any of ($debug*)
}

rule MCP_Type_Confusion_Vulnerability
{
    meta:
        description = "Type confusion vulnerabilities in MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // Actually dangerous type coercion (not just any string comparison)
        $type1 = /parseInt\s*\(\s*user_input\s*\)/
        $type2 = /parseFloat\s*\(\s*params\[/
        $type3 = /Number\s*\(\s*req\.body/
        $type4 = /JSON\.parse\s*\(\s*user_.*\)\s*catch\s*\{\s*\}/
        $type5 = /eval\s*\(\s*.*user.*\)/

        // Prototype pollution risk
        $proto1 = /__proto__\s*=/
        $proto2 = /constructor\.prototype\s*=/
        $proto3 = /Object\.assign\s*\(\s*.*\s*,\s*req\.body/
        $proto4 = /\{\s*\[.*user.*\]\s*:/

        // Dangerous type assumptions in MCP context
        $assume1 = /tool_params\s*\.\s*\w+\s*\+\s*['"]/  // String concatenation without type check
        $assume2 = /request\.\w+\s*-\s*\d+/              // Math ops on user input
        $assume3 = /params\s*\[\s*.*\s*\]\s*\|\|\s*0/    // Assuming numeric with fallback

    condition:
        any of ($type*) or
        any of ($proto*) or
        any of ($assume*)
}

rule MCP_Insufficient_Rate_Limiting
{
    meta:
        description = "Missing or weak rate limiting in MCP servers"
        author = "MCP Security Scanner"
        severity = "high"
        category = "vulnerability"

    strings:
        // No rate limiting
        $norl1 = "// TODO: Add rate limiting"
        $norl2 = "unlimited_requests"
        $norl3 = "rate_limit: null"

        // Weak limits
        $weak1 = /rate_limit.*1000/  // Very high
        $weak2 = /limit.*per.*second.*100/
        $weak3 = "bypass_rate_limit"

        // Resource intensive operations
        $resource1 = "execute_tool"
        $resource2 = "process_large_context"
        $resource3 = "generate_response"

    condition:
        (any of ($norl*) and any of ($resource*)) or
        (any of ($weak*) and any of ($resource*))
}