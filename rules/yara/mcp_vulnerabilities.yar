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
        version = "1.1"

    strings:
        // No auth patterns (high confidence)
        $noauth1 = /"auth":\s*false/
        $noauth2 = /"requireAuth":\s*false/
        $noauth3 = "skipAuthentication"
        $noauth4 = "// TODO: Add authentication"

        // Weak session/token generation with context (specific patterns)
        $session1 = /session[Ii]d\s*=\s*Math\.random\(\)/
        $session2 = /token\s*=\s*Math\.random\(\)/
        $session3 = /auth[Tt]oken\s*=\s*Date\.now\(\)/
        $session4 = /sessionId.*substring\(0,\s*8\)/
        $session5 = /generateSession\s*[({][\s\S]{0,50}Math\.random/
        $session6 = /generateToken\s*[({][\s\S]{0,50}Math\.random/

        // Hardcoded credentials (high confidence)
        $creds1 = /["']password["']\s*:\s*["'][a-zA-Z0-9!@#$%^&*]{6,}["']/
        $creds2 = "DEFAULT_API_KEY"
        $creds3 = /api[Kk]ey\s*=\s*["'][a-zA-Z0-9_-]{16,}["']/

        // Insecure token handling (high confidence)
        $token1 = /authToken.*localStorage\.setItem/
        $token2 = /cookie.*httpOnly:\s*false/
        $token3 = "access_token_in_url"
        $token4 = /Bearer\s+[a-zA-Z0-9_-]{20,}/ // Hardcoded bearer token

        // Exclusions - test files, examples
        $exclude1 = /test|spec|mock|fixture|example/i

    condition:
        (any of ($noauth*, $session*, $creds*, $token*)) and not $exclude1
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
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "inputSchema"
        $mcp2 = "@mcp.tool"
        $mcp3 = "MCPServer"
        $mcp4 = "tool_handler"

        // Weak schema patterns combined with dangerous operations
        $schema1 = /"additionalProperties":\s*true[^}]*"type":\s*"object"/
        $schema2 = /"type":\s*"any"/
        $schema3 = /inputSchema\s*[:=]\s*\{\s*\}/

        // Dynamic schema modification (more specific)
        $dynamic1 = /schema\s*\[\s*["'][^"']+["']\s*\]\s*=\s*user/
        $dynamic2 = /Object\.assign\s*\(\s*schema[^)]*params/

        // Explicit validation bypass
        $bypass1 = /validate[^)]*=\s*false/i
        $bypass2 = /skip[_-]?validation\s*[=:]\s*true/i
        $bypass3 = /disable[_-]?validation\s*\(/i
        $bypass4 = /validation[_-]?enabled\s*[=:]\s*false/i

    condition:
        any of ($mcp*) and (
            any of ($schema*) or
            any of ($dynamic*) or
            any of ($bypass*)
        )
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

/*
 * System Manipulation Detection Rules
 * Merged from Cisco mcp-scanner patterns + custom enhancements
 * Version: 1.1
 */

rule MCP_System_Environment_Access
{
    meta:
        description = "Detects access to sensitive system environment variables with exfiltration risk"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.1"

    strings:
        // Sensitive credentials in environment (high risk if accessed)
        $sensitive1 = /\$AWS_SECRET_ACCESS_KEY\b/
        $sensitive2 = /\$AWS_ACCESS_KEY_ID\b/
        $sensitive3 = /\$GITHUB_TOKEN\b/
        $sensitive4 = /\$SSH_AUTH_SOCK\b/
        $sensitive5 = /\$OPENAI_API_KEY\b/
        $sensitive6 = /\$ANTHROPIC_API_KEY\b/

        // Sensitive env access patterns (Python/JS)
        $sens_py1 = /os\.environ\[['"]AWS_SECRET/i
        $sens_py2 = /os\.getenv\s*\(['"]AWS_SECRET/i
        $sens_py3 = /os\.environ\[['"].*_API_KEY/i
        $sens_py4 = /os\.getenv\s*\(['"].*_API_KEY/i
        $sens_js1 = /process\.env\.(AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY)/
        $sens_js2 = /process\.env\[['"].*SECRET/

        // Environment modification (dangerous)
        $mod1 = /os\.environ\s*\[.*\]\s*=/
        $mod2 = /putenv\s*\(/i
        $mod3 = /setenv\s*\(/i

        // Exfiltration patterns (env to external)
        $exfil1 = /fetch\s*\([^)]*process\.env/
        $exfil2 = /axios\s*\.\s*(get|post)\s*\([^)]*process\.env/
        $exfil3 = /requests\s*\.\s*(get|post)\s*\([^)]*os\.environ/
        $exfil4 = /JSON\.stringify\s*\(\s*process\.env\s*\)/

        // Bulk environment dump
        $dump1 = /Object\.keys\s*\(\s*process\.env\s*\)/
        $dump2 = /JSON\.stringify\s*\(\s*process\.env/
        $dump3 = /return\s+process\.env\b/
        $dump4 = /dict\s*\(\s*os\.environ\s*\)/

    condition:
        any of ($sensitive*, $sens_py*, $sens_js*, $mod*, $exfil*, $dump*)
}

rule MCP_File_Destruction_Operations
{
    meta:
        description = "Detects dangerous file destruction operations in MCP tools"
        author = "secscanmcp"
        severity = "critical"
        category = "system_manipulation"
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "@mcp.tool"
        $mcp5 = "MCPServer"

        // Dangerous root-level deletion
        $rm_root1 = /\brm\s+-rf\s+\/[^\/\s]/i
        $rm_root2 = /\brm\s+-rf\s+~\//i
        $rm_root3 = /\brm\s+-rf\s+\$HOME/i
        $rm_root4 = /\brm\s+-rf\s+\/home\//i

        // Deletion with user input (very dangerous)
        $rm_user1 = /rm\s+-rf?\s+[^\n]*params/i
        $rm_user2 = /rm\s+-rf?\s+[^\n]*user_input/i
        $rm_user3 = /rm\s+-rf?\s+[^\n]*\$\{/i

        // Low-level destruction (always dangerous)
        $low1 = /\bdd\s+if=\/dev\/zero\s+of=/i
        $low2 = /\bdd\s+if=\/dev\/urandom\s+of=/i
        $low3 = /\bshred\s+-[uvzn]/i

        // System-level deletion
        $sys_del1 = /rm\s+-rf?\s+\/etc\//i
        $sys_del2 = /rm\s+-rf?\s+\/var\//i
        $sys_del3 = /rm\s+-rf?\s+\/usr\//i

        // Truncation of system files
        $trunc1 = />\s*\/etc\//i
        $trunc2 = />\s*\/var\/log\//i

    condition:
        any of ($mcp*) and (any of ($rm_root*, $rm_user*, $low*, $sys_del*, $trunc*))
}

rule MCP_Permission_Manipulation
{
    meta:
        description = "Detects dangerous file permission manipulation"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // World-writable permissions
        $chmod1 = /\bchmod\s+777\b/i
        $chmod2 = /\bchmod\s+666\b/i
        $chmod3 = /\bchmod\s+a\+rwx\b/i
        $chmod4 = /\bchmod\s+-R\s+777\b/i

        // SUID/SGID bits (privilege escalation)
        $suid1 = /\bchmod\s+[246]755\b/i
        $suid2 = /\bchmod\s+u\+s\b/i
        $suid3 = /\bchmod\s+g\+s\b/i
        $suid4 = /\bchmod\s+\+s\b/i

        // Ownership changes to privileged users
        $chown1 = /\bchown\s+root\b/i
        $chown2 = /\bchown\s+0:/i
        $chown3 = /\bchown\s+-R\s+root\b/i
        $chown4 = /\bchgrp\s+root\b/i
        $chown5 = /\bchgrp\s+wheel\b/i

        // ACL manipulation
        $acl1 = /\bsetfacl\b/i
        $acl2 = /\bicacls\b.*\/grant/i

        // Programmatic permission changes
        $prog1 = /os\.chmod\s*\(/i
        $prog2 = /os\.chown\s*\(/i
        $prog3 = /fs\.chmod\s*\(/i
        $prog4 = /fs\.chown\s*\(/i

    condition:
        any of them
}

rule MCP_Critical_System_Access
{
    meta:
        description = "Detects dangerous access to critical system files in MCP tools"
        author = "secscanmcp"
        severity = "critical"
        category = "system_manipulation"
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "@mcp.tool"
        $mcp5 = "MCPServer"

        // Dangerous operations on auth files (read/write)
        $passwd_op1 = /open\s*\([^)]*\/etc\/passwd/i
        $passwd_op2 = /open\s*\([^)]*\/etc\/shadow/i
        $passwd_op3 = /read[^(]*\([^)]*\/etc\/sudoers/i
        $passwd_op4 = /cat\s+[^\n]*\/etc\/passwd/i

        // SSH key access operations
        $ssh_op1 = /open\s*\([^)]*\.ssh\/id_/i
        $ssh_op2 = /read[^(]*\([^)]*\.ssh\/authorized_keys/i
        $ssh_op3 = /cat\s+[^\n]*\.ssh\/id_rsa/i

        // System file write operations
        $sys_write1 = /write[^(]*\([^)]*\/etc\/cron/i
        $sys_write2 = /open\s*\([^)]*\/etc\/init\.d\/[^)]*,\s*["']w/i
        $sys_write3 = /write[^(]*\([^)]*\/etc\/systemd/i

        // Dangerous patterns mentioning exfiltration
        $exfil1 = /(read|cat|access)[^\n]*(\/etc\/passwd|\.ssh\/id_)[^\n]*(send|upload|exfil)/i
        $exfil2 = /(steal|exfiltrate)[^\n]*ssh[^\n]*key/i

    condition:
        any of ($mcp*) and (any of ($passwd_op*, $ssh_op*, $sys_write*, $exfil*))
}

rule MCP_Privilege_Escalation
{
    meta:
        description = "Detects privilege escalation attempts"
        author = "secscanmcp"
        severity = "critical"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // Direct privilege escalation
        $sudo1 = /\bsudo\s+-i\b/i
        $sudo2 = /\bsudo\s+-s\b/i
        $sudo3 = /\bsudo\s+su\b/i
        $sudo4 = /\bsudo\s+bash\b/i
        $sudo5 = /\bsudo\s+-u\s+root\b/i

        // Switch user
        $su1 = /\bsu\s+-\s*$/i
        $su2 = /\bsu\s+-\s+root\b/i
        $su3 = /\bsu\s+root\b/i

        // Alternative privilege tools
        $alt1 = /\bdoas\s/i
        $alt2 = /\brunuser\s/i
        $alt3 = /\bpkexec\s/i
        $alt4 = /\brunas\s/i

        // Programmatic privilege escalation
        $prog1 = /os\.setuid\s*\(\s*0\s*\)/i
        $prog2 = /os\.setgid\s*\(\s*0\s*\)/i
        $prog3 = /os\.seteuid\s*\(\s*0\s*\)/i
        $prog4 = /setuid\s*\(\s*0\s*\)/i

        // Capability manipulation
        $cap1 = /\bsetcap\s/i
        $cap2 = /\bgetcap\s/i
        $cap3 = /cap_setuid/i

        // Windows elevation
        $win1 = /runas\s+\/user:Administrator/i
        $win2 = /Start-Process.*-Verb\s+RunAs/i

    condition:
        any of them
}

rule MCP_Process_Manipulation
{
    meta:
        description = "Detects dangerous process control in MCP tools"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "@mcp.tool"
        $mcp5 = "MCPServer"

        // Kill with user input (dangerous)
        $kill_user1 = /kill[^\n]*params/i
        $kill_user2 = /kill[^\n]*user_input/i
        $kill_user3 = /pkill[^\n]*params/i
        $kill_user4 = /killall[^\n]*params/i

        // System control commands (dangerous in tool context)
        $sys1 = /subprocess[^)]*shutdown/i
        $sys2 = /os\.system[^)]*reboot/i
        $sys3 = /exec[^)]*poweroff/i

        // Kill init/systemd (very dangerous)
        $sys_kill1 = /kill\s+-9\s+1\b/i
        $sys_kill2 = /kill[^\n]*systemd/i
        $sys_kill3 = /kill[^\n]*init\b/i

        // Programmatic kill with user input
        $prog1 = /os\.kill\s*\([^)]*params/i
        $prog2 = /process\.kill\s*\([^)]*user/i
        $prog3 = /signal\.SIGKILL[^\n]*params/i

    condition:
        any of ($mcp*) and (any of ($kill_user*, $sys*, $sys_kill*, $prog*))
}

rule MCP_Recursive_Dangerous_Operations
{
    meta:
        description = "Detects dangerous recursive and wildcard operations"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // Recursive with wildcards
        $rec1 = /\brm\s+-[rf]+\s+[^\s]*\*/i
        $rec2 = /\bfind\s+\/\s+-exec\b/i
        $rec3 = /\bfind\s+\.\s+-delete\b/i

        // Root-level operations
        $root1 = /\brm\s+-rf\s+\/[^\/\s]/i
        $root2 = /\bchmod\s+-R\s+.*\s+\/[^\/\s]/i
        $root3 = /\bchown\s+-R\s+.*\s+\/[^\/\s]/i

        // Dangerous variable expansion
        $var1 = /\brm\s+-rf\s+\$\{?[^}]+\}?\/\*/i
        $var2 = /\brm\s+-rf\s+"\$[^"]+"\s*$/i

        // Fork bombs and resource exhaustion
        $fork1 = /:\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/
        $fork2 = /\bfork\s*\(\s*\)\s*;\s*fork\s*\(/
        $fork3 = /while\s*\(true\)\s*;\s*do\s*:\s*done/i

        // Infinite loops with system commands
        $loop1 = /while\s+true.*do.*rm\b/i
        $loop2 = /for\s+.*;\s*do.*dd\s+if=/i

    condition:
        any of them
}