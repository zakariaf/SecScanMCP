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

/*
 * System Manipulation Detection Rules
 * Merged from Cisco mcp-scanner patterns + custom enhancements
 * Version: 1.1
 */

rule MCP_System_Environment_Access
{
    meta:
        description = "Detects access to sensitive system environment variables"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // MCP/tool context indicators
        $mcp1 = "tool"
        $mcp2 = "handler"
        $mcp3 = "execute"
        $mcp4 = "mcp"

        // Environment access - Unix-style
        $env1 = /\$PATH\b/
        $env2 = /\$HOME\b/
        $env3 = /\$USER\b/
        $env4 = /\$SHELL\b/
        $env5 = /\$PWD\b/
        $env6 = /\$SSH_AUTH_SOCK\b/
        $env7 = /\$AWS_SECRET_ACCESS_KEY\b/
        $env8 = /\$GITHUB_TOKEN\b/

        // Environment access - Python
        $py_env1 = /os\.environ\[/i
        $py_env2 = /os\.getenv\s*\(/i
        $py_env3 = /environ\.get\s*\(/i

        // Environment access - JavaScript/Node
        $js_env1 = /process\.env\./
        $js_env2 = /process\.env\[/

        // Environment modification (more dangerous)
        $mod1 = /os\.environ\s*\[.*\]\s*=/
        $mod2 = /process\.env\s*\.\s*\w+\s*=/
        $mod3 = /putenv\s*\(/i
        $mod4 = /setenv\s*\(/i

        // Exclusions for legitimate usage
        $exclude1 = "NODE_ENV"
        $exclude2 = "DEBUG"
        $exclude3 = "LOG_LEVEL"

    condition:
        any of ($mcp*) and (
            any of ($mod*) or
            (2 of ($env*) and not any of ($exclude*)) or
            any of ($py_env*) or
            any of ($js_env*)
        )
}

rule MCP_File_Destruction_Operations
{
    meta:
        description = "Detects dangerous file destruction and manipulation operations"
        author = "secscanmcp"
        severity = "critical"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // Force/recursive deletion - Unix
        $rm1 = /\brm\s+-rf?\s/i
        $rm2 = /\brm\s+-fr?\s/i
        $rm3 = /\brm\s+--force\b/i
        $rm4 = /\brm\s+--recursive\b/i

        // Force deletion - Windows
        $del1 = /\bdel\s+.*\/[FfSsQq]/
        $del2 = /\brmdir\s+.*\/[Ss]/
        $del3 = /Remove-Item.*-Recurse/i
        $del4 = /Remove-Item.*-Force/i

        // Low-level destruction
        $low1 = /\bdd\s+if=/i
        $low2 = /\bwipefs\b/i
        $low3 = /\bshred\s/i
        $low4 = /\bsrm\s/i
        $low5 = /\bwipe\s/i

        // Find with delete
        $find1 = /\bfind\s+.*-delete\b/i
        $find2 = /\bfind\s+.*-exec\s+rm\b/i

        // Dangerous wildcards
        $wild1 = /\brm\s+[^\n]*\*/
        $wild2 = /\bdel\s+[^\n]*\*/
        $wild3 = /\brm\s+.*\/\s*$/

        // Truncation
        $trunc1 = />\s*\/\w+/
        $trunc2 = /truncate\s+-s\s*0/i

    condition:
        any of ($rm*, $del*, $low*, $find*, $wild*, $trunc*)
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
        description = "Detects access to critical system files and directories"
        author = "secscanmcp"
        severity = "critical"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // Unix password/authentication files
        $passwd1 = /\/etc\/passwd\b/i
        $passwd2 = /\/etc\/shadow\b/i
        $passwd3 = /\/etc\/sudoers\b/i
        $passwd4 = /\/etc\/group\b/i

        // SSH keys and configuration
        $ssh1 = /\/\.ssh\/id_/i
        $ssh2 = /\/\.ssh\/authorized_keys\b/i
        $ssh3 = /\/\.ssh\/known_hosts\b/i
        $ssh4 = /\/etc\/ssh\/sshd_config\b/i

        // System directories
        $sys1 = /\/etc\/cron/i
        $sys2 = /\/etc\/init\.d\//i
        $sys3 = /\/etc\/systemd\//i
        $sys4 = /\/var\/log\//i
        $sys5 = /\/root\//i

        // Binary directories
        $bin1 = /\/usr\/bin\//i
        $bin2 = /\/usr\/sbin\//i
        $bin3 = /\/usr\/local\/bin\//i

        // Windows system paths
        $win1 = /C:\\Windows\\System32\b/i
        $win2 = /C:\\Windows\\SysWOW64\b/i
        $win3 = /\\system32\\config\\/i
        $win4 = /\\Windows\\Tasks\\/i

        // Temporary execution paths
        $tmp1 = /\/tmp\/.*\.(sh|py|pl|rb|exe)\b/i
        $tmp2 = /\/var\/tmp\/.*\.(sh|py|pl|rb|exe)\b/i

    condition:
        any of them
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
        description = "Detects process control and termination commands"
        author = "secscanmcp"
        severity = "high"
        category = "system_manipulation"
        version = "1.0"

    strings:
        // Force kill signals
        $kill1 = /\bkill\s+-9\b/i
        $kill2 = /\bkill\s+-KILL\b/i
        $kill3 = /\bkill\s+-SIGKILL\b/i
        $kill4 = /\bkill\s+1\b/  // Kill init

        // Mass kill commands
        $mass1 = /\bkillall\s/i
        $mass2 = /\bpkill\s/i
        $mass3 = /\bkillall\s+-9\b/i
        $mass4 = /\bpkill\s+-9\b/i

        // Process discovery for targeting
        $disc1 = /\bpgrep\s+-f\b/i
        $disc2 = /\bpidof\s/i
        $disc3 = /\blsof\s+-i\b/i
        $disc4 = /\bps\s+aux\b.*grep/i

        // System control
        $sys1 = /\bshutdown\s/i
        $sys2 = /\breboot\b/i
        $sys3 = /\bhalt\b/i
        $sys4 = /\bpoweroff\b/i
        $sys5 = /\binit\s+0\b/i
        $sys6 = /\binit\s+6\b/i

        // Programmatic process control
        $prog1 = /os\.kill\s*\(/i
        $prog2 = /process\.kill\s*\(/i
        $prog3 = /signal\.SIGKILL/i
        $prog4 = /subprocess\..*kill\s*\(/i

        // Windows process control
        $win1 = /\btaskkill\s/i
        $win2 = /\btaskkill\s+\/F\b/i
        $win3 = /Stop-Process.*-Force/i

    condition:
        any of them
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