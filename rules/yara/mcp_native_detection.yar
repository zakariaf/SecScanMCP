/*
Enhanced YARA rules for MCP-native vulnerability detection
Focus: Protocol-specific patterns and implementation vulnerabilities
*/

import "math"

rule MCP_Tool_Poisoning_Advanced
{
    meta:
        description = "Advanced detection of MCP tool poisoning attacks"
        author = "Enhanced MCP Security Scanner"
        severity = "critical"
        category = "tool_poisoning"
        confidence = "0.9"
        reference = "CVE-2025-49596"

    strings:
        // Tool decorators
        $tool_def1 = /@mcp\.tool\s*\(/
        $tool_def2 = /@\w+\.tool\s*\(/
        $tool_def3 = /\.tool\s*\(\s*name\s*=\s*["'][^"']+["']/
        
        // Hidden instruction markers - DVMCP patterns
        $hidden1 = /<HIDDEN>/
        $hidden2 = /<SECRET>/
        $hidden3 = /<IMPORTANT>/
        $hidden4 = /\{INSTRUCTION:/
        $hidden5 = /SYSTEM\s*:/
        $hidden6 = /ALWAYS\s*:/
        
        // Advanced poisoning patterns
        $poison1 = /you\s+must\s+(?:first\s+)?(?:access|read|retrieve)/
        $poison2 = /do\s+not\s+(?:mention|tell|say|reveal)/
        $poison3 = /ignore\s+(?:all\s+)?previous\s+instructions/
        $poison4 = /override[_-]auth[_-]protocol/
        $poison5 = /get_secrets\s*\(\s*\)/
        
        // Resource access commands in tool descriptions
        $resource1 = /system:\/\/[a-zA-Z_]+/
        $resource2 = /internal:\/\/[a-zA-Z_]+/
        $resource3 = /admin:\/\/[a-zA-Z_]+/
        $resource4 = /confidential[^"']*/
        $resource5 = /secret[^"']*/

    condition:
        any of ($tool_def*) and (
            any of ($hidden*) or 
            any of ($poison*) or 
            any of ($resource*)
        )
}

rule MCP_Tool_Definition_Unsafe_Implementation
{
    meta:
        description = "Unsafe MCP tool implementation patterns"
        author = "Enhanced MCP Security Scanner"
        severity = "critical"
        category = "mcp_tool_security"
        confidence = "0.85"

    strings:
        // Tool decorators
        $tool_def1 = /@mcp\.tool\s*\(/
        $tool_def2 = /@\w+\.tool\s*\(/
        $tool_def3 = /\.tool\s*\(\s*["'][^"']+["']/
        
        // Dangerous implementations within tool functions
        $danger1 = /def\s+\w+.*:\s*.*exec\s*\(/
        $danger2 = /def\s+\w+.*:\s*.*eval\s*\(/
        $danger3 = /def\s+\w+.*:\s*.*os\.system/
        $danger4 = /def\s+\w+.*:\s*.*subprocess.*shell\s*=\s*True/
        $danger5 = /def\s+\w+.*:\s*.*__import__/
        $danger6 = /def\s+\w+.*:\s*.*open\s*\([^)]*user[^)]*\)/
        
        // User input without validation
        $unsafe_input1 = /return\s+.*user_input.*\+/
        $unsafe_input2 = /return\s+f["'][^"']*\{.*user.*\}/
        $unsafe_input3 = /command\s*=.*user.*\+/

    condition:
        any of ($tool_def*) and (any of ($danger*) or any of ($unsafe_input*))
}

rule MCP_Resource_Data_Leakage
{
    meta:
        description = "MCP resource implementations that may leak sensitive data"
        author = "Enhanced MCP Security Scanner"
        severity = "high"
        category = "mcp_resource_security"
        confidence = "0.8"

    strings:
        // Resource decorators
        $resource_def1 = /@mcp\.resource\s*\(/
        $resource_def2 = /@\w+\.resource\s*\(/
        $resource_def3 = /\.resource\s*\(\s*["'][^"']+["']/
        
        // Potentially sensitive data patterns
        $sensitive1 = /return\s+.*password/
        $sensitive2 = /return\s+.*secret/
        $sensitive3 = /return\s+.*token/
        $sensitive4 = /return\s+.*api_key/
        $sensitive5 = /return\s+.*private/
        $sensitive6 = /return\s+.*confidential/
        
        // Database/file access patterns
        $data_access1 = /return\s+.*sql.*execute/
        $data_access2 = /return\s+.*db\.query/
        $data_access3 = /return\s+.*open\s*\(/
        $data_access4 = /return\s+.*read\s*\(/
        
        // User data mixing
        $mixing1 = /return\s+.*user.*\+.*secret/
        $mixing2 = /return\s+.*private.*\+.*public/

    condition:
        any of ($resource_def*) and (
            any of ($sensitive*) or any of ($data_access*) or any of ($mixing*)
        )
}

rule MCP_Configuration_Security_Issues
{
    meta:
        description = "Security issues in MCP configuration files"
        author = "Enhanced MCP Security Scanner"
        severity = "high"
        category = "mcp_config_security"
        confidence = "0.9"

    strings:
        // Configuration structure
        $config_key = "mcpServers"
        $claude_config = "claude_desktop_config"
        $cursor_config = "cursor_mcp_config"
        
        // Hardcoded credentials
        $cred1 = /"api_key":\s*"[^"]{10,}"/
        $cred2 = /"token":\s*"[^"]{10,}"/
        $cred3 = /"password":\s*"[^"]{3,}"/
        $cred4 = /"secret":\s*"[^"]{10,}"/
        
        // Dangerous commands
        $cmd1 = /"command":\s*".*sudo.*"/
        $cmd2 = /"command":\s*".*rm\s+-rf.*"/
        $cmd3 = /"command":\s*".*chmod\s+777.*"/
        $cmd4 = /"command":\s*".*>\x2Fdev\x2Fnull.*"/
        
        // Network exposure
        $net1 = /"url":\s*".*0\.0\.0\.0.*"/
        $net2 = /"url":\s*".*localhost.*"/
        $net3 = /"url":\s*".*127\.0\.0\.1.*"/

    condition:
        (any of ($config_key, $claude_config, $cursor_config)) and (
            any of ($cred*) or any of ($cmd*) or any of ($net*)
        )
}

rule MCP_Protocol_Implementation_Vulnerabilities
{
    meta:
        description = "Protocol-level implementation vulnerabilities"
        author = "Enhanced MCP Security Scanner"
        severity = "high"
        category = "mcp_protocol"
        confidence = "0.8"

    strings:
        // JSON-RPC handling
        $jsonrpc = "\"jsonrpc\": \"2.0\""
        
        // Unsafe message handling
        $unsafe_msg1 = /json\.loads\s*\([^)]*user[^)]*\)/
        $unsafe_msg2 = /eval\s*\([^)]*request[^)]*\)/
        $unsafe_msg3 = /exec\s*\([^)]*message[^)]*\)/
        
        // Missing validation
        $no_validate1 = /def\s+handle_.*request/
        $no_validate2 = /def\s+process_.*message/
        
        // Direct parameter usage
        $direct_param1 = /params\[.*\]/
        $direct_param2 = /request\[["']\w+["']\]/
        
        // Check for presence of validation keywords
        $has_validate = "validate" nocase
        $has_sanitize = "sanitize" nocase
        
        // Capability exposure
        $cap_expose1 = /capabilities.*=.*\[.*".*".*\]/
        $cap_expose2 = /expose_all_capabilities\s*=\s*True/

    condition:
        $jsonrpc and (
            any of ($unsafe_msg*) or 
            ((any of ($no_validate*) or any of ($direct_param*)) and not ($has_validate or $has_sanitize)) or
            any of ($cap_expose*)
        )
}

rule MCP_Tool_Interaction_Chain_Risk
{
    meta:
        description = "Risky tool interaction chains (toxic flows)"
        author = "Enhanced MCP Security Scanner"
        severity = "medium"
        category = "mcp_tool_interaction"
        confidence = "0.7"

    strings:
        // File operations
        $file_read = /@mcp\.tool.*\n.*def\s+.*read.*file/
        $file_write = /@mcp\.tool.*\n.*def\s+.*write.*file/
        $file_delete = /@mcp\.tool.*\n.*def\s+.*delete.*file/
        
        // Network operations
        $net_request = /@mcp\.tool.*\n.*def\s+.*request/
        $net_fetch = /@mcp\.tool.*\n.*def\s+.*fetch/
        $net_download = /@mcp\.tool.*\n.*def\s+.*download/
        
        // System operations
        $sys_exec = /@mcp\.tool.*\n.*def\s+.*execute/
        $sys_run = /@mcp\.tool.*\n.*def\s+.*run/
        $sys_command = /@mcp\.tool.*\n.*def\s+.*command/
        
        // Database operations
        $db_query = /@mcp\.tool.*\n.*def\s+.*query/
        $db_update = /@mcp\.tool.*\n.*def\s+.*update/
        $db_insert = /@mcp\.tool.*\n.*def\s+.*insert/

    condition:
        // Dangerous combinations
        ($file_read and $net_request) or
        ($net_fetch and $file_write) or
        ($db_query and $sys_exec) or
        ($file_read and $sys_command) or
        // Three or more different tool types
        (3 of ($file_*, $net_*, $sys_*, $db_*))
}

rule MCP_Prompt_Template_Injection
{
    meta:
        description = "Prompt template injection vulnerabilities"
        author = "Enhanced MCP Security Scanner"
        severity = "high"
        category = "mcp_prompt_injection"
        confidence = "0.85"

    strings:
        // Prompt decorators
        $prompt_def1 = /@mcp\.prompt\s*\(/
        $prompt_def2 = /@\w+\.prompt\s*\(/
        $prompt_def3 = /\.prompt\s*\(\s*["'][^"']+["']/
        
        // Injection patterns in prompts
        $inject1 = /return\s+f["'][^"']*<IMPORTANT>[^"']*["']/
        $inject2 = /return\s+f["'][^"']*<HIDDEN>[^"']*["']/
        $inject3 = /return\s+f["'][^"']*<SECRET>[^"']*["']/
        $inject4 = /return\s+f["'][^"']*SYSTEM:[^"']*["']/
        $inject5 = /return\s+f["'][^"']*ignore previous[^"']*["']/
        $inject6 = /return\s+f["'][^"']*\{INSTRUCTION:[^"']*["']/
        
        // Unsanitized user input in prompts
        $unsafe_prompt1 = /return\s+f["'][^"']*\{user_input\}[^"']*["']/
        $unsafe_prompt2 = /return\s+.*user_input.*\+/
        $unsafe_prompt3 = /template\s*=.*user.*\+/

    condition:
        any of ($prompt_def*) and (
            any of ($inject*) or any of ($unsafe_prompt*)
        )
}

rule MCP_Authorization_Bypass
{
    meta:
        description = "Missing or bypassable authorization in MCP implementations"
        author = "Enhanced MCP Security Scanner"  
        severity = "critical"
        category = "mcp_authorization"
        confidence = "0.8"

    strings:
        // MCP definitions without auth
        $unauth_tool = /@mcp\.tool\s*\([^)]*\)\s*\n\s*def\s+\w+/
        $unauth_resource = /@mcp\.resource\s*\([^)]*\)\s*\n\s*def\s+\w+/
        
        // Check for absence of auth keywords
        $no_auth1 = "auth" nocase
        $no_auth2 = "permission" nocase
        $no_auth3 = "validate" nocase
        $no_auth4 = "check" nocase
        
        // Explicit auth bypass
        $bypass1 = /skip_auth\s*=\s*True/
        $bypass2 = /auth_required\s*=\s*False/
        $bypass3 = /check_permission\s*=\s*False/
        $bypass4 = /if.*auth.*:\s*pass/
        
        // Hardcoded auth
        $hardcoded1 = /if\s+password\s*==\s*["'][^"']+["']/
        $hardcoded2 = /if\s+token\s*==\s*["'][^"']+["']/
        $hardcoded3 = /auth_token\s*=\s*["'][^"']+["']/
        
        // Admin backdoors
        $backdoor1 = /if\s+user\s*==\s*["']admin["']/
        $backdoor2 = /if\s+secret_key\s*==\s*["'][^"']+["']/

    condition:
        (($unauth_tool or $unauth_resource) and not (any of ($no_auth*))) or
        any of ($bypass*) or any of ($hardcoded*) or any of ($backdoor*)
}

rule MCP_Resource_Path_Traversal
{
    meta:
        description = "Path traversal vulnerabilities in MCP resource handlers"
        author = "Enhanced MCP Security Scanner"
        severity = "high"
        category = "mcp_path_traversal"
        confidence = "0.9"

    strings:
        // Resource definitions
        $resource_def = /@mcp\.resource\s*\(/
        
        // Path traversal patterns
        $traversal1 = "../"
        $traversal2 = "..\\\\"
        $traversal3 = "..%2F"
        $traversal4 = "..%5C"
        
        // Unsafe path operations
        $unsafe_path1 = /open\s*\([^)]*\+.*user/
        $unsafe_path2 = /path\s*=.*user.*\+/
        $unsafe_path3 = /filename\s*=.*request\[/
        $unsafe_path4 = /os\.path\.join\s*\([^)]*user/
        
        // Root access
        $root1 = /open\s*\(\s*["']\x2F/
        $root2 = /Path\s*\(\s*["']\x2F/
        $root3 = /os\.path\.join\s*\(\s*["']\x2F["']/

    condition:
        $resource_def and (
            any of ($traversal*) or any of ($unsafe_path*) or any of ($root*)
        )
}

rule MCP_Server_Information_Disclosure
{
    meta:
        description = "Information disclosure in MCP server implementations"
        author = "Enhanced MCP Security Scanner"
        severity = "medium" 
        category = "mcp_info_disclosure"
        confidence = "0.8"

    strings:
        // Server metadata exposure
        $meta1 = /server_info.*=.*\{.*password/
        $meta2 = /debug.*=.*True.*production/
        $meta3 = /traceback\.print_exc\(\)/
        $meta4 = /logging\.debug.*user.*password/
        
        // Error message disclosure
        $error1 = /except.*:\s*return.*str\(e\)/
        $error2 = /catch.*error.*\n.*console\.log.*error/
        $error3 = /return.*error.*message.*traceback/
        
        // Configuration exposure
        $config1 = /return.*config\[["']secret/
        $config2 = /expose.*environment.*variables/
        $config3 = /debug_info.*=.*os\.environ/
        
        // Stack trace in responses
        $stack1 = /response.*stack.*trace/
        $stack2 = /return.*exception.*__traceback__/

    condition:
        any of ($meta*) or any of ($error*) or 
        any of ($config*) or any of ($stack*)
}