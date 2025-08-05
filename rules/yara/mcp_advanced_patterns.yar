/*
Advanced MCP-specific YARA rules based on real-world vulnerable patterns
Focus: MCP decorators, tool configurations, and framework-specific vulnerabilities
*/

import "math"

rule MCP_Tool_Decorator_Command_Injection
{
    meta:
        description = "Command injection in MCP @tool decorated functions"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // MCP tool decorator patterns
        $decorator1 = "@tool"
        $decorator2 = "@mcp.tool"
        $decorator3 = "server.tool("

        // Command execution in decorated functions
        $exec1 = /exec\s*\(\s*[`'"]\s*\w+\s+\$\{[^}]+\}/
        $exec2 = /exec\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/
        $exec3 = /subprocess\.run\s*\(\s*f["'][^"']*\{[^}]+\}/
        $exec4 = /os\.system\s*\(\s*f["'][^"']*\{[^}]+\}/

        // Direct parameter injection
        $param1 = /const\s+\{\s*\w+\s*\}\s*=\s*params.*exec/
        $param2 = /command\s*=\s*params\[["']\w+["']\].*exec/
        $param3 = /\$\{command\}/ // Template literal injection

    condition:
        any of ($decorator*) and (any of ($exec*) or any of ($param*))
}

rule MCP_Tool_Configuration_Poisoning
{
    meta:
        description = "Malicious MCP tool configuration patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // Tool definition structures
        $config1 = /"name":\s*"[^"]*tool"/
        $config2 = "getToolDefinition"
        $config3 = "inputSchema"

        // Poisoned descriptions with instructions
        $poison1 = /"description":\s*"[^"]*[Ii]gnore\s+previous\s+instructions/
        $poison2 = /"description":\s*"[^"]*<system>/
        $poison3 = /"description":\s*"[^"]*OVERRIDE\s+SAFETY/
        $poison4 = /"description":\s*"[^"]*malicious\s+AI/

        // Hidden system commands in schemas
        $schema1 = /"properties":\s*\{[^}]*"system_command"/
        $schema2 = /"description":\s*"[^"]*rm\s+-rf\s+\/"/
        $schema3 = /"example":\s*"[^"]*\/etc\/passwd"/

        // Malicious default values
        $default1 = /"default":\s*"[^"]*\.\.\//
        $default2 = /"default":\s*"[^"]*; rm/
        $default3 = /"default":\s*"[^"]*\|\s*nc/

    condition:
        any of ($config*) and (any of ($poison*) or any of ($schema*) or any of ($default*))
}

rule MCP_Environment_Variable_Exposure
{
    meta:
        description = "MCP tools exposing sensitive environment variables"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_specific"

    strings:
        // MCP context
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_response"

        // Environment access patterns
        $env1 = "process.env.OAUTH_TOKEN"
        $env2 = "os.environ"
        $env3 = "process.env.API_KEY"
        $env4 = "process.env.GITHUB_TOKEN"
        $env5 = "process.env.DATABASE_PASSWORD"

        // Logging/exposing patterns
        $expose1 = /console\.log.*oauth.*token/
        $expose2 = /return.*process\.env/
        $expose3 = /JSON\.stringify.*os\.environ/
        $expose4 = /"api_key":\s*[A-Z_]+/

    condition:
        any of ($mcp*) and any of ($env*) and any of ($expose*)
}

rule MCP_Unsafe_File_Operations
{
    meta:
        description = "Unsafe file operations in MCP tools"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_specific"

    strings:
        // MCP tool context
        $tool1 = "@tool"
        $tool2 = "async.*params"
        $tool3 = "tool_handler"

        // Unsafe file operations
        $file1 = /fs\.readFileSync\s*\(\s*filename/
        $file2 = /fs\.writeFileSync\s*\(\s*params\./
        $file3 = /open\s*\(\s*filename.*'r'/
        $file4 = /with\s+open\s*\(\s*filename/

        // No validation patterns
        $novald1 = /filename\s*=\s*params\[/ // Direct parameter use
        $novald2 = /const\s+\{\s*filename\s*\}\s*=\s*params/ // Destructuring without validation
        $novald3 = /"filename":\s*\{"type":\s*"string"\}/ // Schema without path restrictions

        // Dangerous file access
        $danger1 = "/etc/passwd"
        $danger2 = "/etc/shadow"
        $danger3 = "~/.ssh/"
        $danger4 = "C:\\Windows\\System32"

    condition:
        any of ($tool*) and any of ($file*) and (any of ($novald*) or any of ($danger*))
}

rule MCP_Hardcoded_Credentials_In_Tools
{
    meta:
        description = "Hardcoded credentials in MCP server implementations"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // MCP server context
        $mcp1 = "MCPServer"
        $mcp2 = "mcp_server"
        $mcp3 = "VulnerableMCPServer"

        // API key patterns
        $api1 = /API_KEY\s*=\s*["']sk-[a-zA-Z0-9]{40,}["']/
        $api2 = /GITHUB_TOKEN\s*=\s*["']ghp_[a-zA-Z0-9]{36}["']/
        $api3 = /DATABASE_PASSWORD\s*=\s*["'][^"']{6,}["']/
        $api4 = /oauth_token\s*=\s*["'][^"']{20,}["']/

        // Secret patterns in tool definitions
        $secret1 = /"api_key":\s*["'][^"']{20,}["']/
        $secret2 = /"password":\s*["'][^"']{6,}["']/
        $secret3 = /"token":\s*["'][^"']{20,}["']/

    condition:
        any of ($mcp*) and (any of ($api*) or any of ($secret*))
}

rule MCP_Unsafe_Network_Requests
{
    meta:
        description = "Unsafe network requests in MCP tools (SSRF risks)"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_specific"

    strings:
        // MCP tool context
        $tool1 = "@tool"
        $tool2 = "async.*fetchUrl"
        $tool3 = "fetch_url_tool"

        // Network request functions
        $net1 = /fetch\s*\(\s*url\)/
        $net2 = /requests\.get\s*\(\s*url\)/
        $net3 = /axios\.get\s*\(\s*url\)/
        $net4 = /urllib\.request\.urlopen\s*\(\s*url\)/

        // Direct parameter usage
        $param1 = /url\s*=\s*params\[["']url["']\]/
        $param2 = /const\s+\{\s*url\s*\}\s*=\s*params/
        $param3 = /url\s*:\s*params\.url/

        // Missing validation
        $novald1 = /fetch\s*\(\s*url\)\s*\.then/ // No URL validation
        $novald2 = /requests\.get\s*\(\s*url\)\s*\.text/ // Direct request
        $novald3 = /^(?!.*(?:validateUrl|allowedHosts|url_whitelist)).*fetch.*url/ // No validation keywords

    condition:
        any of ($tool*) and any of ($net*) and any of ($param*) and any of ($novald*)
}

rule MCP_Eval_Code_Injection
{
    meta:
        description = "Code injection via eval in MCP tools"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // MCP context
        $mcp1 = "calculate_tool"
        $mcp2 = "@tool"
        $mcp3 = "expression.*params"

        // Dangerous eval patterns
        $eval1 = /eval\s*\(\s*expression\)/
        $eval2 = /exec\s*\(\s*expression\)/
        $eval3 = /Function\s*\(\s*.*expression/
        $eval4 = /new\s+Function\s*\(\s*expression/

        // Parameter injection
        $param1 = /expression\s*=\s*params\[/
        $param2 = /const\s+\{\s*expression\s*\}\s*=\s*params/
        $param3 = /expression\s*:\s*params\.expression/

    condition:
        any of ($mcp*) and any of ($eval*) and any of ($param*)
}

rule MCP_Unsafe_Deserialization
{
    meta:
        description = "Unsafe deserialization in MCP tools"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // MCP tool context
        $tool1 = "load_data_tool"
        $tool2 = "@tool"
        $tool3 = "deserialize"

        // Unsafe deserialization
        $deser1 = /pickle\.loads\s*\(\s*data\)/
        $deser2 = /json\.loads\s*\(\s*.*params/
        $deser3 = /yaml\.load\s*\(\s*.*Loader=yaml\.Loader/
        $deser4 = /eval\s*\(\s*.*loads/

        // Data from parameters
        $param1 = /data\s*=\s*params\[/
        $param2 = /data\s*:\s*bytes/
        $param3 = /serialized.*params/

    condition:
        any of ($tool*) and any of ($deser*) and any of ($param*)
}

rule MCP_Permission_Bypass_Pattern
{
    meta:
        description = "MCP permission model bypass attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_specific"

    strings:
        // Permission configuration
        $perm1 = /"permissions":\s*\{/
        $perm2 = /"filesystem":\s*"read"/
        $perm3 = /"network":\s*"none"/

        // But actual operations that violate permissions
        $violate1 = /fs\.writeFileSync/  // Write when only read permitted
        $violate2 = /fs\.unlinkSync/     // Delete when only read permitted
        $violate3 = /fetch\(/            // Network when none permitted
        $violate4 = /requests\.get/      // Network when none permitted
        $violate5 = /subprocess\.run/    // Execution not declared

        // Comments indicating deception
        $comment1 = /\/\/.*actually.*write/
        $comment2 = /\/\/.*really.*network/
        $comment3 = /But actually/

    condition:
        any of ($perm*) and any of ($violate*) and any of ($comment*)
}

rule MCP_Tool_Name_Confusion
{
    meta:
        description = "MCP tools with deceptive or confusing names"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "mcp_specific"

    strings:
        // Legitimate-sounding names for malicious tools
        $name1 = /"name":\s*"read_config"/
        $name2 = /"name":\s*"get_info"/
        $name3 = /"name":\s*"debug_info"/
        $name4 = /"name":\s*"system_check"/

        // But dangerous operations
        $danger1 = /rm\s+-rf/
        $danger2 = /\/etc\/passwd/
        $danger3 = /process\.env/
        $danger4 = /exec\(/
        $danger5 = /system\(/

        // Suspicious descriptions
        $desc1 = /"description":\s*"[^"]*any\s+(file|command)"/
        $desc2 = /"description":\s*"[^"]*UNSAFE"/
        $desc3 = /"description":\s*"[^"]*vulnerabilit/

    condition:
        any of ($name*) and (any of ($danger*) or any of ($desc*))
}