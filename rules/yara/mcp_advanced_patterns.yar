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
        $novald3 = /fetch.*url/ // Simple fetch pattern

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

/*
 * Code Execution Detection Rules
 * Merged from Cisco mcp-scanner patterns + custom enhancements
 * Version: 1.1
 */

rule MCP_Python_Code_Execution
{
    meta:
        description = "Detects Python code execution patterns in MCP tools"
        author = "secscanmcp"
        severity = "critical"
        category = "code_execution"
        version = "1.0"

    strings:
        // MCP/tool context
        $mcp1 = "@tool"
        $mcp2 = "mcp"
        $mcp3 = "handler"

        // Python os module execution
        $os1 = /os\.system\s*\(/i
        $os2 = /os\.popen\s*\(/i
        $os3 = /os\.spawn[lv]?[pe]?\s*\(/i
        $os4 = /os\.execv?p?e?\s*\(/i

        // Python subprocess module
        $sub1 = /subprocess\.run\s*\(/i
        $sub2 = /subprocess\.call\s*\(/i
        $sub3 = /subprocess\.Popen\s*\(/i
        $sub4 = /subprocess\.check_output\s*\(/i
        $sub5 = /subprocess\.getoutput\s*\(/i

        // Python eval/exec
        $eval1 = /\beval\s*\(\s*[^)]*input/i
        $eval2 = /\bexec\s*\(\s*[^)]*user/i
        $eval3 = /\bcompile\s*\(\s*[^)]*params/i

        // Python dynamic import
        $import1 = /__import__\s*\(/i
        $import2 = /importlib\.import_module\s*\(/i

        // Python code object manipulation
        $code1 = /types\.CodeType\s*\(/i
        $code2 = /types\.FunctionType\s*\(/i
        $code3 = /marshal\.loads\s*\(/i

    condition:
        any of ($mcp*) and (any of ($os*, $sub*, $eval*, $import*, $code*))
}

rule MCP_JavaScript_Code_Execution
{
    meta:
        description = "Detects JavaScript/Node.js code execution patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "code_execution"
        version = "1.0"

    strings:
        // MCP/tool context
        $mcp1 = "@tool"
        $mcp2 = "mcp"
        $mcp3 = "handler"

        // Child process execution
        $cp1 = /child_process\.exec\s*\(/i
        $cp2 = /child_process\.execSync\s*\(/i
        $cp3 = /child_process\.spawn\s*\(/i
        $cp4 = /child_process\.spawnSync\s*\(/i
        $cp5 = /child_process\.execFile\s*\(/i
        $cp6 = /require\s*\(\s*["']child_process["']\s*\)/i

        // Dynamic code execution
        $dyn1 = /\beval\s*\(\s*[^)]*\)/i
        $dyn2 = /new\s+Function\s*\(/i
        $dyn3 = /Function\s*\(\s*['"]/i
        $dyn4 = /setTimeout\s*\(\s*['"]/i
        $dyn5 = /setInterval\s*\(\s*['"]/i

        // VM module (sandbox escape)
        $vm1 = /vm\.runInThisContext\s*\(/i
        $vm2 = /vm\.runInNewContext\s*\(/i
        $vm3 = /vm\.createScript\s*\(/i
        $vm4 = /vm\.compileFunction\s*\(/i

        // Script loading
        $script1 = /require\s*\(\s*[^)]*\+/i
        $script2 = /import\s*\(\s*[^)]*\+/i
        $script3 = /\.load\s*\(\s*[^)]*\+/i

    condition:
        any of ($mcp*) and (any of ($cp*, $dyn*, $vm*, $script*))
}

rule MCP_PHP_Code_Execution
{
    meta:
        description = "Detects PHP code execution patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "code_execution"
        version = "1.0"

    strings:
        // PHP execution functions
        $exec1 = /\bexec\s*\(/i
        $exec2 = /\bsystem\s*\(/i
        $exec3 = /\bpassthru\s*\(/i
        $exec4 = /\bshell_exec\s*\(/i
        $exec5 = /\bpopen\s*\(/i
        $exec6 = /\bproc_open\s*\(/i

        // PHP eval patterns
        $eval1 = /\beval\s*\(/i
        $eval2 = /\bassert\s*\(/i
        $eval3 = /\bcreate_function\s*\(/i
        $eval4 = /\bpreg_replace\s*\([^)]*\/e/i

        // PHP callback execution
        $cb1 = /\bcall_user_func\s*\(/i
        $cb2 = /\bcall_user_func_array\s*\(/i
        $cb3 = /\barray_map\s*\(\s*\$/i
        $cb4 = /\barray_filter\s*\(\s*\$.*,\s*\$/i

        // PHP include/require
        $inc1 = /\binclude\s*\(\s*\$/i
        $inc2 = /\brequire\s*\(\s*\$/i
        $inc3 = /\binclude_once\s*\(\s*\$/i
        $inc4 = /\brequire_once\s*\(\s*\$/i

    condition:
        any of ($exec*, $eval*, $cb*, $inc*)
}

rule MCP_Ruby_Code_Execution
{
    meta:
        description = "Detects Ruby code execution patterns in MCP tools"
        author = "secscanmcp"
        severity = "critical"
        category = "code_execution"
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "mcp.tool"
        $mcp5 = "MCPServer"

        // Ruby system execution with user input
        $sys1 = /system\s*\(\s*[^)]*params/i
        $sys2 = /system\s*\(\s*[^)]*user/i
        $sys3 = /exec\s*\(\s*[^)]*params/i
        $sys4 = /exec\s*\(\s*[^)]*input/i

        // Ruby IO and popen with user input
        $io1 = /IO\.popen\s*\(\s*[^)]*params/i
        $io2 = /Open3\.popen[^(]*\(\s*[^)]*user/i
        $io3 = /Open3\.capture[^(]*\(\s*[^)]*params/i

        // Ruby eval with user input (dangerous)
        $eval1 = /\beval\s*\(\s*[^)]*params/i
        $eval2 = /\beval\s*\(\s*[^)]*user/i
        $eval3 = /\binstance_eval\s*\(\s*[^)]*params/i
        $eval4 = /\binstance_eval\s*\(\s*[^)]*user/i

        // Ruby kernel methods with user input
        $kern1 = /Kernel\.system\s*\(\s*[^)]*params/i
        $kern2 = /Kernel\.exec\s*\(\s*[^)]*user/i

    condition:
        any of ($mcp*) and (any of ($sys*, $io*, $eval*, $kern*))
}

rule MCP_Code_Obfuscation_Detection
{
    meta:
        description = "Detects code obfuscation techniques used to hide malicious code"
        author = "secscanmcp"
        severity = "high"
        category = "code_execution"
        version = "1.0"

    strings:
        // Base64 encoding/decoding
        $b64_1 = /base64\.b64decode\s*\(/i
        $b64_2 = /base64\.decodebytes\s*\(/i
        $b64_3 = /\batob\s*\(/i
        $b64_4 = /Buffer\.from\s*\([^)]+,\s*["']base64["']\s*\)/i
        $b64_5 = /Convert\.FromBase64String\s*\(/i
        $b64_6 = /Base64::decode\s*\(/i

        // Hex encoding/decoding
        $hex1 = /bytes\.fromhex\s*\(/i
        $hex2 = /\bxxd\s+-r\b/i
        $hex3 = /\bhexdump\b/i
        $hex4 = /printf\s+.*\\x[0-9a-fA-F]/i
        $hex5 = /echo\s+-e\s+.*\\x/i

        // String char code manipulation
        $char1 = /String\.fromCharCode\s*\(/i
        $char2 = /chr\s*\(\s*\d+\s*\)/i
        $char3 = /ord\s*\(\s*['"]/i

        // Compression-based obfuscation
        $comp1 = /zlib\.decompress\s*\(/i
        $comp2 = /gzip\.decompress\s*\(/i
        $comp3 = /bz2\.decompress\s*\(/i
        $comp4 = /lzma\.decompress\s*\(/i

        // Eval with encoding
        $eval_enc1 = /eval\s*\(\s*(base64|atob|decode)/i
        $eval_enc2 = /exec\s*\(\s*(base64|decode)/i
        $eval_enc3 = /Function\s*\(\s*atob/i

    condition:
        any of ($eval_enc*) or
        (2 of ($b64*, $hex*, $char*, $comp*))
}

rule MCP_Polyglot_Payload_Detection
{
    meta:
        description = "Detects polyglot payloads that work in multiple languages"
        author = "secscanmcp"
        severity = "high"
        category = "code_execution"
        version = "1.0"

    strings:
        // Python-JavaScript polyglots
        $poly1 = /^#!.*python.*\n.*<script/i
        $poly2 = /["'].*eval.*["'].*exec/i

        // Shell-Python polyglots
        $poly3 = /^:.*'''.*\n.*import\s/
        $poly4 = /^true.*<<'EOF'.*exec/

        // Multiple shebang indicators
        $shebang1 = /^#!/
        $shebang2 = /\n#!/

        // Language mixing patterns
        $mix1 = /<\?php.*<script/i
        $mix2 = /<script.*<%/i
        $mix3 = /<%.*eval.*%>/i

        // Template with code
        $tpl1 = /\{\{.*exec.*\}\}/i
        $tpl2 = /\$\{.*system.*\}/i
        $tpl3 = /<%=.*exec.*%>/i

    condition:
        any of ($poly*, $mix*, $tpl*) or
        (#shebang1 > 0 and #shebang2 > 0)
}

rule MCP_Shell_Command_Construction
{
    meta:
        description = "Detects dangerous shell command construction patterns in MCP"
        author = "secscanmcp"
        severity = "critical"
        category = "code_execution"
        version = "1.1"

    strings:
        // MCP/tool context (more specific)
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "@mcp.tool"
        $mcp5 = "MCPServer"
        $mcp6 = "mcp.tool("

        // String interpolation in commands WITH subprocess/exec
        $interp1 = /f["'].*\{.*params.*\}.*["'].*subprocess/i
        $interp2 = /`.*\$\{.*user.*\}.*`.*exec/i
        $interp3 = /\.format\s*\([^)]*params[^)]*\).*system/i

        // Command concatenation with user input
        $concat1 = /cmd\s*=\s*["'][^"']*["']\s*\+\s*params/i
        $concat2 = /command\s*=\s*["'][^"']*["']\s*\+\s*user/i
        $concat3 = /subprocess[^(]*\([^)]*\+\s*params/i

        // Shell=True with user input (very dangerous)
        $unsafe1 = /shell\s*=\s*True[^)]*params/i
        $unsafe2 = /shell\s*=\s*True[^)]*user/i
        $unsafe3 = /subprocess\.run\s*\([^,]*params[^)]*shell\s*=\s*True/i

    condition:
        any of ($mcp*) and (
            any of ($interp*, $concat*, $unsafe*)
        )
}

rule MCP_Dynamic_Import_Execution
{
    meta:
        description = "Detects dangerous dynamic import patterns in MCP tools"
        author = "secscanmcp"
        severity = "high"
        category = "code_execution"
        version = "1.1"

    strings:
        // MCP/tool context required
        $mcp1 = "@tool"
        $mcp2 = "mcp_server"
        $mcp3 = "tool_handler"
        $mcp4 = "@mcp.tool"
        $mcp5 = "MCPServer"

        // Python dynamic imports with user input
        $py1 = /__import__\s*\(\s*[^)]*params/i
        $py2 = /__import__\s*\(\s*[^)]*user/i
        $py3 = /importlib\.import_module\s*\(\s*[^)]*params/i
        $py4 = /exec\s*\(\s*["']import\s+[^"']*["']\s*\+/i

        // JavaScript dynamic imports with user input
        $js1 = /require\s*\(\s*[^)]*params/i
        $js2 = /require\s*\(\s*[^)]*user_/i
        $js3 = /import\s*\(\s*[^)]*params/i

        // Package installation at runtime with user input (dangerous)
        $pkg1 = /subprocess[^)]*pip\s+install\s+[^)]*params/i
        $pkg2 = /child_process[^)]*npm\s+install\s+[^)]*user/i
        $pkg3 = /os\.system[^)]*pip\s+install\s+[^)]*params/i

    condition:
        any of ($mcp*) and (any of ($py*, $js*, $pkg*))
}