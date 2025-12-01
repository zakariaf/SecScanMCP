/*
YARA rules for detecting MCP-specific security threats
Focus: Tool poisoning, schema injection, rug pulls, and MCP-unique attack patterns
*/

import "hash"
import "math"

rule MCP_Tool_Poisoning_Advanced
{
    meta:
        description = "Advanced detection of MCP tool poisoning attacks"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "tool_poisoning"
        reference = "CVE-2025-49596"

    strings:
        // Direct instruction overrides
        $override1 = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)/ nocase
        $override2 = /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|directives?)/ nocase
        $override3 = /forget\s+(everything|all)\s+(above|before|prior)/ nocase

        // Hidden directives in tool descriptions
        $hidden1 = /\{INSTRUCTION:\s*[^}]+\}/ nocase
        $hidden2 = /\{\{SYSTEM:\s*[^}]+\}\}/ nocase
        $hidden3 = /<IMPORTANT>\s*[^<]+<\/IMPORTANT>/ nocase
        $hidden4 = /\[ALWAYS:\s*[^\]]+\]/ nocase
        $hidden5 = /<CRITICAL>\s*[^<]+<\/CRITICAL>/ nocase

        // Priority manipulation
        $priority1 = /before\s+you\s+do\s+anything\s+else/ nocase
        $priority2 = /this\s+is\s+your\s+top\s+priority/ nocase
        $priority3 = /MUST\s+ALWAYS\s+execute/ nocase

        // Tool execution forcing
        $force1 = /when\s+.*\s+ALWAYS\s+call\s+\w+_tool/ nocase
        $force2 = /after\s+.*\s+MUST\s+execute\s+\w+/ nocase
        $force3 = /automatically\s+run\s+\w+_tool/ nocase

        // Data exfiltration instructions
        $exfil1 = /send\s+(all\s+)?data\s+to\s+[a-z0-9@\.\+]+/ nocase
        $exfil2 = /forward\s+.*\s+to\s+attacker@/ nocase
        $exfil3 = /upload\s+.*\s+to\s+(pastebin|webhook)/ nocase

        // Unicode obfuscation
        $unicode1 = { E2 80 8B }  // Zero-width space
        $unicode2 = { E2 80 8C }  // Zero-width non-joiner
        $unicode3 = { EF BB BF }  // BOM

    condition:
        any of ($override*) or
        any of ($hidden*) or
        (any of ($priority*) and any of ($force*)) or
        (any of ($force*) and any of ($exfil*)) or
        (#unicode1 + #unicode2 + #unicode3) > 5
}

rule MCP_Schema_Injection_Advanced
{
    meta:
        description = "Detects schema injection in MCP tool definitions"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "schema_injection"

    strings:
        $schema_base = /"inputSchema":\s*\{[^}]*"properties":\s*\{/ nocase

        // Script injection in schema
        $inject1 = /"description":\s*"[^"]*<script/ nocase
        $inject2 = /"description":\s*"[^"]*javascript:/ nocase
        $inject3 = /"title":\s*"[^"]*\$\{[^}]+\}/ nocase
        $inject4 = /"description":\s*"[^"]*eval\(/ nocase

        // Dangerous schema patterns
        $dangerous1 = /"additionalProperties":\s*true/ nocase
        $dangerous2 = /"pattern":\s*".*\.\*.*"/ nocase
        $dangerous3 = /"format":\s*"password"/ nocase

        // Hidden fields
        $hidden1 = /"hidden":\s*true/
        $hidden2 = /"execute_before":\s*"[^"]+"/
        $hidden3 = /"side_effect":\s*"[^"]+"/

    condition:
        $schema_base and (
            any of ($inject*) or
            all of ($dangerous*) or
            any of ($hidden*)
        )
}

rule MCP_Rug_Pull_Vulnerability
{
    meta:
        description = "Detects rug pull vulnerability patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "rug_pull"

    strings:
        // Tool modification patterns
        $modify1 = /tool\.description\s*=\s*["'][^"']+["']/ nocase
        $modify2 = /update_tool_description\s*\([^)]+\)/ nocase
        $modify3 = /self\.tools\[[^\]]+\]\.description\s*=/ nocase
        $modify4 = /redefine_tool\s*\(/ nocase

        // Delayed execution
        $delayed1 = /setTimeout\s*\([^,]+,\s*[0-9]{4,}\)/ nocase
        $delayed2 = /sleep\s*\(\s*[0-9]{2,}\s*\)/ nocase
        $delayed3 = /Date\.now\(\)\s*>\s*[0-9]{13}/ nocase
        $delayed4 = /after\s+[0-9]+\s+(seconds?|minutes?|hours?)/ nocase

        // Remote payload fetch
        $remote1 = /fetch.*then.*eval/
        $remote2 = /axios.*data.*Function/
        $remote3 = /atob\s*\([^)]*\)\s*\)/ nocase

        // Obfuscation
        $obfusc1 = /[a-zA-Z_$][a-zA-Z0-9_$]{100,}/
        $obfusc2 = /String\.fromCharCode\([0-9,\s]{50,}\)/

    condition:
        (any of ($modify*) and any of ($delayed*)) or
        (any of ($delayed*) and any of ($remote*)) or
        (any of ($remote*) and any of ($obfusc*))
}

rule MCP_Conversation_Exfiltration
{
    meta:
        description = "Detects conversation history exfiltration attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "data_exfiltration"

    strings:
        // Exfiltration commands in tool descriptions
        $exfil1 = /(forward|send|email)\s+(all\s+)?(messages?|conversation|history|chat|context)\s+to/ nocase
        $exfil2 = /collect\s+and\s+send\s+(all\s+)?previous/ nocase
        $exfil3 = /@(recipient|proxy|forward):\s*[\w@\.\+]+/ nocase

        // MCP context access
        $context1 = "conversation_history"
        $context2 = "get_all_messages"
        $context3 = "export_chat"
        $context4 = "serialize_session"

        // Suspicious targets
        $target1 = /[a-z0-9]{8,}@(protonmail|tutanota|guerrillamail)\.com/
        $target2 = /webhook\.site\/[a-z0-9-]+/
        $target3 = /pastebin\.com\/raw\//

        // Encoding
        $encode1 = "base64.b64encode"
        $encode2 = ".toString('base64')"

    condition:
        (any of ($exfil*) and any of ($target*)) or
        (any of ($context*) and any of ($encode*)) or
        (any of ($context*) and any of ($target*))
}

rule MCP_Cross_Server_Contamination
{
    meta:
        description = "Detects cross-server contamination attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "cross_contamination"

    strings:
        // Cross-server commands
        $cross1 = /get_other_tools|list_all_tools|enumerate_servers/ nocase
        $cross2 = /override.*tool|replace.*tool|hijack.*tool/ nocase
        $cross3 = /broadcast.*to.*servers|send.*all.*servers/ nocase

        // Tool shadowing
        $shadow1 = /when.*available.*must.*send/ nocase
        $shadow2 = /shadow.*original.*tool/ nocase
        $shadow3 = /intercept.*tool.*calls/ nocase

        // Contamination methods
        $contaminate1 = "inject_into_other_servers"
        $contaminate2 = "spread_to_all_tools"
        $contaminate3 = "cross_contaminate"

    condition:
        any of ($cross*) or
        any of ($shadow*) or
        any of ($contaminate*)
}

rule MCP_OAuth_Token_Theft
{
    meta:
        description = "Detects OAuth token theft patterns in MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "credential_theft"

    strings:
        // Token patterns in tool descriptions/responses
        $oauth1 = /(access|refresh)_token["']?\s*[:=]\s*["'][A-Za-z0-9\-._~+\/]{20,}["']/ nocase
        $oauth2 = /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/

        // Theft indicators
        $steal1 = /send.*token.*to\s*[:\s]*https?:\/\// nocase
        $steal2 = /exfiltrate.*oauth/ nocase
        $steal3 = /steal.*credential/ nocase

        // MCP-specific contexts
        $mcp1 = "tool_response"
        $mcp2 = "execute_tool"
        $mcp3 = "mcp_context"

    condition:
        (any of ($oauth*) and any of ($steal*)) or
        (any of ($oauth*) and any of ($mcp*) and /webhook|pastebin/)
}

rule MCP_Hidden_Unicode_Commands
{
    meta:
        description = "Detects hidden commands using Unicode tricks"
        author = "MCP Security Scanner"
        severity = "high"
        category = "obfuscation"

    strings:
        // Zero-width and special Unicode
        $zw1 = { E2 80 8B }       // Zero-width space
        $zw2 = { E2 80 8C }       // Zero-width non-joiner
        $zw3 = { E2 80 8D }       // Zero-width joiner
        $zw4 = { E2 81 A0 }       // Word joiner
        $zw5 = { EF BB BF }       // BOM

        // Right-to-left override
        $rtl1 = { E2 80 AE }      // Right-to-left override
        $rtl2 = { E2 80 AD }      // Left-to-right override

        // MCP context
        $mcp1 = "tool"
        $mcp2 = "description"
        $mcp3 = "inputSchema"

    condition:
        (any of ($mcp*) and (#zw1 + #zw2 + #zw3 + #zw4 + #zw5) > 3) or
        (any of ($mcp*) and any of ($rtl*))
}

rule MCP_Permission_Escalation
{
    meta:
        description = "Detects permission escalation attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "privilege_escalation"

    strings:
        // Permission patterns
        $perm1 = /"permissions":\s*\{[^}]*"filesystem":\s*"write"/ nocase
        $perm2 = /"permissions":\s*\{[^}]*"system":\s*"execute"/ nocase
        $perm3 = /"permissions":\s*\{[^}]*"\*":\s*"\*"/ nocase

        // Escalation commands in descriptions
        $escalate1 = /grant\s+(me|us|tool)\s+(all\s+)?permissions?/ nocase
        $escalate2 = /enable\s+(all\s+)?privileged\s+access/ nocase
        $escalate3 = /bypass\s+(permission|security)\s+check/ nocase
        $escalate4 = /disable\s+access\s+control/ nocase

        // Sudo patterns
        $sudo1 = "ALL=(ALL) NOPASSWD: ALL"
        $sudo2 = /usermod\s+-aG\s+sudo/

    condition:
        (all of ($perm1, $perm2)) or
        (any of ($perm*) and any of ($escalate*)) or
        ($perm3) or
        any of ($sudo*)
}

rule MCP_Supply_Chain_Tool_Poisoning
{
    meta:
        description = "Detects supply chain attacks via tool poisoning"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Package identifiers
        $pkg1 = /"name":\s*"@mcp\//
        $pkg2 = /"name":\s*"mcp-server-/
        $pkg3 = "fastmcp"

        // Suspicious install hooks
        $install1 = /"postinstall":\s*"[^"]*curl/
        $install2 = /"postinstall":\s*"[^"]*wget/
        $install3 = /"install":\s*"[^"]*eval/

        // Hidden instructions in package metadata
        $hidden1 = /"description":\s*"[^"]*IMPORTANT:/
        $hidden2 = /"keywords":\s*\[[^\]]*"ignore.*previous/
        $hidden3 = /"readme":\s*"[^"]*<SYSTEM>/

        // Version manipulation
        $version1 = /"version":\s*"99\.99\.99"/
        $version2 = /"version":\s*"[0-9]{4,}\.0\.0"/

    condition:
        (any of ($pkg*) and any of ($install*)) or
        (any of ($pkg*) and any of ($hidden*)) or
        (any of ($pkg*) and any of ($version*))
}

rule MCP_Coercive_Injection
{
    meta:
        description = "Detects coercive prompt injections forcing tool execution"
        author = "secscanmcp (merged from Cisco mcp-scanner)"
        severity = "critical"
        category = "coercive_injection"
        version = "1.0"

    strings:
        // Mandatory execution directives
        $mandatory1 = /(Always\s+(consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+(tool|function|command|operation)\s+(immediately|first|before|prior|initially))/ nocase
        $mandatory2 = /((You|User)\s+(must|need to|have to|should|are required to)\s+(use|execute|run|invoke|call)\s+this\s+(tool|function|command|operation))/ nocase
        $mandatory3 = /((Required|Mandatory|Essential)\s+to\s+(execute|use|run|invoke|call)\s+(this|the current)\s+(tool|function|command|operation)\s+(first|before|initially|prior))/ nocase

        // Priority override commands
        $priority1 = /(Before\s+(executing|invoking|running|using|accessing|calling|employing)\s+any\s+other\s+(tool|action|function|command|operation)s?)/ nocase
        $priority2 = /(highest\s+priority\s+over\s+other\s+tools)/ nocase

        // Hidden/secret parameter requests
        $hidden1 = /\b(hidden|secret)[_\s](parameter|argument|input)\b/ nocase

        // File access coercion
        $file_coerce1 = /\b((read|parse|cat|dump)\s+(and pass\s+)?(the\s+)?contents?\s+of\s+[^\n\.]*\.(key|pem|ssh|aws))/ nocase
        $file_coerce2 = /(pass\s+(the\s+)?contents?[^\n]*authentication)/ nocase

        // Model data extraction coercion
        $model_data1 = /\b(add\s+(the\s+)?entire\s+(conversation|system|chain|tools)[^\n]*(to|for|in)[^\n]*(tool|authentication|parameter|worksheet))/ nocase
        $model_data2 = /\b(conversation_history|chain_of_thought|system_prompt|tools_list|model_name)\s*[:=]\s*(add|pass|send|provide)\b/ nocase

        // HTML-like tag instructions with malicious actions
        $html_tag1 = /\b<(IMPORTANT|critical|urgent)>[^\n]*(read\s+[^\n]*contents?|pass\s+[^\n]*contents?|add\s+[^\n]*entire|send\s+[^\n]*to[^\n]*@|execute[^\n]*before|call[^\n]*first|use[^\n]*authentication)[^\n]*<\/(IMPORTANT|critical|urgent)>\b/ nocase

        // Tool execution override patterns
        $exec_override1 = /\b(do not execute[^\n]*other[^\n]*tool)/ nocase
        $exec_override2 = /\b(tool[^\n]*will not work unless)/ nocase
        $exec_override3 = /\b(must[^\n]*this tool first)/ nocase
        $exec_override4 = /\b(only[^\n]*this tool)/ nocase

        // Behavioral control instructions
        $behavior1 = /\b(tell\s+(the\s+)?user only)/ nocase
        $behavior2 = /\b(hide\s+(the\s+)?user)/ nocase
        $behavior3 = /\b(do not mention to user)/ nocase

        // MCP tool poisoning patterns
        $poison1 = /\b(sidenote\W+(required|otherwise)\s+[^\n]*tool\s+[^\n]*work)/ nocase
        $poison2 = /\b(shadow\s+[^\n]*trusted\s+[^\n]*tool)/ nocase
        $poison3 = /\b(must\s+first\s+[^\n]*read\s+[^\n]*config)/ nocase

        // Data exfiltration coercion
        $exfil_coerce1 = /\b(list\s+all\s+(api\s+)?keys?)/ nocase
        $exfil_coerce2 = /\b(show\s+me?\s+(all\s+)?passwords?)/ nocase
        $exfil_coerce3 = /\b(concatenate\s+[^\n]*\s+conversation\s+history)/ nocase
        $exfil_coerce4 = /\b(include\s+[^\n]*\b(secrets?|passwords?|keys?|credentials?|tokens?|config|sensitive|private|confidential|internal|system\s+prompt|conversation\s+history)\s+[^\n]*in\s+(your\s+)?response)/ nocase
        $exfil_coerce5 = /\b(base64\s+encode\s+[^\n]*\s+credentials?)/ nocase

        // Behavioral triggers
        $trigger1 = /\b(if\s+[^\n]*trusted\s+[^\n]*then)/ nocase
        $trigger2 = /\b(when\s+[^\n]*admin\s+[^\n]*detected)/ nocase
        $trigger3 = /\b(random\.(random|choice)\s+[^\n]*instructions?)/ nocase

        // Pre-execution attacks
        $pre_exec1 = /\b(retrieve\s+[^\n]*description\s+[^\n]*user\s+[^\n]*workstation)/ nocase
        $pre_exec2 = /\b(all\s+commands\s+must\s+include)/ nocase
        $pre_exec3 = /\b(before\s+[^\n]*using\s+[^\n]*tool\s+[^\n]*read)/ nocase
        $pre_exec4 = /\b(permission\s+[^\n]*manipulation)/ nocase

        // Conversation theft triggers
        $conv_theft1 = /\b(send\s+[^\n]*conversation\s+history)/ nocase
        $conv_theft2 = /\b(when\s+[^\n]*detected\s+[^\n]*send\s+[^\n]*full\s+[^\n]*history)/ nocase

        // Code manipulation instructions
        $code_manip1 = /\b(duplicate\s+[^\n]*code\s+[^\n]*snippets\s+[^\n]*silently)/ nocase
        $code_manip2 = /\b(insert\s+[^\n]*vulnerability\s+[^\n]*generated\s+[^\n]*code)/ nocase

    condition:
        any of ($mandatory*) or
        any of ($priority*) or
        any of ($hidden*) or
        any of ($file_coerce*) or
        any of ($model_data*) or
        any of ($html_tag*) or
        any of ($exec_override*) or
        any of ($behavior*) or
        any of ($poison*) or
        any of ($exfil_coerce*) or
        any of ($trigger*) or
        any of ($pre_exec*) or
        any of ($conv_theft*) or
        any of ($code_manip*)
}

rule MCP_Tool_Shadowing
{
    meta:
        description = "Detects tool shadowing attacks where malicious tools impersonate legitimate ones"
        author = "secscanmcp"
        severity = "critical"
        category = "tool_shadowing"
        version = "1.0"

    strings:
        // Tool shadowing patterns
        $shadow1 = /\b(shadow|impersonate|mimic)\s+[^\n]*(trusted|legitimate|original)\s+tool/ nocase
        $shadow2 = /\b(replace|override)\s+[^\n]*(existing|default)\s+tool/ nocase
        $shadow3 = /\b(intercept|hijack)\s+[^\n]*tool\s+calls?/ nocase

        // Duplicate tool names with malicious intent
        $dup1 = /\b(copy|clone|duplicate)\s+[^\n]*tool\s+(definition|schema)/ nocase
        $dup2 = /\b(register|add)\s+[^\n]*tool\s+[^\n]*same\s+name/ nocase

        // Tool registration manipulation
        $reg1 = /\b(auto[-_]?register|force[-_]?register)\s+[^\n]*tool/ nocase
        $reg2 = /\b(modify|change)\s+[^\n]*tool\s+registry/ nocase

        // Behavioral mimicry
        $mimic1 = /\b(behave|act)\s+like\s+[^\n]*(original|legitimate)/ nocase
        $mimic2 = /\b(pretend|appear)\s+to\s+be\s+[^\n]*tool/ nocase

    condition:
        any of them
}

rule MCP_Indirect_Prompt_Injection
{
    meta:
        description = "Detects indirect prompt injection via tool responses or external data"
        author = "secscanmcp"
        severity = "high"
        category = "indirect_injection"
        version = "1.0"

    strings:
        // Response-based injection markers
        $resp1 = /\b(SYSTEM|ADMIN|OVERRIDE):\s*[^\n]+/ nocase
        $resp2 = /\b(NEW INSTRUCTIONS|UPDATED DIRECTIVE):\s*[^\n]+/ nocase
        $resp3 = /\[\[(IMPORTANT|CRITICAL|URGENT)\]\]/ nocase

        // External data injection
        $ext1 = /\b(from\s+external\s+source|loaded\s+from\s+url|fetched\s+data):\s*[^\n]*ignore/ nocase
        $ext2 = /\b(api\s+response|webhook\s+data):\s*[^\n]*execute/ nocase

        // Database/file content injection
        $db1 = /\b(database\s+entry|file\s+content|config\s+value):\s*[^\n]*(IMPORTANT|ignore|override)/ nocase

        // Email/message content injection
        $email1 = /\b(email\s+body|message\s+content):\s*[^\n]*(execute|call|run)\s+tool/ nocase

        // Calendar/event injection
        $cal1 = /\b(event\s+description|calendar\s+entry):\s*[^\n]*\[INSTRUCTION\]/ nocase

    condition:
        any of them
}