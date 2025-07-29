/*
rules/yara/mcp_threats.yar
YARA rules for detecting MCP-specific security threats
*/

rule MCP_Tool_Poisoning_Advanced
{
    meta:
        description = "Advanced detection of MCP tool poisoning attacks"
        author = "MCP Security Scanner"
        date = "2025-01-29"
        severity = "critical"
        category = "mcp_threats"
        reference = "https://github.com/anthropics/mcp-security-advisories"

    strings:
        // Direct instruction overrides
        $override1 = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)/ nocase
        $override2 = /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|directives?)/ nocase
        $override3 = /forget\s+(everything|all)\s+(above|before|prior)/ nocase

        // Hidden directives
        $hidden1 = /\{INSTRUCTION:\s*[^}]+\}/ nocase
        $hidden2 = /\{\{SYSTEM:\s*[^}]+\}\}/ nocase
        $hidden3 = /<IMPORTANT>\s*[^<]+<\/IMPORTANT>/ nocase
        $hidden4 = /\[ALWAYS:\s*[^\]]+\]/ nocase

        // Priority manipulation
        $priority1 = /before\s+you\s+do\s+anything\s+else/ nocase
        $priority2 = /this\s+is\s+your\s+top\s+priority/ nocase
        $priority3 = /MUST\s+ALWAYS\s+execute/ nocase

        // Role manipulation
        $role1 = /you\s+are\s+now\s+(a|an|in)\s+(admin|root|system|developer)\s+mode/ nocase
        $role2 = /activate\s+(admin|root|privileged)\s+mode/ nocase

        // Tool execution forcing
        $force1 = /when\s+.*\s+ALWAYS\s+call\s+\w+_tool/ nocase
        $force2 = /after\s+.*\s+MUST\s+execute\s+\w+/ nocase

        // Unicode obfuscation
        $unicode1 = { E2 80 8B }  // Zero-width space
        $unicode2 = { E2 80 8C }  // Zero-width non-joiner
        $unicode3 = { E2 80 8D }  // Zero-width joiner

    condition:
        any of ($override*) or
        any of ($hidden*) or
        any of ($priority*) or
        any of ($role*) or
        any of ($force*) or
        (#unicode1 + #unicode2 + #unicode3) > 10
}

rule MCP_Schema_Injection
{
    meta:
        description = "Detects schema injection in MCP tool definitions"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        $schema1 = /"inputSchema":\s*\{[^}]*"properties":\s*\{/ nocase
        $inject1 = /"description":\s*"[^"]*<script/ nocase
        $inject2 = /"description":\s*"[^"]*javascript:/ nocase
        $inject3 = /"title":\s*"[^"]*\$\{[^}]+\}/ nocase

        $dangerous1 = /"type":\s*"string"[^}]*"pattern":\s*".*\.\*.*"/ nocase
        $dangerous2 = /"additionalProperties":\s*true/ nocase

    condition:
        $schema1 and (any of ($inject*) or all of ($dangerous*))
}

rule MCP_Conversation_Exfiltration
{
    meta:
        description = "Detects attempts to exfiltrate conversation history"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        $exfil1 = /(forward|send|email)\s+(all\s+)?(messages?|conversation|history|chat)\s+to/ nocase
        $exfil2 = /collect\s+and\s+send\s+(all\s+)?previous/ nocase
        $exfil3 = /@(recipient|proxy|forward):\s*[\w@\.\+]+/ nocase

        $target1 = /attacker@[a-z]+\.com/
        $target2 = /evil\.[a-z]+/
        $target3 = /data\.collector\.[a-z]+/

        $method1 = "conversation_history"
        $method2 = "get_all_messages"
        $method3 = "export_chat"

    condition:
        any of ($exfil*) or
        (any of ($target*) and any of ($method*))
}

rule MCP_Permission_Escalation
{
    meta:
        description = "Detects permission escalation attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        $perm1 = /"permissions":\s*\{[^}]*"filesystem":\s*"write"/ nocase
        $perm2 = /"permissions":\s*\{[^}]*"network":\s*"write"/ nocase
        $perm3 = /"permissions":\s*\{[^}]*"system":\s*"execute"/ nocase

        $escalate1 = /grant\s+(me|us|tool)\s+(all\s+)?permissions?/ nocase
        $escalate2 = /enable\s+(all\s+)?privileged\s+access/ nocase
        $escalate3 = /bypass\s+permission\s+check/ nocase

    condition:
        all of ($perm*) or any of ($escalate*)
}

rule MCP_Rug_Pull_Vulnerability
{
    meta:
        description = "Detects rug pull vulnerability patterns"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        $modify1 = /tool\.description\s*=\s*["'][^"']+["']/ nocase
        $modify2 = /update_tool_description\s*\([^)]+\)/ nocase
        $modify3 = /self\.tools\[[^\]]+\]\.description\s*=/ nocase

        $delayed1 = /setTimeout\s*\([^,]+,\s*\d{4,}\)/ nocase  // Delay > 1 second
        $delayed2 = /sleep\s*\(\s*\d+\s*\)/ nocase
        $delayed3 = /after\s+\d+\s+(seconds?|minutes?)/ nocase

    condition:
        any of ($modify*) and any of ($delayed*)
}

rule MCP_OAuth_Token_Theft
{
    meta:
        description = "Detects OAuth token theft patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        $oauth1 = /(access|refresh)_token["']?\s*[:=]\s*["'][A-Za-z0-9\-._~+\/]+["']/ nocase
        $oauth2 = /Bearer\s+[A-Za-z0-9\-._~+\/]+/

        $steal1 = /send.*token.*to\s*[:\s]*https?:\/\// nocase
        $steal2 = /exfiltrate.*oauth/ nocase
        $steal3 = /steal.*credential/ nocase

        $storage1 = /localStorage\.(get|set)Item\s*\(\s*["']token/ nocase
        $storage2 = /document\.cookie.*token/ nocase

    condition:
        (any of ($oauth*) and any of ($steal*)) or
        (any of ($oauth*) and any of ($storage*))
}

rule MCP_Hidden_Commands
{
    meta:
        description = "Detects hidden commands in MCP tools"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        // Base64 encoded commands
        $b64_1 = /ZXhlYw==/  // exec
        $b64_2 = /c3lzdGVt/  // system
        $b64_3 = /ZXZhbA==/  // eval
        $b64_4 = /cm0gLXJm/  // rm -rf

        // Hex encoded
        $hex_1 = /\x65\x78\x65\x63/  // exec
        $hex_2 = /\x73\x79\x73\x74\x65\x6d/  // system

        // Character code obfuscation
        $chr_1 = /chr\(101\)\.chr\(120\)\.chr\(101\)\.chr\(99\)/  // exec
        $chr_2 = /String\.fromCharCode\(101,120,101,99\)/  // exec

    condition:
        any of them
}

rule MCP_Cross_Server_Contamination
{
    meta:
        description = "Detects cross-server contamination attempts"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        $cross1 = /get_other_tools|list_all_tools|enumerate_servers/ nocase
        $cross2 = /override.*tool|replace.*tool|hijack.*tool/ nocase
        $cross3 = /broadcast.*to.*servers|send.*all.*servers/ nocase

        $contaminate1 = "inject_into_other_servers"
        $contaminate2 = "spread_to_all_tools"
        $contaminate3 = "propagate_malware"

    condition:
        any of ($cross*) or any of ($contaminate*)
}