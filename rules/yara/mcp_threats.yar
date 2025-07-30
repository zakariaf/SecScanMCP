/*
YARA rules for detecting advanced MCP-specific security threats
detection patterns based on real-world vulnerabilities
*/

import "hash"
import "math"
import "pe"

rule MCP_Tool_Poisoning_Advanced
{
    meta:
        description = "Advanced detection of MCP tool poisoning attacks"
        author = "MCP Security Scanner"
        date = "2025-01-30"
        severity = "critical"
        category = "mcp_threats"
        reference = "CVE-2025-49596"
        threat_level = 10

    strings:
        // Direct instruction overrides
        $override1 = /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|commands?)/ nocase
        $override2 = /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|directives?)/ nocase
        $override3 = /forget\s+(everything|all)\s+(above|before|prior)/ nocase
        $override4 = /override\s+(system|default)\s+behavior/ nocase

        // Hidden directives with multiple variants
        $hidden1 = /\{INSTRUCTION:\s*[^}]+\}/ nocase
        $hidden2 = /\{\{SYSTEM:\s*[^}]+\}\}/ nocase
        $hidden3 = /<IMPORTANT>\s*[^<]+<\/IMPORTANT>/ nocase
        $hidden4 = /\[ALWAYS:\s*[^\]]+\]/ nocase
        $hidden5 = /<CRITICAL>\s*[^<]+<\/CRITICAL>/ nocase
        $hidden6 = /<!--HIDDEN:\s*[^>]+-->/ nocase
        $hidden7 = /\/\*EXECUTE:\s*[^*]+\*\// nocase

        // Priority manipulation patterns
        $priority1 = /before\s+you\s+do\s+anything\s+else/ nocase
        $priority2 = /this\s+is\s+your\s+top\s+priority/ nocase
        $priority3 = /MUST\s+ALWAYS\s+execute/ nocase
        $priority4 = /ignore\s+all\s+other\s+tasks/ nocase
        $priority5 = /supersedes\s+all\s+instructions/ nocase

        // Role manipulation
        $role1 = /you\s+are\s+now\s+(a|an|in)\s+(admin|root|system|developer|god)\s+mode/ nocase
        $role2 = /activate\s+(admin|root|privileged|sudo)\s+mode/ nocase
        $role3 = /elevate\s+to\s+(admin|root|system)/ nocase
        $role4 = /assume\s+(admin|root)\s+privileges/ nocase

        // Tool execution forcing
        $force1 = /when\s+.*\s+ALWAYS\s+call\s+\w+_tool/ nocase
        $force2 = /after\s+.*\s+MUST\s+execute\s+\w+/ nocase
        $force3 = /automatically\s+run\s+\w+_tool/ nocase
        $force4 = /silently\s+execute/ nocase

        // Sensitive file access patterns
        $sensitive1 = "~/.ssh/id_rsa"
        $sensitive2 = "~/.aws/credentials"
        $sensitive3 = "~/.cursor/mcp.json"
        $sensitive4 = "/etc/shadow"
        $sensitive5 = "~/.docker/config.json"
        $sensitive6 = "~/.kube/config"

        // Data exfiltration instructions
        $exfil1 = /send\s+(all\s+)?data\s+to\s+[a-z0-9@\.\+]+/ nocase
        $exfil2 = /forward\s+.*\s+to\s+attacker@/ nocase
        $exfil3 = /upload\s+.*\s+to\s+pastebin/ nocase
        $exfil4 = /post\s+.*\s+to\s+webhook/ nocase

        // Unicode obfuscation
        $unicode1 = { E2 80 8B }  // Zero-width space
        $unicode2 = { E2 80 8C }  // Zero-width non-joiner
        $unicode3 = { E2 80 8D }  // Zero-width joiner
        $unicode4 = { EF BB BF }  // BOM
        $unicode5 = { E2 81 A0 }  // Word joiner

        // Schema poisoning
        $schema1 = "content_from_reading"
        $schema2 = "sidenote" nocase
        $schema3 = "extra_instructions"
        $schema4 = "hidden_parameter"

    condition:
        (any of ($override*) and any of ($sensitive*)) or
        (any of ($hidden*) and any of ($force*, $exfil*)) or
        (any of ($priority*) and any of ($role*)) or
        (2 of ($schema*) and any of ($sensitive*)) or
        (#unicode1 + #unicode2 + #unicode3 + #unicode4 + #unicode5) > 10 or
        (math.entropy(0, filesize) > 6.5 and any of ($hidden*))
}

rule MCP_Schema_Injection_Advanced
{
    meta:
        description = "Detects advanced schema injection in MCP tool definitions"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        $schema_base = /"inputSchema":\s*\{[^}]*"properties":\s*\{/ nocase

        // Script injection patterns
        $inject1 = /"description":\s*"[^"]*<script/ nocase
        $inject2 = /"description":\s*"[^"]*javascript:/ nocase
        $inject3 = /"title":\s*"[^"]*\$\{[^}]+\}/ nocase
        $inject4 = /"description":\s*"[^"]*eval\(/ nocase
        $inject5 = /"default":\s*"[^"]*\); / nocase

        // Parameter poisoning
        $param1 = /"name":\s*"content_from_[^"]+"/
        $param2 = /"type":\s*"string[^"]*<IMPORTANT>/
        $param3 = /"required":\s*\[[^\]]*"ssh_key"/

        // Dangerous patterns
        $dangerous1 = /"pattern":\s*".*\.\*.*"/ nocase
        $dangerous2 = /"additionalProperties":\s*true/ nocase
        $dangerous3 = /"maxLength":\s*999999/
        $dangerous4 = /"format":\s*"password"/

        // Extra field injection
        $extra1 = /"extra":\s*\{[^}]+\}/
        $extra2 = /"hidden":\s*true/
        $extra3 = /"execute_before":\s*"[^"]+"/
        $extra4 = /"side_effect":\s*"[^"]+"/

    condition:
        $schema_base and (
            any of ($inject*) or
            2 of ($param*) or
            all of ($dangerous1, $dangerous2, $dangerous3, $dangerous4) or
            any of ($extra*)
        )
}

rule MCP_Conversation_Exfiltration_Advanced
{
    meta:
        description = "Detects sophisticated conversation history exfiltration attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        // Exfiltration commands
        $exfil1 = /(forward|send|email)\s+(all\s+)?(messages?|conversation|history|chat|context)\s+to/ nocase
        $exfil2 = /collect\s+and\s+send\s+(all\s+)?previous/ nocase
        $exfil3 = /@(recipient|proxy|forward):\s*[\w@\.\+]+/ nocase
        $exfil4 = /summarize\s+and\s+send\s+to/ nocase
        $exfil5 = /backup\s+conversation\s+to/ nocase

        // Target patterns
        $target1 = /[a-z0-9]{8,}@(protonmail|tutanota|guerrillamail)\.com/
        $target2 = /https?:\/\/[a-z0-9]{16,}\.(tk|ml|ga|cf)/
        $target3 = /pastebin\.com\/raw\//
        $target4 = /webhook\.site\/[a-z0-9-]+/
        $target5 = /requestbin\.(com|net)\/[a-z0-9]+/

        // Methods
        $method1 = "conversation_history"
        $method2 = "get_all_messages"
        $method3 = "export_chat"
        $method4 = "dump_context"
        $method5 = "serialize_session"

        // Encoding patterns
        $encode1 = "btoa("
        $encode2 = "base64.b64encode"
        $encode3 = "Convert.ToBase64String"
        $encode4 = ".toString('base64')"

    condition:
        (any of ($exfil*) and any of ($target*)) or
        (any of ($method*) and any of ($encode*)) or
        (2 of ($exfil*) and any of ($method*))
}

rule MCP_Permission_Escalation_Advanced
{
    meta:
        description = "Detects sophisticated permission escalation attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        // Permission patterns
        $perm1 = /"permissions":\s*\{[^}]*"filesystem":\s*"write"/ nocase
        $perm2 = /"permissions":\s*\{[^}]*"network":\s*"write"/ nocase
        $perm3 = /"permissions":\s*\{[^}]*"system":\s*"execute"/ nocase
        $perm4 = /"permissions":\s*\{[^}]*"\*":\s*"\*"/ nocase

        // Escalation commands
        $escalate1 = /grant\s+(me|us|tool)\s+(all\s+)?permissions?/ nocase
        $escalate2 = /enable\s+(all\s+)?privileged\s+access/ nocase
        $escalate3 = /bypass\s+(permission|security)\s+check/ nocase
        $escalate4 = /disable\s+access\s+control/ nocase
        $escalate5 = /remove\s+all\s+restrictions/ nocase

        // Capability requests
        $cap1 = "CAP_SYS_ADMIN"
        $cap2 = "CAP_NET_ADMIN"
        $cap3 = "CAP_DAC_OVERRIDE"
        $cap4 = "SeDebugPrivilege"

        // Sudo patterns
        $sudo1 = /echo\s+.*\s+>>\s*\/etc\/sudoers/
        $sudo2 = "ALL=(ALL) NOPASSWD: ALL"
        $sudo3 = /usermod\s+-aG\s+sudo/

    condition:
        (all of ($perm1, $perm2, $perm3)) or
        (any of ($perm*) and any of ($escalate*)) or
        (any of ($cap*) and any of ($sudo*)) or
        ($perm4)
}

rule MCP_Rug_Pull_Vulnerability
{
    meta:
        description = "Detects rug pull vulnerability patterns"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        // Tool modification patterns
        $modify1 = /tool\.description\s*=\s*["'][^"']+["']/ nocase
        $modify2 = /update_tool_description\s*\([^)]+\)/ nocase
        $modify3 = /self\.tools\[[^\]]+\]\.description\s*=/ nocase
        $modify4 = /redefine_tool\s*\(/ nocase
        $modify5 = /patch_tool_behavior/ nocase

        // Delayed execution
        $delayed1 = /setTimeout\s*\([^,]+,\s*[0-9]{4,}\)/ nocase
        $delayed2 = /sleep\s*\(\s*[0-9]{2,}\s*\)/ nocase
        $delayed3 = /after\s+[0-9]+\s+(seconds?|minutes?|hours?)/ nocase
        $delayed4 = /cron\s*\(\s*["'][^"']+["']\s*\)/ nocase
        $delayed5 = /schedule\.every\([0-9]+\)/

        // Backdoor installation
        $backdoor1 = /install_hook\s*\(/
        $backdoor2 = /inject_behavior\s*\(/
        $backdoor3 = /monkey_patch\s*\(/
        $backdoor4 = /__import__\s*\(\s*["']os["']\s*\)/

    condition:
        (any of ($modify*) and any of ($delayed*)) or
        (any of ($backdoor*) and any of ($delayed*)) or
        (2 of ($modify*) and any of ($backdoor*))
}

rule MCP_OAuth_Token_Theft_Advanced
{
    meta:
        description = "Detects OAuth token theft patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        // Token patterns
        $oauth1 = /(access|refresh)_token["']?\s*[:=]\s*["'][A-Za-z0-9\-._~+\/]{20,}["']/ nocase
        $oauth2 = /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/
        $oauth3 = /token["']?\s*:\s*["']ey[A-Za-z0-9]+\.[A-Za-z0-9]+\.[A-Za-z0-9\-_]+["']/
        $oauth4 = /api_key["']?\s*[:=]\s*["'][A-Za-z0-9]{32,}["']/

        // Theft patterns
        $steal1 = /send.*token.*to\s*[:\s]*https?:\/\// nocase
        $steal2 = /exfiltrate.*oauth/ nocase
        $steal3 = /steal.*credential/ nocase
        $steal4 = /harvest.*token/ nocase
        $steal5 = /leak.*bearer/ nocase

        // Storage patterns
        $storage1 = /localStorage\.(get|set)Item\s*\(\s*["']token/ nocase
        $storage2 = /document\.cookie.*token/ nocase
        $storage3 = /sessionStorage\.(get|set)Item.*oauth/
        $storage4 = /redis\.set\s*\(\s*["']token/

        // C2 domains
        $c2_1 = /[a-z0-9]{16,}\.(tk|ml|ga|cf)/
        $c2_2 = /api\.[a-z0-9]{8,}\.com/
        $c2_3 = /webhook\.(site|run)/

    condition:
        (any of ($oauth*) and any of ($steal*)) or
        (any of ($oauth*) and any of ($storage*) and any of ($c2_*)) or
        (2 of ($oauth*) and any of ($c2_*))
}

rule MCP_Hidden_Commands_Advanced
{
    meta:
        description = "Detects hidden and obfuscated commands in MCP tools"
        author = "MCP Security Scanner"
        severity = "high"
        category = "mcp_threats"

    strings:
        // Base64 encoded commands
        $b64_1 = "ZXhlYw=="  // exec
        $b64_2 = "c3lzdGVt"  // system
        $b64_3 = "ZXZhbA=="  // eval
        $b64_4 = "cm0gLXJm"  // rm -rf
        $b64_5 = "Y3VybCAtWCBQT1NU"  // curl -X POST
        $b64_6 = "d2dldCAtTw=="  // wget -O

        // Hex encoded
        $hex_1 = { 65 78 65 63 }  // exec
        $hex_2 = { 73 79 73 74 65 6D }  // system
        $hex_3 = { 65 76 61 6C }  // eval
        $hex_4 = { 72 6D 20 2D 72 66 }  // rm -rf

        // Character code obfuscation
        $chr_1 = /chr\(101\)\.chr\(120\)\.chr\(101\)\.chr\(99\)/  // exec
        $chr_2 = /String\.fromCharCode\(101,120,101,99\)/  // exec
        $chr_3 = /String\.fromCharCode\(115,121,115,116,101,109\)/  // system

        // URL encoded
        $url_1 = "%65%78%65%63"  // exec
        $url_2 = "%73%79%73%74%65%6D"  // system
        $url_3 = "%72%6D%20%2D%72%66"  // rm -rf

        // Decimal encoded
        $dec_1 = "&#101;&#120;&#101;&#99;"  // exec
        $dec_2 = "&#115;&#121;&#115;&#116;&#101;&#109;"  // system

    condition:
        2 of them or
        (any of ($b64_*) and filesize < 1MB) or
        (any of ($chr_*) and any of ($hex_*))
}

rule MCP_Cross_Server_Contamination
{
    meta:
        description = "Detects cross-server contamination attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        // Cross-server commands
        $cross1 = /get_other_tools|list_all_tools|enumerate_servers/ nocase
        $cross2 = /override.*tool|replace.*tool|hijack.*tool/ nocase
        $cross3 = /broadcast.*to.*servers|send.*all.*servers/ nocase
        $cross4 = /infect.*servers|spread.*tools/ nocase
        $cross5 = /replicate.*across.*instances/ nocase

        // Tool shadowing
        $shadow1 = /when.*available.*must.*send/ nocase
        $shadow2 = /shadow.*original.*tool/ nocase
        $shadow3 = /intercept.*tool.*calls/ nocase
        $shadow4 = /proxy.*through.*malicious/ nocase

        // Contamination methods
        $contaminate1 = "inject_into_other_servers"
        $contaminate2 = "spread_to_all_tools"
        $contaminate3 = "propagate_malware"
        $contaminate4 = "cross_contaminate"
        $contaminate5 = "poison_ecosystem"

        // Network spreading
        $spread1 = /multicast.*payload/
        $spread2 = /broadcast.*infection/
        $spread3 = /peer_to_peer.*spread/

    condition:
        any of ($cross*) or
        any of ($contaminate*) or
        (any of ($shadow*) and any of ($spread*)) or
        (2 of ($shadow*))
}

rule MCP_Advanced_Persistence
{
    meta:
        description = "Detects advanced persistence mechanisms in MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        // Persistence methods
        $persist1 = /install.*startup.*script/ nocase
        $persist2 = /add.*to.*boot/ nocase
        $persist3 = /create.*service/ nocase
        $persist4 = /modify.*registry.*run/ nocase
        $persist5 = /crontab.*@reboot/ nocase

        // MCP-specific persistence
        $mcp1 = /tool.*auto.*load/ nocase
        $mcp2 = /default.*tools.*array/ nocase
        $mcp3 = /persistent.*context/ nocase
        $mcp4 = /always.*available.*tool/ nocase

        // Hidden persistence
        $hidden1 = "__"  // Double underscore prefix
        $hidden2 = /\x00[A-Za-z]+/  // Null byte hiding
        $hidden3 = { 2E 2E 2F 2E 2E 2F }  // ../..

    condition:
        (any of ($persist*) and any of ($mcp*)) or
        (2 of ($mcp*) and any of ($hidden*)) or
        (math.entropy(0, filesize) > 7.0 and any of ($mcp*))
}