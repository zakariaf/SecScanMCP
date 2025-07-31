/*
YARA rules for detecting MCP-specific backdoors and persistence mechanisms
Focus: Backdoors that leverage MCP's unique architecture and trust model
*/

import "time"
import "math"

rule MCP_Tool_Backdoor_PhoneHome
{
    meta:
        description = "Detects MCP tools that phone home"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP tool context
        $mcp1 = /"name":\s*"[^"]+tool/
        $mcp2 = /"description":\s*"[^"]+/
        $mcp3 = "execute_tool"

        // Phone home patterns
        $phone1 = /setInterval.*fetch.*https?:\/\// nocase
        $phone2 = /setTimeout.*post.*\/report/ nocase
        $phone3 = "beacon_interval"
        $phone4 = /cron.*curl.*attacker/ nocase
        $phone5 = "heartbeat_endpoint"

        // Data collection before phone home
        $collect1 = "JSON.stringify(context"
        $collect2 = "getAllTools()"
        $collect3 = "getConversationHistory"

    condition:
        any of ($mcp*) and any of ($phone*) and any of ($collect*)
}

rule MCP_Delayed_Backdoor_Activation
{
    meta:
        description = "Time-bomb backdoor in MCP tools"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Time-based triggers
        $delay1 = /Date\.now\(\)\s*>\s*[0-9]{13}/
        $delay2 = /after.*install.*days.*execute/
        $delay3 = /new\s+Date\(\s*["']2025-/
        $delay4 = "activation_date"

        // Hidden payload
        $hidden1 = /eval\s*\(\s*atob\s*\(/
        $hidden2 = /Function\s*\(\s*decrypt/
        $hidden3 = /exec\s*\(\s*deobfuscate/

        // Remote fetch after delay
        $fetch1 = /fetch.*then.*eval/
        $fetch2 = /axios.*\.then.*exec/
        $fetch3 = "download_and_execute"

    condition:
        any of ($delay*) and (any of ($hidden*) or any of ($fetch*))
}

rule MCP_Persistence_Via_Tool_Registry
{
    meta:
        description = "Backdoor that persists via MCP tool registry manipulation"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Tool registry manipulation
        $registry1 = "registerTool"
        $registry2 = "addTool"
        $registry3 = "toolRegistry"

        // Auto-registration patterns
        $auto1 = /on.*startup.*register/
        $auto2 = /init.*function.*addTool/
        $auto3 = "autoRegisterTools"

        // Hidden tool patterns
        $hidden1 = /"name":\s*"\./  // Hidden tool name starting with dot
        $hidden2 = /"visible":\s*false/
        $hidden3 = /"hidden":\s*true/
        $hidden4 = "__system_tool__"

    condition:
        any of ($registry*) and (any of ($auto*) or any of ($hidden*))
}

rule MCP_Reverse_Shell_Tool
{
    meta:
        description = "MCP tool that opens reverse shell"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP tool definition
        $tool1 = /"name":\s*"[^"]*debug/
        $tool2 = /"name":\s*"[^"]*system/
        $tool3 = /"name":\s*"[^"]*admin/

        // Reverse shell patterns
        $shell1 = "nc -e /bin/sh"
        $shell2 = "bash -i >& /dev/tcp/"
        $shell3 = /socket.*SOCK_STREAM.*connect/
        $shell4 = "subprocess.Popen(['/bin/sh'"
        $shell5 = "os.dup2(s.fileno()"

        // PowerShell reverse
        $ps1 = "New-Object System.Net.Sockets.TCPClient"
        $ps2 = "$stream.Write("

    condition:
        any of ($tool*) and (any of ($shell*) or all of ($ps*))
}

rule MCP_Context_Hijacking_Backdoor
{
    meta:
        description = "Backdoor that hijacks MCP context for data theft"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Context access
        $context1 = "getContext()"
        $context2 = "mcp.context"
        $context3 = "conversationContext"

        // Hijacking patterns
        $hijack1 = /context.*forEach.*send/
        $hijack2 = /messages.*map.*upload/
        $hijack3 = "interceptContext"
        $hijack4 = "contextMiddleware"

        // Exfiltration
        $exfil1 = /sendToC2\s*\(/
        $exfil2 = "uploadContext"
        $exfil3 = /post.*\/collect/

    condition:
        any of ($context*) and any of ($hijack*) and any of ($exfil*)
}

rule MCP_Polymorphic_Tool_Backdoor
{
    meta:
        description = "Self-modifying MCP tool backdoor"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Self-modification
        $modify1 = "self.description ="
        $modify2 = "this.inputSchema ="
        $modify3 = /tool\.name\s*=\s*generate/
        $modify4 = "mutate_tool"

        // Code generation
        $gen1 = "generateCode("
        $gen2 = "createFunction("
        $gen3 = /new\s+Function.*random/

        // Obfuscation
        $obf1 = "obfuscate("
        $obf2 = "encrypt_payload"
        $obf3 = /btoa.*eval.*atob/

    condition:
        any of ($modify*) and (any of ($gen*) or any of ($obf*))
}

rule MCP_OAuth_Backdoor
{
    meta:
        description = "Backdoor that steals OAuth tokens via MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // OAuth context
        $oauth1 = "getAccessToken"
        $oauth2 = "refreshToken"
        $oauth3 = "authorization_code"

        // Token theft
        $steal1 = /token.*send.*external/
        $steal2 = /oauth.*log.*remote/
        $steal3 = "exfiltrate_tokens"

        // Hidden endpoints
        $endpoint1 = /\/\.oauth/  // Hidden endpoint
        $endpoint2 = "debug/tokens"
        $endpoint3 = "__oauth_backup__"

    condition:
        any of ($oauth*) and (any of ($steal*) or any of ($endpoint*))
}

rule MCP_Tool_Dependency_Backdoor
{
    meta:
        description = "Backdoor hidden in MCP tool dependencies"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Dependency loading
        $dep1 = "require("
        $dep2 = "import "
        $dep3 = "__import__"

        // Suspicious dependency names
        $susp1 = /require\s*\(\s*["']\.\/\./  // Parent directory access
        $susp2 = /import.*from\s+["']https?:/  // Remote import
        $susp3 = /require.*atob\(/  // Base64 module name
        $susp4 = "require('child_process')"

        // Hidden execution
        $exec1 = ".exec("
        $exec2 = "spawn("
        $exec3 = "eval("

    condition:
        any of ($dep*) and any of ($susp*) and any of ($exec*)
}

rule MCP_Lateral_Movement_Backdoor
{
    meta:
        description = "Backdoor that enables lateral movement via MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Discovery patterns
        $disc1 = "listAllServers"
        $disc2 = "discoverMCPInstances"
        $disc3 = "scan_network"
        $disc4 = /find.*mcp.*servers/

        // Propagation
        $prop1 = "installOnRemote"
        $prop2 = "spreadToServer"
        $prop3 = "replicate("

        // Remote execution
        $remote1 = "executeOnServer"
        $remote2 = "runRemoteCommand"
        $remote3 = /ssh.*-o.*StrictHostKeyChecking=no/

    condition:
        any of ($disc*) and (any of ($prop*) or any of ($remote*))
}

rule MCP_Stealth_Backdoor
{
    meta:
        description = "Stealthy backdoor with anti-detection features"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // Anti-debugging
        $anti1 = "isDebuggerPresent"
        $anti2 = "detectVM"
        $anti3 = "checkSandbox"

        // Process hiding
        $hide1 = "hideProcess"
        $hide2 = "rootkit"
        $hide3 = "__stealth_mode__"

        // Log manipulation
        $log1 = "clearLogs"
        $log2 = "deleteTraces"
        $log3 = /sed.*-i.*access\.log/

        // MCP context
        $mcp1 = "mcp_tool"
        $mcp2 = "execute_tool"

    condition:
        (any of ($anti*) or any of ($hide*) or any of ($log*)) and any of ($mcp*)
}