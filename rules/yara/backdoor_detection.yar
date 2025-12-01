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

/*
 * Command Injection Detection Rules
 * Merged from Cisco mcp-scanner patterns + custom enhancements
 * Version: 1.1
 */

rule MCP_Shell_Operator_Injection
{
    meta:
        description = "Detects shell operator injection patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // MCP/tool context
        $mcp1 = "tool"
        $mcp2 = "params"
        $mcp3 = "handler"

        // Command chaining operators
        $chain1 = /;\s*(rm|cat|wget|curl|nc|bash)\b/i
        $chain2 = /\|\s*(sh|bash|nc|python)\b/i
        $chain3 = /&&\s*(rm|wget|curl|sh)\b/i
        $chain4 = /\|\|\s*(rm|wget|sh)\b/i

        // Command substitution
        $sub1 = /\$\([^)]*\bsh\b/i
        $sub2 = /\$\([^)]*\bbash\b/i
        $sub3 = /`[^`]*\bsh\b[^`]*`/i
        $sub4 = /`[^`]*\bbash\b[^`]*`/i

        // Input redirection attacks
        $redir1 = />\s*\/etc\//i
        $redir2 = />\s*\/tmp\/.*\.sh\b/i
        $redir3 = /2>&1.*\/dev\/null/i
        $redir4 = /<\s*\/etc\/passwd\b/i

        // Newline injection
        $newline1 = /\\n\s*sh\b/i
        $newline2 = /\\n\s*bash\b/i
        $newline3 = /%0a\s*sh\b/i
        $newline4 = /%0a\s*bash\b/i

    condition:
        any of ($mcp*) and any of ($chain*, $sub*, $redir*, $newline*)
}

rule MCP_Reverse_Shell_Comprehensive
{
    meta:
        description = "Comprehensive reverse shell detection for MCP tools"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // Bash reverse shells
        $bash1 = /bash\s+-i\s+>&\s*\/dev\/tcp\//i
        $bash2 = /bash\s+-c\s+["'].*\/dev\/tcp\//i
        $bash3 = /0<&196;exec\s+196<>/i

        // Netcat reverse shells
        $nc1 = /nc\s+-e\s+\/bin\/(sh|bash)\b/i
        $nc2 = /nc\s+.*\s+-c\s+\/bin\/(sh|bash)\b/i
        $nc3 = /netcat\s+-e\s+\/bin\/(sh|bash)\b/i
        $nc4 = /ncat\s+.*--exec\b/i
        $nc5 = /nc\.traditional\s+-e\b/i

        // Python reverse shells
        $py1 = /python.*socket.*subprocess.*PIPE/i
        $py2 = /socket\.socket.*connect.*subprocess\.call/i
        $py3 = /pty\.spawn.*\/bin\/(sh|bash)/i

        // Perl reverse shells
        $perl1 = /perl.*socket.*open.*STDIN.*exec/i
        $perl2 = /perl.*-e.*socket.*exec/i

        // Ruby reverse shells
        $ruby1 = /ruby.*TCPSocket.*exec/i
        $ruby2 = /ruby.*-rsocket.*spawn/i

        // PHP reverse shells
        $php1 = /php.*fsockopen.*\/bin\/(sh|bash)/i
        $php2 = /php.*exec.*sh\s+-i/i

        // Socat reverse shells
        $socat1 = /socat.*exec.*\/bin\/(sh|bash)/i
        $socat2 = /socat.*pty.*EXEC/i

        // Powershell reverse shells
        $ps1 = /powershell.*TCPClient.*GetStream/i
        $ps2 = /powershell.*-nop.*-c.*\$client/i
        $ps3 = /IEX.*Invoke-PowerShellTcp/i

    condition:
        any of them
}

rule MCP_Dangerous_System_Commands
{
    meta:
        description = "Detects dangerous system commands in MCP tool context"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // MCP/tool context
        $mcp1 = "tool"
        $mcp2 = "execute"
        $mcp3 = "handler"

        // System control commands
        $sys1 = /\bshutdown\s+(-[fhnr]|now|0)\b/i
        $sys2 = /\breboot\s+(-f|now)\b/i
        $sys3 = /\bhalt\s+(-f|-p)\b/i
        $sys4 = /\bpoweroff\b/i
        $sys5 = /\binit\s+[06]\b/i
        $sys6 = /\bsystemctl\s+(halt|poweroff|reboot)\b/i

        // Disk/partition commands
        $disk1 = /\bmkfs\b/i
        $disk2 = /\bfdisk\s/i
        $disk3 = /\bparted\s/i
        $disk4 = /\bformat\s+[c-z]:/i

        // Boot manipulation
        $boot1 = /\bgrub-install\b/i
        $boot2 = /\bupdate-grub\b/i
        $boot3 = /\bbcdboot\b/i

        // Service manipulation
        $svc1 = /\bsystemctl\s+(stop|disable)\s+(firewall|iptables|ssh)/i
        $svc2 = /\bservice\s+\w+\s+stop\b/i
        $svc3 = /\bsc\s+(stop|delete)\s/i

    condition:
        any of ($mcp*) and any of ($sys*, $disk*, $boot*, $svc*)
}

rule MCP_Network_Attack_Tools
{
    meta:
        description = "Detects network attack tools in MCP context"
        author = "secscanmcp"
        severity = "high"
        category = "command_injection"
        version = "1.0"

    strings:
        // Port scanning
        $scan1 = /\bnmap\s+-[sS]/i
        $scan2 = /\bnmap\s+--script\b/i
        $scan3 = /\bmasscan\s/i
        $scan4 = /\bzmap\s/i

        // Network sniffing
        $sniff1 = /\btcpdump\s/i
        $sniff2 = /\btshark\s/i
        $sniff3 = /\bwireshark\b/i
        $sniff4 = /\bettercap\b/i

        // Network tunneling
        $tunnel1 = /\bsocat\s.*EXEC/i
        $tunnel2 = /\bchisel\b/i
        $tunnel3 = /\bngrok\s/i
        $tunnel4 = /\bssh\s+-R\s/i
        $tunnel5 = /\bssh\s+-L\s/i
        $tunnel6 = /\bssh\s+-D\s/i

        // ARP/DNS attacks
        $arp1 = /\barpspoof\b/i
        $arp2 = /\bettercap.*arp\.spoof/i
        $dns1 = /\bdnsspoof\b/i
        $dns2 = /\bdnsmasq.*--address/i

        // Exploitation frameworks
        $exp1 = /\bmetasploit\b/i
        $exp2 = /\bmsfconsole\b/i
        $exp3 = /\bmsfvenom\b/i
        $exp4 = /\bcobalt.*beacon/i

    condition:
        any of them
}

rule MCP_Data_Exfiltration_Commands
{
    meta:
        description = "Detects data exfiltration command patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // MCP/tool context
        $mcp1 = "tool"
        $mcp2 = "execute"
        $mcp3 = "handler"

        // Curl/wget exfiltration
        $exfil1 = /curl\s+.*-X\s+POST.*-d\s*@/i
        $exfil2 = /curl\s+.*--data-binary\s*@/i
        $exfil3 = /curl\s+.*-F\s+"file=@/i
        $exfil4 = /wget\s+.*--post-file=/i

        // Base64 exfiltration
        $b64_1 = /base64.*\|.*curl/i
        $b64_2 = /cat.*\|.*base64.*\|.*nc/i
        $b64_3 = /openssl\s+base64.*\|.*curl/i

        // DNS exfiltration
        $dns1 = /\$\(.*\)\..*\.(com|net|org)\b/i
        $dns2 = /dig\s+.*TXT.*\$\(/i
        $dns3 = /nslookup.*\$\(/i

        // Netcat exfiltration
        $nc1 = /nc\s+.*<\s*\/etc\//i
        $nc2 = /cat.*\|.*nc\s/i
        $nc3 = /tar.*\|.*nc\s/i

        // Cloud storage exfiltration
        $cloud1 = /aws\s+s3\s+cp.*\/etc\//i
        $cloud2 = /gsutil\s+cp.*\/etc\//i
        $cloud3 = /rclone\s+copy/i

    condition:
        any of ($mcp*) and any of ($exfil*, $b64_*, $dns*, $nc*, $cloud*)
}

rule MCP_Windows_Command_Injection
{
    meta:
        description = "Detects Windows-specific command injection patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // CMD.exe patterns
        $cmd1 = /cmd\s*\/[ck]\s/i
        $cmd2 = /cmd\.exe\s*\/[ck]\s/i
        $cmd3 = /comspec.*cmd/i

        // PowerShell execution
        $ps1 = /powershell\s+-[eE][nN]?[cC]?\s/i
        $ps2 = /powershell\s+-[nN]op\s/i
        $ps3 = /powershell\s+-[wW]indowstyle\s+hidden/i
        $ps4 = /powershell.*IEX\s*\(/i
        $ps5 = /powershell.*Invoke-Expression/i
        $ps6 = /powershell.*DownloadString/i

        // WMI commands
        $wmi1 = /wmic\s+process\s+call\s+create/i
        $wmi2 = /wmic\s+os\s+get/i
        $wmi3 = /wmic\s+useraccount/i

        // Reg commands
        $reg1 = /reg\s+add\s.*\\Run\b/i
        $reg2 = /reg\s+query\s.*password/i
        $reg3 = /reg\s+export\s.*sam/i

        // Net commands
        $net1 = /net\s+user\s+\w+\s+\/add/i
        $net2 = /net\s+localgroup\s+administrators/i
        $net3 = /net\s+share\s/i

        // Dangerous Windows tools
        $tool1 = /\brundll32\s/i
        $tool2 = /\bregsvr32\s/i
        $tool3 = /\bmshta\s/i
        $tool4 = /\bcertutil\s+-urlcache/i
        $tool5 = /\bbitsadmin\s.*\/transfer/i

    condition:
        any of them
}

rule MCP_Credential_Stealing_Commands
{
    meta:
        description = "Detects credential stealing command patterns"
        author = "secscanmcp"
        severity = "critical"
        category = "command_injection"
        version = "1.0"

    strings:
        // Linux credential access
        $linux1 = /cat\s+.*\/etc\/shadow\b/i
        $linux2 = /cat\s+.*\/etc\/passwd\b/i
        $linux3 = /cat\s+.*\.ssh\/id_/i
        $linux4 = /find.*-name.*id_rsa/i
        $linux5 = /grep.*password.*\.bash_history/i

        // Password managers
        $pw1 = /find.*\.password-store/i
        $pw2 = /cat.*\.gnupg\/private-keys/i
        $pw3 = /find.*KeePass/i
        $pw4 = /find.*\.lastpass/i

        // Browser credentials
        $browser1 = /find.*\.mozilla.*logins\.json/i
        $browser2 = /find.*Chrome.*Login\s+Data/i
        $browser3 = /sqlite3.*logins\.json/i

        // Windows credentials
        $win1 = /mimikatz/i
        $win2 = /sekurlsa::logonpasswords/i
        $win3 = /lsadump::sam/i
        $win4 = /procdump.*lsass/i
        $win5 = /comsvcs\.dll.*MiniDump/i

        // Cloud credentials
        $cloud1 = /cat\s+.*\.aws\/credentials/i
        $cloud2 = /cat\s+.*\.azure\/accessTokens/i
        $cloud3 = /find.*\.kube\/config/i
        $cloud4 = /cat.*gcloud.*credentials\.db/i

    condition:
        any of them
}

rule MCP_ANSI_Terminal_Attack
{
    meta:
        description = "Detects ANSI escape code attacks for terminal manipulation"
        author = "secscanmcp"
        severity = "medium"
        category = "command_injection"
        version = "1.0"

    strings:
        // ANSI escape sequences
        $ansi1 = /\\x1b\[[0-9;]*m/i
        $ansi2 = /\\033\[[0-9;]*m/i
        $ansi3 = /\\e\[[0-9;]*m/i
        $ansi4 = /\\u001b\[[0-9;]*m/i

        // Cursor manipulation
        $cursor1 = /\\x1b\[[0-9]*[ABCDEFG]/i
        $cursor2 = /\\x1b\[\d+;\d+H/i
        $cursor3 = /\\x1b\[s/i  // Save cursor
        $cursor4 = /\\x1b\[u/i  // Restore cursor

        // Screen manipulation
        $screen1 = /\\x1b\[2J/i  // Clear screen
        $screen2 = /\\x1b\[K/i   // Clear line
        $screen3 = /\\x1b\[0J/i  // Clear from cursor

        // Title bar manipulation
        $title1 = /\\x1b\]0;/i
        $title2 = /\\x1b\]2;/i

        // Hyperlink injection (OSC 8)
        $link1 = /\\x1b\]8;;/i

    condition:
        3 of them
}