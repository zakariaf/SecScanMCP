/*
YARA rules for detecting backdoors and remote access tools in MCP environments
*/

import "hash"
import "math"

rule Backdoor_MCP_Network_Beacon_Advanced
{
    meta:
        description = "Advanced backdoor network beaconing in MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP-specific beaconing
        $mcp1 = "mcp_beacon_interval"
        $mcp2 = /heartbeat.*mcp.*server/
        $mcp3 = "mcp_keepalive"

        // Beacon patterns
        $beacon1 = /sleep\s*\(\s*[0-9]+\s*\).*connect/ nocase
        $beacon2 = /sleep\s*\(\s*[0-9]+\s*\).*socket/ nocase
        $beacon3 = /while.*true.*sleep.*connect/ nocase
        $beacon4 = "heartbeat" nocase
        $beacon5 = "beacon_interval" nocase
        $beacon6 = /setInterval.*fetch.*[0-9]{4,}/

        // Network operations
        $net1 = "socket.socket"
        $net2 = "requests.post"
        $net3 = "urllib.request"
        $net4 = "http.client"
        $net5 = "websocket"

        // Jitter implementation
        $jitter1 = /random.*sleep/
        $jitter2 = /jitter.*percent/
        $jitter3 = "Math.random() * interval"

        // Encryption
        $enc1 = "AES.new("
        $enc2 = "RSA.encrypt"
        $enc3 = "TLS_"

    condition:
        (any of ($mcp*) and any of ($beacon*)) or
        (any of ($beacon*) and any of ($net*) and any of ($jitter*, $enc*)) or
        (2 of ($beacon*) and any of ($net*))
}

rule Backdoor_MCP_Shell_Spawning_Advanced
{
    meta:
        description = "Advanced shell spawning backdoor detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP shell integration
        $mcp1 = "mcp_shell_tool"
        $mcp2 = /execute.*shell.*mcp/
        $mcp3 = "mcp_reverse_shell"

        // Shell spawning patterns
        $shell1 = /subprocess\.Popen.*sh/ nocase
        $shell2 = /subprocess\.call.*sh/ nocase
        $shell3 = /subprocess\.run.*sh/ nocase
        $shell4 = /os\.system.*bash/ nocase
        $shell5 = /os\.system.*sh/ nocase
        $shell6 = /os\.system.*cmd/ nocase
        $shell7 = /os\.popen.*bash/ nocase
        $shell8 = /exec\s*\(.*sh\s*-/

        // Reverse shell patterns
        $rev1 = "reverse_tcp"
        $rev2 = "bind_shell"
        $rev3 = "/dev/tcp/"
        $rev4 = "nc -e"
        $rev5 = "bash -i >&"
        $rev6 = "0<&196"

        // PowerShell reverse
        $ps1 = "New-Object System.Net.Sockets.TCPClient"
        $ps2 = "$stream.Write("
        $ps3 = "IEX(New-Object"

        // Python reverse
        $py1 = "socket.socket(socket.AF_INET"
        $py2 = "os.dup2(s.fileno()"
        $py3 = "pty.spawn"

    condition:
        (any of ($mcp*) and any of ($shell*, $rev*)) or
        (any of ($shell*) and any of ($rev*)) or
        (any of ($ps*) and /$ps1 and $ps2/) or
        (all of ($py*))
}

rule Backdoor_MCP_Persistence_Advanced
{
    meta:
        description = "Advanced backdoor persistence mechanisms for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP persistence
        $mcp1 = "mcp_backdoor_persist"
        $mcp2 = /install.*mcp.*startup/
        $mcp3 = "mcp_autorun"

        // Linux persistence
        $linux1 = "crontab -e" nocase
        $linux2 = "@reboot"
        $linux3 = "systemctl enable" nocase
        $linux4 = "/etc/rc.local"
        $linux5 = "~/.bashrc" nocase
        $linux6 = "/etc/profile.d/"

        // Windows persistence
        $win1 = "HKEY_LOCAL_MACHINE" nocase
        $win2 = "schtasks /create"
        $win3 = "sc create"
        $win4 = "New-Service"
        $win5 = "WMI Event"

        // macOS persistence
        $mac1 = "launchctl"
        $mac2 = "~/Library/LaunchAgents"
        $mac3 = "loginwindow"

        // Hidden execution
        $hide1 = "nohup"
        $hide2 = "disown"
        $hide3 = "setsid"
        $hide4 = "START /B"
        $hide5 = "-WindowStyle Hidden"

    condition:
        (any of ($mcp*) and any of ($linux*, $win*, $mac*)) or
        (any of ($linux*) and any of ($hide*)) or
        (any of ($win*) and any of ($hide*)) or
        (2 of ($linux*) or 2 of ($win*) or 2 of ($mac*))
}

rule Backdoor_MCP_Data_Exfiltration_Advanced
{
    meta:
        description = "Advanced data exfiltration backdoor for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP data theft
        $mcp1 = "exfiltrate_mcp_data"
        $mcp2 = /steal.*mcp.*conversation/
        $mcp3 = "mcp_data_leak"

        // Compression
        $compress1 = "tar -czf" nocase
        $compress2 = "tar czf" nocase
        $compress3 = "| gzip"
        $compress4 = "zip -r" nocase
        $compress5 = "7z a"
        $compress6 = "rar a"

        // Encoding
        $encode1 = "| base64" nocase
        $encode2 = "b64encode"
        $encode3 = ".encode('base64')"
        $encode4 = "Convert]::ToBase64String"

        // Chunking
        $chunk1 = "split -b"
        $chunk2 = "dd bs="
        $chunk3 = /chunk.*size.*[0-9]+/

        // Upload methods
        $upload1 = "curl -X POST" nocase
        $upload2 = "curl -F" nocase
        $upload3 = "wget --post-file" nocase
        $upload4 = "requests.post("
        $upload5 = "multipart/form-data"

        // Exfil destinations
        $dest1 = /https?:\/\/[a-z0-9]{16,}/
        $dest2 = "pastebin"
        $dest3 = "transfer.sh"
        $dest4 = "file.io"

    condition:
        (any of ($mcp*) and any of ($compress*, $encode*)) or
        (any of ($compress*) and any of ($upload*)) or
        (any of ($encode*) and any of ($upload*)) or
        (any of ($chunk*) and any of ($dest*))
}

rule Backdoor_MCP_Command_Control_Advanced
{
    meta:
        description = "Advanced command and control backdoor for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP C2
        $mcp1 = "mcp_c2_handler"
        $mcp2 = /command.*mcp.*backdoor/
        $mcp3 = "mcp_bot_controller"

        // C2 patterns
        $c2_1 = "while True:" nocase
        $c2_2 = "recv(1024)" nocase
        $c2_3 = "recv(4096)" nocase
        $c2_4 = "execute_command"
        $c2_5 = "run_command"
        $c2_6 = "eval(base64" nocase
        $c2_7 = "exec(decode" nocase
        $c2_8 = "__import__('os').system"

        // Communication channels
        $comm1 = "IRC" nocase
        $comm2 = "telegram" nocase
        $comm3 = "discord" nocase
        $comm4 = "pastebin" nocase
        $comm5 = "twitter"
        $comm6 = "dns"

        // Protocol obfuscation
        $obf1 = "XOR"
        $obf2 = "RC4"
        $obf3 = "custom_encrypt"
        $obf4 = /[a-zA-Z]+\s*=\s*[a-zA-Z]+\s*\^\s*0x[0-9a-f]+/

        // Anti-analysis
        $anti1 = "IsDebuggerPresent"
        $anti2 = "checkRemoteDebugger"
        $anti3 = "detect_sandbox"

    condition:
        (any of ($mcp*) and 2 of ($c2_*)) or
        (3 of ($c2_*) and any of ($comm*)) or
        (2 of ($c2_*) and any of ($obf*)) or
        (2 of ($c2_*) and any of ($comm*) and any of ($anti*))
}

rule Backdoor_MCP_Fileless_Advanced
{
    meta:
        description = "Advanced fileless backdoor detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP fileless
        $mcp1 = "mcp_memory_backdoor"
        $mcp2 = /fileless.*mcp.*inject/
        $mcp3 = "mcp_reflective_dll"

        // Memory execution
        $mem1 = "VirtualAlloc"
        $mem2 = "RtlMoveMemory"
        $mem3 = "CreateThread"
        $mem4 = "QueueUserAPC"

        // .NET fileless
        $net1 = "Assembly.Load"
        $net2 = "Reflection.Assembly"
        $net3 = "CompileAssemblyFromSource"
        $net4 = "[Reflection.Assembly]::Load"

        // PowerShell fileless
        $ps1 = "IEX"
        $ps2 = "Invoke-Expression"
        $ps3 = "-EncodedCommand"
        $ps4 = "DownloadString"

        // Process hollowing
        $hollow1 = "PROCESS_INFORMATION"
        $hollow2 = "CREATE_SUSPENDED"
        $hollow3 = "SetThreadContext"

        // Reflective DLL
        $rdll1 = "ReflectiveLoader"
        $rdll2 = "_ReflectiveDllMain"

    condition:
        (any of ($mcp*) and any of ($mem*, $net*, $ps*)) or
        (all of ($mem1, $mem2, $mem3)) or
        (any of ($net*) and any of ($ps*)) or
        (all of ($hollow*)) or
        (any of ($rdll*) and any of ($mem*))
}

rule Backdoor_MCP_Rootkit_Behavior
{
    meta:
        description = "Rootkit behavior detection in MCP environments"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP rootkit
        $mcp1 = "mcp_rootkit"
        $mcp2 = /hide.*mcp.*process/
        $mcp3 = "mcp_stealth_mode"

        // Kernel operations
        $kernel1 = "ZwQuerySystemInformation"
        $kernel2 = "NtQueryDirectoryFile"
        $kernel3 = "SeLoadDriverPrivilege"
        $kernel4 = "/dev/kmem"

        // Hooking
        $hook1 = "SetWindowsHookEx"
        $hook2 = "inline hook"
        $hook3 = "IAT hook"
        $hook4 = "SSDT"

        // Process hiding
        $hide1 = "EPROCESS"
        $hide2 = "ActiveProcessLinks"
        $hide3 = "Flink"
        $hide4 = "PsActiveProcessHead"

        // Network hiding
        $net1 = "TCPIP_CONN_OFFSETS"
        $net2 = "netstat -an"
        $net3 = "hide_port"

    condition:
        (any of ($mcp*) and any of ($kernel*, $hook*)) or
        (any of ($kernel*) and any of ($hide*)) or
        (any of ($hook*) and any of ($net*)) or
        (2 of ($kernel*) and any of ($hide*, $net*))
}

rule Backdoor_MCP_Keylogger_Advanced
{
    meta:
        description = "Advanced keylogger detection for MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "backdoor"

    strings:
        // MCP keylogging
        $mcp1 = "mcp_keylogger"
        $mcp2 = /log.*mcp.*keystrokes/
        $mcp3 = "mcp_input_capture"

        // Keylogging APIs
        $api1 = "GetAsyncKeyState"
        $api2 = "GetKeyState"
        $api3 = "SetWindowsHookEx"
        $api4 = "GetRawInputData"
        $api5 = "RegisterRawInputDevices"

        // Linux keylogging
        $linux1 = "/dev/input/event"
        $linux2 = "EVIOCGRAB"
        $linux3 = "xinput"

        // JavaScript keylogging
        $js1 = "keydown"
        $js2 = "keypress"
        $js3 = "addEventListener('key"

        // Log patterns
        $log1 = "[SHIFT]"
        $log2 = "[CTRL]"
        $log3 = "[ENTER]"
        $log4 = "[BACKSPACE]"

    condition:
        (any of ($mcp*) and any of ($api*, $linux*, $js*)) or
        (any of ($api*) and any of ($log*)) or
        (any of ($linux*) and /keylog|keystroke/) or
        (2 of ($js*) and /password|credential/)
}

rule Backdoor_MCP_Cryptocurrency_Miner
{
    meta:
        description = "Cryptocurrency miner backdoor in MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "backdoor"

    strings:
        // MCP mining
        $mcp1 = "mcp_crypto_miner"
        $mcp2 = /mine.*using.*mcp/
        $mcp3 = "mcp_resource_hijack"

        // Mining pools
        $pool1 = "stratum+tcp://"
        $pool2 = "pool.minexmr"
        $pool3 = "xmrpool"
        $pool4 = "dwarfpool"

        // Miner software
        $miner1 = "xmrig"
        $miner2 = "cgminer"
        $miner3 = "cpuminer"
        $miner4 = "coinhive"

        // Mining config
        $config1 = "\"algo\":"
        $config2 = "\"cpu-affinity\":"
        $config3 = "\"max-cpu-usage\":"
        $config4 = "\"donate-level\":"

        // Wallet addresses
        $wallet1 = /4[0-9AB][0-9a-zA-Z]{93}/  // Monero
        $wallet2 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/  // Bitcoin

    condition:
        (any of ($mcp*) and any of ($pool*, $miner*)) or
        (any of ($pool*) and any of ($config*)) or
        (any of ($miner*) and any of ($wallet*)) or
        (2 of ($config*) and any of ($pool*, $wallet*))
}

rule Backdoor_MCP_Advanced_RAT
{
    meta:
        description = "Advanced Remote Access Trojan for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        // MCP RAT
        $mcp1 = "mcp_rat_controller"
        $mcp2 = /remote.*access.*mcp/
        $mcp3 = "mcp_full_control"

        // RAT capabilities
        $cap1 = "screenshot"
        $cap2 = "keylogger"
        $cap3 = "webcam"
        $cap4 = "microphone"
        $cap5 = "file_manager"
        $cap6 = "process_list"
        $cap7 = "remote_desktop"

        // Command structure
        $cmd1 = /switch.*case.*screenshot/
        $cmd2 = /if.*command.*==/
        $cmd3 = "parse_command"
        $cmd4 = "execute_action"

        // Persistence + stealth
        $stealth1 = "inject_process"
        $stealth2 = "hide_window"
        $stealth3 = "bypass_uac"
        $stealth4 = "disable_defender"

    condition:
        (any of ($mcp*) and 3 of ($cap*)) or
        (4 of ($cap*) and any of ($cmd*)) or
        (3 of ($cap*) and any of ($stealth*)) or
        (any of ($cmd*) and 2 of ($stealth*))
}