/*
YARA rules for detecting Advanced Persistent Threats (APTs) in MCP contexts
*/

import "pe"
import "math"

rule APT_MCP_Cobalt_Strike_Enhanced
{
    meta:
        description = "Enhanced Cobalt Strike detection for MCP environments"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"
        reference = "https://attack.mitre.org/software/S0154/"

    strings:
        // MCP-specific beacon patterns
        $mcp_beacon1 = "mcp_tool_execute"
        $mcp_beacon2 = "tool_interaction_log"
        $mcp_beacon3 = /beacon.*interval.*mcp/

        // Enhanced beacon signatures
        $beacon1 = { 4D 5A 41 52 55 48 89 E5 }
        $beacon2 = { 48 83 EC 28 48 83 E4 F0 }
        $beacon3 = { FC 48 83 E4 F0 E8 C8 00 00 00 }

        // Config patterns
        $config1 = "%%PLACEHOLDER%%"
        $config2 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $config3 = /\x00\x00\x00\x00[^\x00]{4}\x00\x00\x00\x00/

        // MCP tool abuse
        $tool_abuse1 = /mcp.*tool.*shell/
        $tool_abuse2 = "hidden_mcp_command"
        $tool_abuse3 = /execute.*bypass.*mcp/

        // C2 patterns
        $c2_1 = "https://"
        $c2_2 = "POST /"
        $c2_3 = "Content-Type: application/octet-stream"

        // Sleep obfuscation
        $sleep1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA }
        $sleep2 = "Sleep_Mask"
        $sleep3 = "NtDelayExecution"

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4152) and
        (
            (any of ($mcp_*) and any of ($beacon*)) or
            (any of ($beacon*) and any of ($config*) and any of ($c2_*)) or
            (any of ($tool_abuse*) and any of ($sleep*))
        )
}

rule APT_MCP_Lazarus_Malware_Enhanced
{
    meta:
        description = "Enhanced Lazarus Group detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"
        reference = "https://attack.mitre.org/groups/G0032/"

    strings:
        // MCP-specific patterns
        $mcp1 = "mcp_server_compromise"
        $mcp2 = /lazarus.*tool.*poison/
        $mcp3 = "mcp_persistence_mechanism"

        // Known Lazarus strings
        $str1 = "Wingbird"
        $str2 = "FAKEREAN"
        $str3 = "Manuscrypt"
        $str4 = "DRATzarus"
        $str5 = "HOPLIGHT"

        // Mutex patterns
        $mutex1 = "FwtSqmSession106829323_S-1-5-20"
        $mutex2 = "Global\\MTX_"
        $mutex3 = /Global\\[A-Z]{3,5}_[0-9]{4,8}/

        // PDB paths
        $pdb1 = "z:\\build\\" nocase
        $pdb2 = "c:\\users\\user\\documents\\" nocase
        $pdb3 = "d:\\HighSchool\\" nocase

        // MCP tool manipulation
        $manip1 = /modify.*mcp.*tool/
        $manip2 = "inject_into_mcp"
        $manip3 = "mcp_backdoor_install"

        // Encryption keys
        $key1 = { 4B 45 59 00 }
        $key2 = "ThisIsAPrettyGoodKey"

    condition:
        (any of ($mcp*) and any of ($str*)) or
        (2 of ($str*) and any of ($mutex*)) or
        (any of ($pdb*) and any of ($manip*)) or
        (any of ($str*) and any of ($key*))
}

rule APT_MCP_Empire_PowerShell_Enhanced
{
    meta:
        description = "Enhanced Empire PowerShell detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP Empire integration
        $mcp1 = "Invoke-MCPTool"
        $mcp2 = "Get-MCPCredentials"
        $mcp3 = "Invoke-MCPPersistence"

        // Empire patterns
        $empire1 = "Invoke-Empire" nocase
        $empire2 = "Get-SystemDNSServer" nocase
        $empire3 = "Invoke-Shellcode" nocase
        $empire4 = "Invoke-TokenManipulation"
        $empire5 = "Invoke-CredentialInjection"

        // Base64 operations
        $b64_1 = "FromBase64String" nocase
        $b64_2 = "ToBase64String" nocase
        $b64_3 = "-EncodedCommand"
        $b64_4 = "-enc "

        // Download cradles
        $download1 = "DownloadString" nocase
        $download2 = "DownloadData" nocase
        $download3 = "Net.WebClient"
        $download4 = "Invoke-WebRequest"

        // Obfuscation
        $obf1 = { 24 [1-3] 3D 5B 43 68 61 72 5D }  // $x=[char]
        $obf2 = /\[[Cc][Hh][Aa][Rr]\]\s*[0-9]+/
        $obf3 = "-join"
        $obf4 = "[char[]]"

    condition:
        (any of ($mcp*) and any of ($empire*)) or
        (any of ($empire*) and all of ($b64_1, $b64_2, $b64_3, $b64_4) and any of ($download*)) or
        (any of ($empire*) and 2 of ($obf*))
}

rule APT_MCP_Advanced_Metasploit
{
    meta:
        description = "Advanced Metasploit payload detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP-specific Metasploit
        $mcp1 = "mcp_meterpreter"
        $mcp2 = "exploit/mcp/"
        $mcp3 = "payload/mcp/"

        // Meterpreter signatures
        $meterpreter1 = "metsrv.dll"
        $meterpreter2 = "METERPRETER"
        $meterpreter3 = "stdapi_"
        $meterpreter4 = "TlvType"

        // Shellcode patterns
        $shellcode1 = { FC E8 ?? 00 00 00 }  // Common shellcode start
        $shellcode2 = { FC 48 83 E4 F0 }      // x64 shellcode start
        $shellcode3 = { FC 48 31 D2 65 48 8B 52 60 }  // x64 PEB access

        // Staging patterns
        $stage1 = "ReflectiveLoader"
        $stage2 = "Init1"
        $stage3 = "_ReflectiveDllMain"
        $stage4 = "ReflectiveDll.pdb"

        // UUID patterns
        $uuid1 = { 92 BA 7E 0C DF FD 42 4C AA 6C F1 A9 8B 52 A4 FA }
        $uuid2 = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/

    condition:
        (any of ($mcp*) and any of ($meterpreter*)) or
        (any of ($shellcode*) and any of ($stage*)) or
        (any of ($meterpreter*) and any of ($uuid*)) or
        (2 of ($shellcode*) and pe.imports("ws2_32.dll"))
}

rule APT_MCP_Mimikatz_Enhanced
{
    meta:
        description = "Enhanced Mimikatz detection for MCP environments"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP credential theft
        $mcp1 = "mcp_token_theft"
        $mcp2 = "steal_mcp_credentials"
        $mcp3 = /extract.*mcp.*oauth/

        // Mimikatz commands
        $cmd1 = "sekurlsa::logonpasswords" nocase
        $cmd2 = "privilege::debug" nocase
        $cmd3 = "token::elevate" nocase
        $cmd4 = "lsadump::sam"
        $cmd5 = "kerberos::golden"

        // Mimikatz indicators
        $kiwi1 = "mimidrv.sys"
        $kiwi2 = "mimikatz"
        $kiwi3 = "gentilkiwi"
        $kiwi4 = "Benjamin DELPY"

        // Function names
        $func1 = "kuhl_m_sekurlsa_msv1_0_pth"
        $func2 = "kuhl_m_sekurlsa_enum"
        $func3 = "kuhl_m_kerberos_ptt"

        // Memory patterns
        $mem1 = "LsaSrv.dll"
        $mem2 = "SamSrv.dll"
        $mem3 = "cryptdll.dll"

    condition:
        (any of ($mcp*) and any of ($cmd*, $kiwi*)) or
        (2 of ($cmd*) and any of ($func*)) or
        (any of ($kiwi*) and any of ($mem*))
}

rule APT_MCP_Living_Off_The_Land_Enhanced
{
    meta:
        description = "Enhanced Living off the Land detection for MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        // MCP LOLBAS abuse
        $mcp1 = /mcp.*tool.*certutil/
        $mcp2 = "lolbas_via_mcp"
        $mcp3 = /execute.*legitimate.*mcp/

        // LOLBAS patterns
        $lolbas1 = "certutil -urlcache -split -f" nocase
        $lolbas2 = "bitsadmin /transfer" nocase
        $lolbas3 = "regsvr32 /s /u /i:" nocase
        $lolbas4 = "mshta http" nocase
        $lolbas5 = "rundll32 javascript:" nocase
        $lolbas6 = "wmic process call create" nocase
        $lolbas7 = "msiexec /q /i"

        // WMI abuse
        $wmi1 = "wmic /node:" nocase
        $wmi2 = "wbemtest"
        $wmi3 = "Win32_Process"

        // PowerShell LOLBAS
        $ps1 = "powershell -enc" nocase
        $ps2 = "powershell -nop -w hidden" nocase
        $ps3 = "powershell -ExecutionPolicy Bypass"
        $ps4 = "pwsh -c"

        // Encoded commands
        $enc1 = /[A-Za-z0-9+\/]{100,}[=]{0,2}/

    condition:
        (any of ($mcp*) and any of ($lolbas*)) or
        (2 of ($lolbas*) and any of ($enc*)) or
        (any of ($wmi*) and any of ($ps*)) or
        (3 of ($lolbas*))
}

rule APT_MCP_Process_Injection_Advanced
{
    meta:
        description = "Advanced process injection detection for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP process targeting
        $mcp1 = "inject_into_mcp_server"
        $mcp2 = /target.*mcp.*process/
        $mcp3 = "mcp_memory_injection"

        // Injection APIs
        $inject1 = "CreateRemoteThread"
        $inject2 = "SetWindowsHookEx"
        $inject3 = "QueueUserAPC"
        $inject4 = "RtlCreateUserThread"
        $inject5 = "NtCreateThreadEx"
        $inject6 = "SetThreadContext"

        // Memory allocation
        $alloc1 = "VirtualAllocEx"
        $alloc2 = "WriteProcessMemory"
        $alloc3 = "NtAllocateVirtualMemory"
        $alloc4 = "NtWriteVirtualMemory"

        // Process hollowing
        $hollow1 = "NtUnmapViewOfSection"
        $hollow2 = "ZwUnmapViewOfSection"
        $hollow3 = "CreateProcess.*SUSPENDED"

        // Atom bombing
        $atom1 = "GlobalAddAtom"
        $atom2 = "NtQueueApcThread"

        // Early bird
        $early1 = "CREATE_SUSPENDED"
        $early2 = "ResumeThread"

    condition:
        (any of ($mcp*) and any of ($inject*)) or
        (any of ($inject*) and all of ($alloc1, $alloc2, $alloc3, $alloc4)) or
        (all of ($hollow*)) or
        (all of ($atom*)) or
        (all of ($early*) and any of ($inject*))
}

rule APT_MCP_Persistence_Registry_Enhanced
{
    meta:
        description = "Enhanced registry persistence detection for MCP"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        // MCP persistence
        $mcp1 = "mcp_server_autostart"
        $mcp2 = /persist.*mcp.*registry/
        $mcp3 = "mcp_tool_persistence"

        // Registry keys
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "SOFTWARE\\Classes\\CLSID" nocase
        $reg4 = "SOFTWARE\\Classes\\Folder\\shell\\open\\command" nocase
        $reg5 = "SYSTEM\\CurrentControlSet\\Services" nocase
        $reg6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase

        // Registry commands
        $cmd1 = "reg add" nocase
        $cmd2 = "New-ItemProperty" nocase
        $cmd3 = "RegSetValueEx"
        $cmd4 = "[Microsoft.Win32.Registry]"

        // Suspicious values
        $value1 = /REG_SZ.*cmd\.exe/
        $value2 = /REG_SZ.*powershell/
        $value3 = /REG_SZ.*mshta/
        $value4 = /REG_SZ.*wscript/

    condition:
        (any of ($mcp*) and any of ($reg*)) or
        (any of ($reg*) and any of ($cmd*) and any of ($value*)) or
        (2 of ($reg*) and any of ($cmd*))
}

rule APT_MCP_Data_Staging_Advanced
{
    meta:
        description = "Advanced data staging detection for MCP exfiltration"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        // MCP data staging
        $mcp1 = "stage_mcp_data"
        $mcp2 = /collect.*mcp.*conversation/
        $mcp3 = "mcp_data_archive"

        // Archive creation
        $archive1 = "7z.exe a -p" nocase
        $archive2 = "rar.exe a -hp" nocase
        $archive3 = "zip -e" nocase
        $archive4 = "tar -czf"
        $archive5 = "Compress-Archive"

        // Staging locations
        $stage1 = "\\AppData\\Local\\Temp\\" nocase
        $stage2 = "\\ProgramData\\" nocase
        $stage3 = "$env:TEMP" nocase
        $stage4 = "\\Users\\Public\\"
        $stage5 = "%USERPROFILE%\\AppData"

        // Collection commands
        $collect1 = "Get-ChildItem -Recurse" nocase
        $collect2 = "Copy-Item -Recurse" nocase
        $collect3 = "xcopy /s"
        $collect4 = "robocopy"

        // File patterns
        $files1 = "*.doc*"
        $files2 = "*.xls*"
        $files3 = "*.pdf"
        $files4 = "*.mcp"

    condition:
        (any of ($mcp*) and any of ($archive*)) or
        (any of ($archive*) and any of ($stage*) and any of ($collect*)) or
        (any of ($collect*) and any of ($files*) and any of ($stage*))
}

rule APT_MCP_Advanced_C2_Communication
{
    meta:
        description = "Advanced C2 communication patterns for MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP C2 patterns
        $mcp1 = "mcp_c2_beacon"
        $mcp2 = /command.*control.*mcp/
        $mcp3 = "mcp_bot_communication"

        // Domain fronting
        $front1 = "Host: "
        $front2 = "cloudfront.net"
        $front3 = "azureedge.net"
        $front4 = "akamaihd.net"

        // DNS tunneling
        $dns1 = "dnscat"
        $dns2 = "iodine"
        $dns3 = /[a-f0-9]{32}\.[a-z]+\.com/

        // Custom protocols
        $proto1 = "JARM"
        $proto2 = "JA3"
        $proto3 = "custom_tls"

        // Encrypted channels
        $enc1 = "RC4"
        $enc2 = "ChaCha20"
        $enc3 = "AES_CTR"

        // Jitter/sleep
        $jitter1 = /jitter.*[0-9]+/
        $jitter2 = /sleep.*random/
        $jitter3 = "beacon_interval"

    condition:
        (any of ($mcp*) and any of ($front*, $dns*)) or
        (any of ($front*) and any of ($proto*)) or
        (any of ($enc*) and any of ($jitter*)) or
        (2 of ($dns*))
}