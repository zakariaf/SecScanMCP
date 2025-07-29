/*
rules/yara/apt_detection.yar
YARA rules for detecting Advanced Persistent Threats (APTs)
*/

rule APT_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"
        reference = "https://attack.mitre.org/software/S0154/"

    strings:
        $beacon1 = { 4D 5A 41 52 55 48 89 E5 }  // MZ header variant
        $beacon2 = { 48 83 EC 28 48 83 E4 F0 }  // Stack alignment

        $config1 = "%%PLACEHOLDER%%"
        $config2 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

        $api1 = "VirtualAllocExNuma"
        $api2 = "FlsAlloc"

        $sleep1 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA }

    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4152) and
        (any of ($beacon*) or all of ($api*)) and
        any of ($config*)
}

rule APT_Lazarus_Malware
{
    meta:
        description = "Detects Lazarus Group malware patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"
        reference = "https://attack.mitre.org/groups/G0032/"

    strings:
        $str1 = "Wingbird"
        $str2 = "FAKEREAN"
        $str3 = "Manuscrypt"

        $mutex1 = "FwtSqmSession106829323_S-1-5-20"
        $mutex2 = "Global\\MTX_"

        $pdb1 = "z:\\build\\" nocase
        $pdb2 = "c:\\users\\user\\documents\\" nocase

        $func1 = { 55 8B EC 83 EC 14 53 56 57 6A 00 }

    condition:
        2 of ($str*) or
        any of ($mutex*) or
        (any of ($pdb*) and $func1)
}

rule APT_Empire_PowerShell
{
    meta:
        description = "Detects Empire PowerShell framework"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $empire1 = "Invoke-Empire" nocase
        $empire2 = "Get-SystemDNSServer" nocase
        $empire3 = "Invoke-Shellcode" nocase

        $b64_1 = "FromBase64String" nocase
        $b64_2 = "ToBase64String" nocase

        $download1 = "DownloadString" nocase
        $download2 = "DownloadData" nocase

        $obf1 = { 24 [1-3] 3D 5B 43 68 61 72 5D }  // $x=[char]

    condition:
        any of ($empire*) or
        (all of ($b64_*) and any of ($download*)) or
        $obf1
}

rule APT_Metasploit_Payload
{
    meta:
        description = "Detects Metasploit payload patterns"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $meterpreter1 = "metsrv.dll"
        $meterpreter2 = "METERPRETER"

        $shellcode1 = { FC E8 ?? 00 00 00 }  // Common shellcode start
        $shellcode2 = { FC 48 83 E4 F0 }      // x64 shellcode start

        $api1 = "ReflectiveLoader"
        $api2 = "Init1"

        $uuid = { 92 BA 7E 0C DF FD 42 4C AA 6C F1 A9 8B 52 A4 FA }

    condition:
        any of ($meterpreter*) or
        (any of ($shellcode*) and any of ($api*)) or
        $uuid
}

rule APT_Mimikatz_Credential_Theft
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $str1 = "sekurlsa::logonpasswords" nocase
        $str2 = "privilege::debug" nocase
        $str3 = "token::elevate" nocase

        $kiwi1 = "mimidrv.sys"
        $kiwi2 = "mimikatz"
        $kiwi3 = "gentilkiwi"

        $func1 = "kuhl_m_sekurlsa_msv1_0_pth"
        $func2 = "kuhl_m_sekurlsa_enum"

    condition:
        2 of ($str*) or
        2 of ($kiwi*) or
        any of ($func*)
}

rule APT_Living_Off_The_Land
{
    meta:
        description = "Detects Living off the Land techniques"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $lolbas1 = "certutil -urlcache -split -f" nocase
        $lolbas2 = "bitsadmin /transfer" nocase
        $lolbas3 = "regsvr32 /s /u /i:" nocase
        $lolbas4 = "mshta http" nocase
        $lolbas5 = "rundll32 javascript:" nocase

        $wmi1 = "wmic process call create" nocase
        $wmi2 = "wmic /node:" nocase

        $ps1 = "powershell -enc" nocase
        $ps2 = "powershell -nop -w hidden" nocase

    condition:
        2 of ($lolbas*) or
        any of ($wmi*) or
        any of ($ps*)
}

rule APT_Process_Injection
{
    meta:
        description = "Detects process injection techniques"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $inject1 = "CreateRemoteThread"
        $inject2 = "SetWindowsHookEx"
        $inject3 = "QueueUserAPC"
        $inject4 = "RtlCreateUserThread"

        $alloc1 = "VirtualAllocEx"
        $alloc2 = "WriteProcessMemory"

        $hollow1 = "NtUnmapViewOfSection"
        $hollow2 = "SetThreadContext"

    condition:
        (any of ($inject*) and all of ($alloc*)) or
        all of ($hollow*)
}

rule APT_Persistence_Registry
{
    meta:
        description = "Detects registry persistence mechanisms"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "SOFTWARE\\Classes\\CLSID" nocase
        $reg4 = "SOFTWARE\\Classes\\Folder\\shell\\open\\command" nocase

        $cmd1 = "reg add" nocase
        $cmd2 = "New-ItemProperty" nocase

        $value1 = /REG_SZ.*cmd\.exe/
        $value2 = /REG_SZ.*powershell/

    condition:
        (any of ($reg*) and any of ($cmd*)) or
        (any of ($reg*) and any of ($value*))
}

rule APT_Data_Staging
{
    meta:
        description = "Detects data staging for exfiltration"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $archive1 = "7z.exe a -p" nocase
        $archive2 = "rar.exe a -hp" nocase
        $archive3 = "zip -e" nocase

        $stage1 = "\\AppData\\Local\\Temp\\" nocase
        $stage2 = "\\ProgramData\\" nocase
        $stage3 = "$env:TEMP" nocase

        $collect1 = "Get-ChildItem -Recurse" nocase
        $collect2 = "Copy-Item -Recurse" nocase

    condition:
        any of ($archive*) and any of ($stage*) or
        all of ($collect*) and any of ($stage*)
}

rule APT_Network_Reconnaissance
{
    meta:
        description = "Detects network reconnaissance activities"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "apt"

    strings:
        $recon1 = "net view /domain" nocase
        $recon2 = "net group \"domain admins\" /domain" nocase
        $recon3 = "nltest /domain_trusts" nocase
        $recon4 = "Get-ADComputer -Filter *" nocase

        $scan1 = "nmap -sS" nocase
        $scan2 = "masscan -p" nocase

        $enum1 = "Get-NetComputer" nocase
        $enum2 = "Get-NetUser" nocase

    condition:
        2 of ($recon*) or
        any of ($scan*) or
        all of ($enum*)
}

rule APT_Defense_Evasion
{
    meta:
        description = "Detects defense evasion techniques"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $amsi1 = "AmsiScanBuffer"
        $amsi2 = "amsi.dll"
        $amsi3 = { 41 6D 73 69 }  // Amsi

        $etw1 = "EtwEventWrite"
        $etw2 = "EtwpCreateEtwThread"

        $defender1 = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $defender2 = "sc stop WinDefend" nocase

        $patch1 = { B8 57 00 07 80 C3 }  // Common AMSI patch

    condition:
        (2 of ($amsi*) and $patch1) or
        any of ($etw*) or
        any of ($defender*)
}