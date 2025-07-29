/*
rules/yara/backdoor_detection.yar
YARA rules for detecting backdoors and remote access tools
*/

rule Backdoor_Python_Reverse_Shell
{
    meta:
        description = "Detects Python reverse shell backdoors"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $import1 = "import socket" nocase
        $import2 = "import subprocess" nocase
        $import3 = "import os" nocase

        $shell1 = "socket.socket(socket.AF_INET" nocase
        $shell2 = ".connect((" nocase
        $shell3 = "subprocess.call([" nocase
        $shell4 = "os.dup2(" nocase

        $cmd1 = "/bin/sh" nocase
        $cmd2 = "cmd.exe" nocase
        $cmd3 = "/bin/bash" nocase

    condition:
        (#import1 + #import2 + #import3 >= 2) and
        (#shell1 + #shell2 >= 2) and
        any of ($cmd*)
}

rule Backdoor_Web_Shell
{
    meta:
        description = "Detects web shell backdoors"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "webshell"

    strings:
        $php1 = "<?php @eval($_POST[" nocase
        $php2 = "<?php @system($_GET[" nocase
        $php3 = "<?php @assert($_REQUEST[" nocase

        $jsp1 = "Runtime.getRuntime().exec(request.getParameter" nocase
        $jsp2 = "<%@page import=\"java.io.*\"%>" nocase

        $aspx1 = "eval(Request.Item[" nocase
        $aspx2 = "ProcessStartInfo" nocase

        $func1 = "shell_exec" nocase
        $func2 = "passthru" nocase
        $func3 = "exec(" nocase
        $func4 = "system(" nocase

        $obf1 = /[a-zA-Z0-9+\/]{100,}/ // Long base64 string

    condition:
        any of ($php*) or
        all of ($jsp*) or
        all of ($aspx*) or
        (2 of ($func*) and $obf1)
}

rule Backdoor_SSH_Key_Injection
{
    meta:
        description = "Detects SSH key injection for backdoor access"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $ssh1 = "~/.ssh/authorized_keys" nocase
        $ssh2 = "/home/*/.ssh/authorized_keys" nocase
        $ssh3 = "StrictHostKeyChecking=no" nocase

        $key1 = /ssh-rsa [A-Za-z0-9+\/]{200,}/
        $key2 = /ssh-ed25519 [A-Za-z0-9+\/]{50,}/

        $inject1 = "echo" nocase
        $inject2 = "printf" nocase
        $inject3 = ">>"

    condition:
        any of ($ssh*) and
        any of ($key*) and
        any of ($inject*)
}

rule Backdoor_Bind_Shell
{
    meta:
        description = "Detects bind shell backdoors"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $bind1 = "bind(" nocase
        $bind2 = "listen(" nocase
        $bind3 = "accept(" nocase

        $port1 = ":4444" nocase
        $port2 = ":1337" nocase
        $port3 = ":31337" nocase
        $port4 = ":8888" nocase

        $shell1 = "sh -i" nocase
        $shell2 = "/bin/bash" nocase
        $shell3 = "cmd.exe /c" nocase

    condition:
        all of ($bind*) and
        (any of ($port*) or any of ($shell*))
}

rule Backdoor_Hidden_Service
{
    meta:
        description = "Detects hidden service backdoors"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $service1 = "sc create" nocase
        $service2 = "New-Service" nocase
        $service3 = "systemctl enable" nocase

        $hide1 = "Hidden" nocase
        $hide2 = "SYSTEM" nocase
        $hide3 = "svchost.exe -k" nocase

        $persist1 = "auto_start" nocase
        $persist2 = "StartupType Automatic" nocase
        $persist3 = "enabled" nocase

    condition:
        any of ($service*) and
        any of ($hide*) and
        any of ($persist*)
}

rule Backdoor_RAT_Generic
{
    meta:
        description = "Detects generic Remote Access Tool patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $rat1 = "keylogger" nocase
        $rat2 = "screenshot" nocase
        $rat3 = "webcam" nocase
        $rat4 = "microphone" nocase

        $comm1 = "command_handler" nocase
        $comm2 = "execute_command" nocase
        $comm3 = "recv_command" nocase

        $exfil1 = "upload_file" nocase
        $exfil2 = "download_file" nocase
        $exfil3 = "send_data" nocase

    condition:
        2 of ($rat*) or
        (any of ($comm*) and any of ($exfil*))
}

rule Backdoor_Cryptocurrency_Stealer
{
    meta:
        description = "Detects cryptocurrency wallet stealers"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "Electrum" nocase
        $wallet3 = "Bitcoin" nocase
        $wallet4 = "Ethereum" nocase

        $path1 = "\\AppData\\Roaming\\Bitcoin" nocase
        $path2 = "\\AppData\\Roaming\\Ethereum" nocase

        $steal1 = "copy" nocase
        $steal2 = "upload" nocase
        $steal3 = "exfiltrate" nocase

    condition:
        any of ($wallet*) and
        (any of ($path*) or any of ($steal*))
}

rule Backdoor_Fileless_Malware
{
    meta:
        description = "Detects fileless malware techniques"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $mem1 = "VirtualAlloc" nocase
        $mem2 = "RtlMoveMemory" nocase
        $mem3 = "CreateThread" nocase

        $ps1 = "IEX" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "[System.Reflection.Assembly]::Load" nocase

        $wmi1 = "Win32_Process" nocase
        $wmi2 = "Create(" nocase

    condition:
        all of ($mem*) or
        (2 of ($ps*) and any of ($wmi*))
}

rule Backdoor_DNS_Tunnel
{
    meta:
        description = "Detects DNS tunneling backdoors"
        author = "MCP Security Scanner"
        severity = "high"
        category = "backdoor"

    strings:
        $dns1 = "dnslib" nocase
        $dns2 = "scapy" nocase
        $dns3 = "dig" nocase
        $dns4 = "nslookup" nocase

        $tunnel1 = /[a-f0-9]{32,}\.evil\.com/
        $tunnel2 = "TXT record" nocase
        $tunnel3 = "base32" nocase
        $tunnel4 = "base64" nocase

    condition:
        any of ($dns*) and 2 of ($tunnel*)
}

rule Backdoor_Container_Escape
{
    meta:
        description = "Detects container escape attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $docker1 = "/var/run/docker.sock" nocase
        $docker2 = "docker.sock" nocase

        $escape1 = "nsenter" nocase
        $escape2 = "--privileged" nocase
        $escape3 = "CAP_SYS_ADMIN" nocase

        $mount1 = "mount" nocase
        $mount2 = "/proc/self/exe" nocase

    condition:
        any of ($docker*) and
        (any of ($escape*) or all of ($mount*))
}