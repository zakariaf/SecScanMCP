/*
YARA rules for detecting data exfiltration patterns in MCP
*/

import "math"

rule MCP_Data_Exfiltration_Patterns
{
    meta:
        description = "Detects common data exfiltration patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // Archive creation
        $archive1 = /tar\s+-czf.*\.(tar\.gz|tgz)/
        $archive2 = /zip\s+-r.*\.zip/
        $archive3 = /7z\s+a.*\.7z/
        $archive4 = "ZipFile("
        $archive5 = "tarfile.open("

        // Encoding methods
        $encode1 = "base64.b64encode"
        $encode2 = "btoa("
        $encode3 = ".toString('base64')"
        $encode4 = "Convert.ToBase64String"
        $encode5 = "hexlify("

        // Upload patterns
        $upload1 = /curl\s+-X\s*POST.*-F/
        $upload2 = /wget\s+--post-file/
        $upload3 = /fetch.*method:\s*['"]POST/
        $upload4 = /axios\.post.*data:/
        $upload5 = "requests.post("

        // Exfil domains
        $domain1 = /https?:\/\/[a-z0-9]{16,}\.(tk|ml|ga|cf)/
        $domain2 = "pastebin.com"
        $domain3 = "transfer.sh"
        $domain4 = "file.io"
        $domain5 = "anonfiles.com"

    condition:
        (any of ($archive*) and any of ($encode*) and any of ($upload*)) or
        (any of ($encode*) and any of ($domain*)) or
        (2 of ($archive*) and any of ($domain*))
}

rule MCP_Sensitive_Data_Collection
{
    meta:
        description = "Detects collection of sensitive data for exfiltration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // SSH keys
        $ssh1 = "~/.ssh/id_rsa"
        $ssh2 = "~/.ssh/id_ed25519"
        $ssh3 = "~/.ssh/authorized_keys"
        $ssh4 = ".ssh/known_hosts"

        // Cloud credentials
        $cloud1 = "~/.aws/credentials"
        $cloud2 = "~/.azure/accessTokens.json"
        $cloud3 = "~/.config/gcloud"
        $cloud4 = "~/.docker/config.json"

        // Password files
        $pwd1 = "/etc/passwd"
        $pwd2 = "/etc/shadow"
        $pwd3 = "~/.bash_history"
        $pwd4 = "~/.zsh_history"

        // Application secrets
        $app1 = ".env"
        $app2 = "config.json"
        $app3 = "secrets.yml"
        $app4 = "database.yml"

        // Browser data
        $browser1 = "Login Data"
        $browser2 = "Cookies"
        $browser3 = "Web Data"
        $browser4 = "History"

    condition:
        3 of them or
        (any of ($ssh*) and any of ($cloud*)) or
        (any of ($pwd*) and /read|cat|type|get-content/)
}

rule MCP_Covert_Channel_Exfiltration
{
    meta:
        description = "Detects covert channel data exfiltration"
        author = "MCP Security Scanner"
        severity = "high"
        category = "exfiltration"

    strings:
        // DNS exfiltration
        $dns1 = /nslookup.*\..*\./
        $dns2 = /dig\s+.*\./
        $dns3 = "dns.resolve"
        $dns4 = /[a-f0-9]{32}\.[a-z]+\.com/

        // ICMP tunneling
        $icmp1 = "ping -p"
        $icmp2 = "ping -c"
        $icmp3 = "IcmpSendEcho"

        // Timing channels
        $timing1 = /sleep\s*\(\s*ord\(/
        $timing2 = /delay.*charCodeAt/
        $timing3 = "time.sleep(data"

        // Steganography
        $steg1 = "PIL.Image"
        $steg2 = "jimp"
        $steg3 = "stegano"
        $steg4 = "LSB"

    condition:
        any of ($dns*) or
        any of ($icmp*) or
        any of ($timing*) or
        any of ($steg*)
}

rule MCP_Database_Dump_Exfiltration
{
    meta:
        description = "Detects database dumping for exfiltration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // Database dump commands
        $dump1 = "mysqldump"
        $dump2 = "pg_dump"
        $dump3 = "mongodump"
        $dump4 = "redis-cli --rdb"
        $dump5 = "sqlite3 .dump"

        // Export patterns
        $export1 = /SELECT.*INTO\s+OUTFILE/
        $export2 = "COPY.*TO"
        $export3 = ".backup"
        $export4 = "export_data"

        // Compression
        $compress1 = "| gzip"
        $compress2 = "| bzip2"
        $compress3 = "| xz"

        // Output redirection
        $output1 = "> dump.sql"
        $output2 = ">> backup"
        $output3 = "| curl"

    condition:
        (any of ($dump*) and any of ($compress*, $output*)) or
        (any of ($export*) and any of ($compress*, $output*))
}

rule MCP_Conversation_History_Theft
{
    meta:
        description = "Detects MCP conversation history exfiltration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // MCP specific patterns
        $mcp1 = "conversation_history"
        $mcp2 = "message_store"
        $mcp3 = "context_memory"
        $mcp4 = "tool_interactions"

        // Serialization
        $serial1 = "JSON.stringify(messages"
        $serial2 = "pickle.dumps(history"
        $serial3 = "serialize(conversation"
        $serial4 = "export_context"

        // Bulk operations
        $bulk1 = /messages\.map.*join/
        $bulk2 = "getAllMessages()"
        $bulk3 = "dumpConversation()"
        $bulk4 = /for.*message.*in.*history/

        // Destinations
        $dest1 = "webhook.site"
        $dest2 = "requestbin"
        $dest3 = "pipedream"
        $dest4 = /attacker@.*\.com/

    condition:
        (any of ($mcp*) and any of ($serial*)) or
        (any of ($bulk*) and any of ($dest*)) or
        (2 of ($mcp*) and any of ($dest*))
}

rule MCP_Screenshot_Capture
{
    meta:
        description = "Detects screenshot capture for data theft"
        author = "MCP Security Scanner"
        severity = "high"
        category = "exfiltration"

    strings:
        // Screenshot libraries
        $lib1 = "pyautogui"
        $lib2 = "puppeteer"
        $lib3 = "selenium"
        $lib4 = "playwright"

        // Screenshot methods
        $method1 = ".screenshot("
        $method2 = "takeScreenshot"
        $method3 = "captureScreen"
        $method4 = "save_screenshot"

        // Image processing
        $img1 = "getScreenshot().save"
        $img2 = "toDataURL('image/"
        $img3 = "Canvas.toBlob"

        // Upload after capture
        $upload1 = /screenshot.*upload/
        $upload2 = /capture.*post/
        $upload3 = /screen.*send/

    condition:
        (any of ($lib*) and any of ($method*)) or
        (any of ($img*) and any of ($upload*))
}

rule MCP_Clipboard_Monitoring
{
    meta:
        description = "Detects clipboard monitoring for data theft"
        author = "MCP Security Scanner"
        severity = "high"
        category = "exfiltration"

    strings:
        // Clipboard access
        $clip1 = "pyperclip"
        $clip2 = "clipboard"
        $clip3 = "navigator.clipboard"
        $clip4 = "tkinter.clipboard"

        // Monitoring patterns
        $monitor1 = /while.*clipboard/
        $monitor2 = "setInterval.*clipboard"
        $monitor3 = "clipboard.on('change'"
        $monitor4 = /loop.*getClipboard/

        // Data patterns
        $data1 = /password.*clipboard/
        $data2 = /private.*key.*clip/
        $data3 = /credit.*card.*clipboard/

    condition:
        (any of ($clip*) and any of ($monitor*)) or
        (any of ($clip*) and any of ($data*))
}

rule MCP_Network_Traffic_Interception
{
    meta:
        description = "Detects network traffic interception for exfiltration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // Packet capture
        $pcap1 = "pcap"
        $pcap2 = "tcpdump"
        $pcap3 = "wireshark"
        $pcap4 = "tshark"

        // MITM patterns
        $mitm1 = "mitmproxy"
        $mitm2 = "SSLstrip"
        $mitm3 = "ettercap"
        $mitm4 = "arpspoof"

        // Traffic analysis
        $traffic1 = "packet.payload"
        $traffic2 = "http.request"
        $traffic3 = "tcp.data"
        $traffic4 = "sniff("

    condition:
        any of ($pcap*) or
        any of ($mitm*) or
        (any of ($traffic*) and /password|token|cookie/)
}

rule MCP_Staged_Exfiltration
{
    meta:
        description = "Detects staged data exfiltration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "exfiltration"

    strings:
        // Staging directories
        $stage1 = "/tmp/staging"
        $stage2 = "/var/tmp/.hidden"
        $stage3 = "$env:TEMP\\data"
        $stage4 = "AppData\\Local\\Temp"

        // Collection scripts
        $collect1 = /find.*-name.*\.(txt|pdf|doc|xls)/
        $collect2 = /Get-ChildItem.*-Recurse/
        $collect3 = "glob.glob('**/*"
        $collect4 = "os.walk("

        // Chunking
        $chunk1 = /split\s+-b\s*[0-9]+[MK]/
        $chunk2 = "chunk_size"
        $chunk3 = /for.*chunk.*in.*chunks/

        // Scheduled exfil
        $sched1 = "crontab"
        $sched2 = "schtasks"
        $sched3 = "at "
        $sched4 = "systemd.timer"

    condition:
        (any of ($stage*) and any of ($collect*)) or
        (any of ($chunk*) and any of ($sched*)) or
        (any of ($stage*) and any of ($chunk*))
}

rule MCP_Anti_Analysis_Exfiltration
{
    meta:
        description = "Detects anti-analysis techniques in exfiltration"
        author = "MCP Security Scanner"
        severity = "high"
        category = "exfiltration"

    strings:
        // VM detection
        $vm1 = "VMware"
        $vm2 = "VirtualBox"
        $vm3 = "QEMU"
        $vm4 = "Hyper-V"

        // Debugger detection
        $debug1 = "IsDebuggerPresent"
        $debug2 = "ptrace"
        $debug3 = "__debugbreak"
        $debug4 = "/proc/self/status"

        // Sandbox evasion
        $sandbox1 = "sleep(300"
        $sandbox2 = "mouse_event"
        $sandbox3 = "get_tick_count"

        // Encryption before exfil
        $encrypt1 = "AES.encrypt"
        $encrypt2 = "RSA.encrypt"
        $encrypt3 = "gpg -e"
        $encrypt4 = "openssl enc"

    condition:
        (any of ($vm*, $debug*, $sandbox*) and any of ($encrypt*)) or
        (2 of ($vm*, $debug*, $sandbox*))
}