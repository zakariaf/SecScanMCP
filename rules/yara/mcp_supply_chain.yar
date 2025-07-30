/*
YARA rules for detecting supply chain attacks targeting MCP ecosystem
*/

import "hash"

rule MCP_Supply_Chain_Typosquatting
{
    meta:
        description = "Detects typosquatting attacks on MCP packages"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Common typosquatting patterns
        $typo1 = "mcp-sever" nocase
        $typo2 = "mcp-clent" nocase
        $typo3 = "mcp-servr" nocase
        $typo4 = "mcp-serrver" nocase
        $typo5 = "mcpserver" nocase
        $typo6 = "mpc-server" nocase
        $typo7 = "ncp-server" nocase
        $typo8 = "mcp_server" nocase

        // FastMCP typos
        $fast1 = "fastmpc" nocase
        $fast2 = "fast-mcp" nocase
        $fast3 = "fastmcp-server" nocase
        $fast4 = "fastncp" nocase

        // Anthropic typos
        $anthro1 = "antropic" nocase
        $anthro2 = "anthropik" nocase
        $anthro3 = "antrhopic" nocase
        $anthro4 = "anthropic-mcp" nocase

        // Package indicators
        $pkg1 = "package.json"
        $pkg2 = "setup.py"
        $pkg3 = "pyproject.toml"
        $pkg4 = "Cargo.toml"

    condition:
        any of ($pkg*) and (
            any of ($typo*) or
            any of ($fast*) or
            any of ($anthro*)
        )
}

rule MCP_Dependency_Confusion
{
    meta:
        description = "Detects dependency confusion attacks"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Internal package patterns
        $internal1 = /@corp-mcp\//
        $internal2 = /@internal\/mcp/
        $internal3 = /@private\/.*mcp/
        $internal4 = /company-mcp-/

        // Version manipulation
        $version1 = /"version":\s*"99\.99\.99"/
        $version2 = /"version":\s*"[0-9]{4,}\.0\.0"/
        $version3 = /"version":\s*"999\./

        // Malicious registry
        $registry1 = /registry\.npmjs\.com/
        $registry2 = /registry\s*=\s*https?:\/\/[a-z0-9]+\.(tk|ml|ga)/
        $registry3 = /"publishConfig":\s*\{[^}]*"registry"/

        // Preinstall hooks
        $hook1 = /"preinstall":\s*"[^"]*curl/
        $hook2 = /"postinstall":\s*"[^"]*wget/
        $hook3 = /"install":\s*"[^"]*node\s+-e/

    condition:
        (any of ($internal*) and any of ($version*)) or
        (any of ($registry*) and any of ($hook*)) or
        (2 of ($version*) and any of ($hook*))
}

rule MCP_Malicious_Package_Indicators
{
    meta:
        description = "Detects indicators of malicious MCP packages"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Suspicious domains
        $domain1 = /[a-z0-9]{16,}\.(tk|ml|ga|cf)/
        $domain2 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $domain3 = /pastebin\.com\/raw/
        $domain4 = /ngrok\.io/
        $domain5 = /webhook\.site/

        // Obfuscation
        $obfusc1 = /eval\s*\(\s*atob/
        $obfusc2 = /Function\s*\(\s*atob/
        $obfusc3 = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/
        $obfusc4 = /String\.fromCharCode\([0-9,\s]{100,}\)/

        // Data theft
        $steal1 = /process\.env\.[A-Z_]+/
        $steal2 = /os\.homedir\(\)/
        $steal3 = /fs\.readFileSync.*ssh/
        $steal4 = /child_process.*cat.*\/etc\/passwd/

        // Backdoor installation
        $backdoor1 = /require\s*\(\s*['"]child_process['"]\s*\)\.exec/
        $backdoor2 = /net\.createServer/
        $backdoor3 = /process\.binding\s*\(\s*['"]spawn_sync/

    condition:
        (any of ($domain*) and any of ($obfusc*)) or
        (any of ($steal*) and any of ($backdoor*)) or
        (2 of ($obfusc*) and any of ($steal*))
}

rule MCP_Package_Hijacking
{
    meta:
        description = "Detects package hijacking attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Maintainer changes
        $maint1 = /"maintainers":\s*\[[^\]]*\]/
        $maint2 = /"author":\s*\{[^}]*"email":\s*"[^"]+@(gmail|protonmail|tutanota)\.com"/
        $maint3 = /"contributors":\s*\[\s*\]/

        // Sudden behavior changes
        $change1 = /\/\*\s*LEGACY CODE.*\*\//
        $change2 = /\/\/\s*TODO:\s*remove\s+after/
        $change3 = /DEPRECATED.*use\s+instead/

        // New dependencies
        $newdep1 = /"dependencies":\s*\{[^}]*"request":/
        $newdep2 = /"dependencies":\s*\{[^}]*"node-fetch":/
        $newdep3 = /"dependencies":\s*\{[^}]*"axios":/

        // Mining indicators
        $mining1 = "stratum+tcp://"
        $mining2 = "coinhive"
        $mining3 = /worker\.postMessage.*hashrate/

    condition:
        (any of ($change*) and any of ($newdep*)) or
        (any of ($maint*) and any of ($mining*)) or
        (filesize > 1MB and any of ($mining*))
}

rule MCP_Build_Process_Injection
{
    meta:
        description = "Detects build process injection attacks"
        author = "MCP Security Scanner"
        severity = "high"
        category = "supply_chain"

    strings:
        // Build script manipulation
        $build1 = /"build":\s*"[^"]*&&[^"]*"/
        $build2 = /"prebuild":\s*"[^"]*curl/
        $build3 = /"postbuild":\s*"[^"]*eval/

        // GitHub Actions manipulation
        $gha1 = ".github/workflows"
        $gha2 = "on: [push, pull_request]"
        $gha3 = /uses:\s*[^@]+@[a-f0-9]{7}/
        $gha4 = "GITHUB_TOKEN"

        // CI/CD secrets theft
        $secret1 = "${{ secrets."
        $secret2 = "env.NPM_TOKEN"
        $secret3 = "PYPI_PASSWORD"
        $secret4 = "DOCKER_PASSWORD"

    condition:
        (any of ($build*) and any of ($secret*)) or
        ($gha1 and any of ($gha2, $gha3, $gha4) and any of ($secret*))
}

rule MCP_Protestware_Detection
{
    meta:
        description = "Detects protestware in MCP packages"
        author = "MCP Security Scanner"
        severity = "medium"
        category = "supply_chain"

    strings:
        // Geolocation checks
        $geo1 = /process\.env\.LANG.*ru_RU/
        $geo2 = /timezone.*Moscow/
        $geo3 = /country.*===.*["']CN["']/

        // Destructive behavior
        $destruct1 = /fs\.rmSync.*recursive:\s*true/
        $destruct2 = /rimraf\.sync\(/
        $destruct3 = /exec.*rm\s+-rf/

        // Conditional logic
        $cond1 = /if\s*\(.*isRussian\(/
        $cond2 = /checkCountry\s*\(/
        $cond3 = /Date\.now\(\)\s*>\s*[0-9]{13}/

        // Messages
        $msg1 = /console\.log.*("peace"|"stop war"|"freedom")/i
        $msg2 = "WITH_LOVE_FROM_AMERICA"

    condition:
        (any of ($geo*) and any of ($destruct*)) or
        (any of ($cond*) and any of ($msg*))
}

rule MCP_NPM_Security_Audit_Bypass
{
    meta:
        description = "Detects attempts to bypass npm security audits"
        author = "MCP Security Scanner"
        severity = "high"
        category = "supply_chain"

    strings:
        // Audit bypass
        $audit1 = "npm audit fix --force"
        $audit2 = "--no-audit"
        $audit3 = "audit-level=none"

        // Lockfile manipulation
        $lock1 = "package-lock.json"
        $lock2 = /"resolved":\s*"[^"]*\.(tk|ml|ga)/
        $lock3 = /"integrity":\s*"sha[0-9]+-[A-Za-z0-9+\/]+=="/

        // Version pinning removal
        $pin1 = /"\^[0-9]+\.[0-9]+\.[0-9]+"/
        $pin2 = /"~[0-9]+\.[0-9]+\.[0-9]+"/
        $pin3 = /"[0-9]+\.[0-9]+\.[0-9]+"/

    condition:
        (any of ($audit*) and $lock1) or
        ($lock1 and any of ($lock2, $lock3)) or
        ($lock1 and #pin1 < 3 and #pin2 < 3 and #pin3 < 3)
}

rule MCP_Malicious_Webhook_Patterns
{
    meta:
        description = "Detects malicious webhook patterns in supply chain"
        author = "MCP Security Scanner"
        severity = "high"
        category = "supply_chain"

    strings:
        // Webhook endpoints
        $webhook1 = /discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/
        $webhook2 = /hooks\.slack\.com\/services/
        $webhook3 = /webhook\.site\/[a-f0-9-]+/
        $webhook4 = /requestbin\.(com|net)\/[a-z0-9]+/

        // Data collection
        $collect1 = /JSON\.stringify\s*\(\s*process\.env\s*\)/
        $collect2 = "os.userInfo()"
        $collect3 = "os.hostname()"
        $collect4 = /glob\.sync.*\.(pem|key|crt)/

        // Exfiltration
        $exfil1 = /fetch.*method:\s*["']POST/
        $exfil2 = /axios\.post.*data:/
        $exfil3 = /https?:\/\/[^\/]+\/.*\?data=/

    condition:
        (any of ($webhook*) and any of ($collect*)) or
        (any of ($webhook*) and any of ($exfil*))
}

rule MCP_Container_Image_Backdoor
{
    meta:
        description = "Detects backdoors in MCP container images"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Dockerfile manipulation
        $docker1 = "FROM "
        $docker2 = /RUN\s+curl.*\|\s*sh/
        $docker3 = /RUN\s+wget.*\|\s*bash/
        $docker4 = "USER root"

        // Hidden layers
        $layer1 = /LABEL\s+[a-z]+="[^"]{200,}"/
        $layer2 = /ENV\s+[A-Z_]+="\\x/
        $layer3 = /ARG\s+[A-Z_]+=\$\(/

        // Reverse shell
        $shell1 = "nc -e /bin/sh"
        $shell2 = "bash -i >& /dev/tcp"
        $shell3 = "python -c 'import socket"

        // Persistence
        $persist1 = "ENTRYPOINT"
        $persist2 = "CMD [\"/bin/sh\""
        $persist3 = "crontab"

    condition:
        ($docker1 and any of ($docker2, $docker3)) or
        ($docker1 and any of ($layer*) and any of ($shell*)) or
        ($docker1 and $docker4 and any of ($persist*))
}

rule MCP_PyPI_Distribution_Attack
{
    meta:
        description = "Detects PyPI distribution attacks on MCP packages"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "supply_chain"

    strings:
        // Setup.py manipulation
        $setup1 = "setup.py"
        $setup2 = /setup\s*\(/
        $setup3 = "cmdclass"
        $setup4 = "install_requires"

        // Malicious commands
        $cmd1 = /os\.system\s*\(['"]/
        $cmd2 = /subprocess\.\w+\s*\(['"]/
        $cmd3 = "__import__('os').system"

        // Hidden imports
        $import1 = /__import__\s*\(\s*["']base64/
        $import2 = /__import__\s*\(\s*["']urllib/
        $import3 = /exec\s*\(\s*__import__/

        // Obfuscated strings
        $obf1 = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}/
        $obf2 = /chr\s*\(\s*[0-9]+\s*\)/
        $obf3 = /decode\s*\(\s*["']hex["']\s*\)/

    condition:
        ($setup1 and $setup2 and any of ($cmd*)) or
        ($setup3 and any of ($import*)) or
        ($setup4 and any of ($obf*))
}