/*
YARA rules for detecting Advanced Persistent Threats targeting MCP infrastructure
Focus: APT groups specifically targeting MCP servers and AI infrastructure
*/

import "pe"
import "math"

rule APT_MCP_Infrastructure_Targeting
{
    meta:
        description = "APT groups targeting MCP infrastructure"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP-specific reconnaissance
        $recon1 = "mcp_server_enumerate"
        $recon2 = /scan.*model.*context.*protocol/
        $recon3 = "find_mcp_instances"
        $recon4 = /claude.*desktop.*config/

        // AI infrastructure targeting
        $ai1 = "anthropic_api_key"
        $ai2 = "openai_token"
        $ai3 = /steal.*llm.*credentials/
        $ai4 = "ai_model_access"

        // Persistence in MCP context
        $persist1 = /mcp.*tool.*backdoor/
        $persist2 = "inject_into_mcp"
        $persist3 = /persistent.*ai.*agent/

    condition:
        any of ($recon*) and (any of ($ai*) or any of ($persist*))
}

rule APT_MCP_Supply_Chain_Attack
{
    meta:
        description = "APT supply chain attacks on MCP ecosystem"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // Package targeting
        $pkg1 = "@modelcontextprotocol/"
        $pkg2 = "fastmcp"
        $pkg3 = "mcp-server-"

        // APT signatures in packages
        $apt1 = { 4D 5A 90 00 03 00 00 00 }  // PE header in npm package
        $apt2 = "-----BEGIN RSA PRIVATE KEY-----"  // Leaked keys
        $apt3 = /\x00\x00\x00\x00[^\x00]{4}\x00\x00\x00\x00/  // Null padding

        // Command and control
        $c2_1 = /https?:\/\/[a-z0-9]{16,}\.(tk|ml|ga|cf)/
        $c2_2 = "stratum+tcp://"  // Cryptomining
        $c2_3 = /[a-f0-9]{32}\.[a-z]+\.com/  // DGA domains

        // Obfuscation
        $obf1 = { E8 ?? ?? ?? ?? }  // Call with offset
        $obf2 = /eval\s*\(\s*String\.fromCharCode/

    condition:
        any of ($pkg*) and (any of ($apt*) or any of ($c2*)) and any of ($obf*)
}

rule APT_MCP_Tool_Weaponization
{
    meta:
        description = "APT weaponization of MCP tools"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP tool context
        $tool1 = /"name":\s*"[^"]+_tool"/
        $tool2 = "execute_tool"
        $tool3 = "tool_response"

        // APT payloads
        $payload1 = { FC 48 83 E4 F0 E8 C8 00 00 00 }  // Metasploit
        $payload2 = { FC E8 ?? 00 00 00 }  // Shellcode
        $payload3 = "ReflectiveLoader"
        $payload4 = "meterpreter"

        // Lateral movement via MCP
        $lateral1 = "spread_via_mcp"
        $lateral2 = /infect.*other.*tools/
        $lateral3 = "cross_server_exec"

    condition:
        any of ($tool*) and any of ($payload*) and any of ($lateral*)
}

rule APT_MCP_Data_Staging
{
    meta:
        description = "APT data staging through MCP channels"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP data access
        $mcp1 = "conversation_history"
        $mcp2 = "tool_execution_log"
        $mcp3 = "mcp_context_dump"

        // Staging patterns
        $stage1 = /collect.*compress.*encrypt/
        $stage2 = "7z a -p"  // Password protected archive
        $stage3 = /tar.*gpg.*-c/  // Encrypted tar
        $stage4 = "create_data_bundle"

        // Exfiltration markers
        $exfil1 = "chunk_size = 1024"
        $exfil2 = /split\s+-b\s*[0-9]+k/
        $exfil3 = "use_dead_drop"

        // APT-specific indicators
        $apt1 = "operation_id"
        $apt2 = "campaign_marker"
        $apt3 = { 41 50 54 }  // "APT" marker

    condition:
        any of ($mcp*) and any of ($stage*) and (any of ($exfil*) or any of ($apt*))
}

rule APT_MCP_LivingOffTheLand
{
    meta:
        description = "APT using legitimate MCP features maliciously"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        // Legitimate MCP functions abused
        $legit1 = "list_tools"
        $legit2 = "get_prompt"
        $legit3 = "execute_tool"

        // LOTL patterns
        $lotl1 = /legitimate.*malicious.*purpose/
        $lotl2 = "hide_in_plain_sight"
        $lotl3 = /normal.*tool.*evil/

        // Data gathering via legitimate means
        $gather1 = /for.*tool.*in.*list_tools/
        $gather2 = "enumerate_all_prompts"
        $gather3 = "harvest_tool_descriptions"

        // Covert channels
        $covert1 = /description.*base64/
        $covert2 = "steganography_in_schema"
        $covert3 = /hidden.*in.*metadata/

    condition:
        all of ($legit*) and (any of ($lotl*) or any of ($gather*) or any of ($covert*))
}

rule APT_MCP_Persistence_Registry
{
    meta:
        description = "APT establishing persistence via MCP configuration"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // MCP config files
        $config1 = "mcp.json"
        $config2 = ".mcp.yaml"
        $config3 = "servers.json"

        // Persistence injection
        $persist1 = /"autostart":\s*true/
        $persist2 = /"startup_tools":\s*\[/
        $persist3 = /"persistent":\s*true/

        // Hidden configuration
        $hidden1 = /\x00[a-zA-Z]+server/  // Null byte hiding
        $hidden2 = /"\.hidden[^"]*":\s*\{/
        $hidden3 = { 2E 2E 2F 2E 2E 2F }  // Directory traversal

        // APT markers
        $apt1 = "implant_id"
        $apt2 = "beacon_config"
        $apt3 = /c2_[a-f0-9]{8}/

    condition:
        any of ($config*) and any of ($persist*) and (any of ($hidden*) or any of ($apt*))
}

rule APT_MCP_CloudProvider_Abuse
{
    meta:
        description = "APT abusing cloud MCP deployments"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        // Cloud contexts
        $cloud1 = "lambda_function"
        $cloud2 = "cloud_run"
        $cloud3 = "azure_functions"

        // MCP in cloud
        $mcp1 = "mcp_server_handler"
        $mcp2 = "serverless_mcp"
        $mcp3 = "cloud_tool_executor"

        // Abuse patterns
        $abuse1 = "infinite_loop"
        $abuse2 = "cryptomining_payload"
        $abuse3 = "resource_exhaustion"
        $abuse4 = /while.*true.*execute/

        // APT infrastructure
        $infra1 = "dead_drop_bucket"
        $infra2 = "exfil_storage"
        $infra3 = /s3:\/\/[a-z0-9-]+\.s3/

    condition:
        any of ($cloud*) and any of ($mcp*) and (any of ($abuse*) or any of ($infra*))
}

rule APT_Zero_Day_MCP_Exploit
{
    meta:
        description = "Potential zero-day exploit targeting MCP"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"
        confidence = "experimental"

    strings:
        // Exploit patterns
        $exploit1 = { 48 31 C0 48 31 FF 48 31 F6 48 31 D2 }  // Register clearing
        $exploit2 = { 90 90 90 90 90 90 90 90 }  // NOP sled
        $exploit3 = /\x00\x00\x00\x00[^\x00]+\xFF\xFF\xFF\xFF/  // Overflow pattern

        // MCP-specific targets
        $target1 = "mcp_message_handler"
        $target2 = "parse_tool_response"
        $target3 = "schema_validator"

        // Memory corruption indicators
        $corrupt1 = "stack_pivot"
        $corrupt2 = "heap_spray"
        $corrupt3 = "use_after_free"

        // Advanced techniques
        $adv1 = "rop_chain"
        $adv2 = "jop_gadget"
        $adv3 = "blind_return"

    condition:
        (any of ($exploit*) and any of ($target*)) or
        (any of ($target*) and any of ($corrupt*) and any of ($adv*)) or
        (math.entropy(0, filesize) > 7.8 and any of ($target*))
}