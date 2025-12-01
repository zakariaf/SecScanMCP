/*
 * Credential Harvesting Detection Rules
 * Target: API keys, tokens, passwords, certificates, and sensitive data exposure
 * Author: secscanmcp (merged from Cisco mcp-scanner + custom patterns)
 * Version: 1.0
 */

rule Credential_API_Keys_Cloud {
    meta:
        description = "Detects cloud provider API keys and access tokens"
        severity = "CRITICAL"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // AWS credentials
        $aws1 = /AKIA[0-9A-Z]{16}/
        $aws2 = /aws_access_key_id\s*[=:]\s*['"]?[A-Z0-9]{20}/i
        $aws3 = /aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9\/+=]{40}/i
        $aws4 = /ASIA[0-9A-Z]{16}/  // Temporary credentials

        // Google Cloud
        $gcp1 = /AIza[0-9A-Za-z\-_]{35}/
        $gcp2 = /"type"\s*:\s*"service_account"/
        $gcp3 = /GOOG[\w\W]{10,30}/

        // Azure
        $azure1 = /[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/i
        $azure2 = /AccountKey=[A-Za-z0-9+\/=]{86}/
        $azure3 = /SharedAccessSignature=sv=/

        // DigitalOcean
        $do1 = /dop_v1_[a-f0-9]{64}/
        $do2 = /doo_v1_[a-f0-9]{64}/

        // Linode (API token format)
        $linode1 = /LINODE_CLI_TOKEN\s*[=:]\s*['"]?[a-f0-9]{64}/i
        $linode2 = /linode_api_token\s*[=:]\s*['"]?[a-f0-9]{64}/i

        // Exclusion for templates
        $exclude1 = /(YOUR_API_KEY|REPLACE_WITH|INSERT_KEY|\.example|\.sample|\.template)/i

    condition:
        (any of ($aws*) or any of ($gcp*) or any of ($azure*) or any of ($do*) or any of ($linode*)) and not $exclude1
}

rule Credential_API_Keys_AI_ML {
    meta:
        description = "Detects AI/ML platform API keys"
        severity = "CRITICAL"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // OpenAI
        $openai1 = /sk-[A-Za-z0-9]{48}/
        $openai2 = /sk-proj-[A-Za-z0-9]{48}/
        $openai3 = /OPENAI_API_KEY\s*[=:]\s*['"]?sk-/i

        // Anthropic/Claude
        $anthropic1 = /sk-ant-[A-Za-z0-9\-]{32,}/
        $anthropic2 = /ANTHROPIC_API_KEY\s*[=:]/i
        $anthropic3 = /CLAUDE_API_KEY\s*[=:]/i

        // Google AI
        $google1 = /GOOGLE_AI_KEY\s*[=:]/i
        $google2 = /GEMINI_API_KEY\s*[=:]/i
        $google3 = /PALM_API_KEY\s*[=:]/i

        // Hugging Face
        $hf1 = /hf_[A-Za-z0-9]{34}/
        $hf2 = /HUGGINGFACE_TOKEN\s*[=:]/i
        $hf3 = /HF_TOKEN\s*[=:]/i

        // Cohere
        $cohere1 = /COHERE_API_KEY\s*[=:]/i

        // Replicate
        $replicate1 = /r8_[A-Za-z0-9]{40}/
        $replicate2 = /REPLICATE_API_TOKEN\s*[=:]/i

        // Together AI
        $together1 = /TOGETHER_API_KEY\s*[=:]/i

        // Mistral
        $mistral1 = /MISTRAL_API_KEY\s*[=:]/i

        // Azure OpenAI
        $azure_ai1 = /AZURE_OPENAI_KEY\s*[=:]/i
        $azure_ai2 = /AZURE_COGNITIVE_KEY\s*[=:]/i

        // AWS Bedrock
        $bedrock1 = /BEDROCK_ACCESS_KEY\s*[=:]/i

        // Exclusion
        $exclude1 = /\.example|\.sample|\.template|YOUR_KEY/i

    condition:
        any of ($openai*, $anthropic*, $google*, $hf*, $cohere*, $replicate*, $together*, $mistral*, $azure_ai*, $bedrock*) and not $exclude1
}

rule Credential_API_Keys_Development {
    meta:
        description = "Detects development platform API keys"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // GitHub
        $github1 = /ghp_[A-Za-z0-9]{36}/
        $github2 = /gho_[A-Za-z0-9]{36}/
        $github3 = /ghu_[A-Za-z0-9]{36}/
        $github4 = /ghs_[A-Za-z0-9]{36}/
        $github5 = /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/

        // GitLab
        $gitlab1 = /glpat-[A-Za-z0-9\-]{20}/

        // Bitbucket
        $bitbucket1 = /BITBUCKET_TOKEN\s*[=:]/i

        // npm
        $npm1 = /npm_[A-Za-z0-9]{36}/
        $npm2 = /NPM_TOKEN\s*[=:]/i

        // PyPI
        $pypi1 = /pypi-[A-Za-z0-9\-]{36,}/

        // Docker
        $docker1 = /DOCKER_PASSWORD\s*[=:]/i
        $docker2 = /dckr_pat_[A-Za-z0-9\-_]{27}/

        // Heroku
        $heroku1 = /[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/i
        $heroku2 = /HEROKU_API_KEY\s*[=:]/i

        // Vercel
        $vercel1 = /VERCEL_TOKEN\s*[=:]/i

        // Netlify
        $netlify1 = /NETLIFY_AUTH_TOKEN\s*[=:]/i

    condition:
        any of them
}

rule Credential_API_Keys_Communication {
    meta:
        description = "Detects communication platform API keys"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Slack
        $slack1 = /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/
        $slack2 = /SLACK_TOKEN\s*[=:]/i
        $slack3 = /SLACK_WEBHOOK\s*[=:]/i

        // Discord
        $discord1 = /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/
        $discord2 = /DISCORD_TOKEN\s*[=:]/i
        $discord3 = /DISCORD_WEBHOOK\s*[=:]/i

        // Telegram
        $telegram1 = /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/
        $telegram2 = /TELEGRAM_BOT_TOKEN\s*[=:]/i

        // Twilio
        $twilio1 = /SK[a-f0-9]{32}/
        $twilio2 = /TWILIO_AUTH_TOKEN\s*[=:]/i

        // SendGrid
        $sendgrid1 = /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/
        $sendgrid2 = /SENDGRID_API_KEY\s*[=:]/i

        // Mailgun
        $mailgun1 = /key-[a-f0-9]{32}/
        $mailgun2 = /MAILGUN_API_KEY\s*[=:]/i

    condition:
        any of them
}

rule Credential_API_Keys_Payment {
    meta:
        description = "Detects payment platform API keys"
        severity = "CRITICAL"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Stripe
        $stripe1 = /sk_live_[a-zA-Z0-9]{24,}/
        $stripe2 = /rk_live_[a-zA-Z0-9]{24,}/
        $stripe3 = /STRIPE_SECRET_KEY\s*[=:]/i
        $stripe4 = /pk_live_[a-zA-Z0-9]{24,}/

        // PayPal
        $paypal1 = /PAYPAL_CLIENT_SECRET\s*[=:]/i
        $paypal2 = /access_token\$production\$/

        // Square
        $square1 = /sq0csp-[A-Za-z0-9\-_]{43}/
        $square2 = /SQUARE_ACCESS_TOKEN\s*[=:]/i

        // Braintree
        $braintree1 = /BRAINTREE_PRIVATE_KEY\s*[=:]/i

    condition:
        any of them
}

rule Credential_SSH_Keys {
    meta:
        description = "Detects SSH private keys and related credentials"
        severity = "CRITICAL"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // SSH private key headers
        $ssh1 = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh2 = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ssh3 = "-----BEGIN DSA PRIVATE KEY-----"
        $ssh4 = "-----BEGIN EC PRIVATE KEY-----"
        $ssh5 = "-----BEGIN PRIVATE KEY-----"
        $ssh6 = "-----BEGIN ENCRYPTED PRIVATE KEY-----"

        // SSH public key patterns (in context of exfiltration)
        $pub1 = /ssh-rsa\s+[A-Za-z0-9+\/=]{100,}/
        $pub2 = /ssh-ed25519\s+[A-Za-z0-9+\/=]{40,}/
        $pub3 = /ecdsa-sha2-[^\s]+\s+[A-Za-z0-9+\/=]{100,}/

        // PuTTY keys
        $putty1 = "PuTTY-User-Key-File"

        // SSH file patterns
        $file1 = /id_rsa[^\w]/
        $file2 = /id_dsa[^\w]/
        $file3 = /id_ecdsa[^\w]/
        $file4 = /id_ed25519[^\w]/

    condition:
        any of them
}

rule Credential_Certificates {
    meta:
        description = "Detects certificate and key file access"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Certificate headers
        $cert1 = "-----BEGIN CERTIFICATE-----"
        $cert2 = "-----BEGIN X509 CERTIFICATE-----"

        // File extensions with access patterns
        $ext1 = /\.(pem|crt|cer|key|p12|pfx|jks|keystore)\b/i

        // Certificate file names
        $name1 = /\b(server|client|ca|root|intermediate)\.(pem|crt|key)\b/i
        $name2 = /\b(ssl|tls)[-_]?(cert|key|certificate)\b/i

        // Java keystore
        $java1 = /keytool.*-keystore/i
        $java2 = /\.keystore\b/i
        $java3 = /\.jks\b/i

        // PKCS#12
        $pkcs1 = /\.p12\b/i
        $pkcs2 = /\.pfx\b/i

    condition:
        any of them
}

rule Credential_Database {
    meta:
        description = "Detects database credentials and connection strings"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Connection strings
        $conn1 = /mysql:\/\/[^:]+:[^@]+@/i
        $conn2 = /postgres(ql)?:\/\/[^:]+:[^@]+@/i
        $conn3 = /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i
        $conn4 = /redis:\/\/:[^@]+@/i
        $conn5 = /Server=[^;]+;.*Password=[^;]+/i
        $conn6 = /jdbc:[a-z]+:\/\/.*password=/i

        // Environment variables
        $env1 = /DATABASE_PASSWORD\s*[=:]/i
        $env2 = /DB_PASSWORD\s*[=:]/i
        $env3 = /MYSQL_PASSWORD\s*[=:]/i
        $env4 = /POSTGRES_PASSWORD\s*[=:]/i
        $env5 = /MONGODB_PASSWORD\s*[=:]/i
        $env6 = /REDIS_PASSWORD\s*[=:]/i

        // DSN patterns
        $dsn1 = /dsn\s*[=:]\s*['"][^'"]*password/i
        $dsn2 = /connection_string\s*[=:]\s*['"][^'"]*password/i

    condition:
        any of them
}

rule Credential_Directories {
    meta:
        description = "Detects access to credential directories"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Unix credential directories
        $dir1 = /[\/\\]\.ssh[\/\\]/
        $dir2 = /[\/\\]\.aws[\/\\]/
        $dir3 = /[\/\\]\.kube[\/\\]/
        $dir4 = /[\/\\]\.gnupg[\/\\]/
        $dir5 = /[\/\\]\.config[\/\\]gcloud[\/\\]/
        $dir6 = /[\/\\]\.docker[\/\\]/

        // Windows credential locations
        $win1 = /\\AppData\\.*\\credentials/i
        $win2 = /\\\.azure[\/\\]/i

        // Specific credential files
        $file1 = /credentials\.json/i
        $file2 = /service_account\.json/i
        $file3 = /\.netrc\b/i
        $file4 = /\.pgpass\b/i
        $file5 = /\.my\.cnf\b/i
        $file6 = /wallet\.dat\b/i

        // Config files with credentials
        $config1 = /aws_credentials/i
        $config2 = /config\.json.*token/i
        $config3 = /\.npmrc.*_authToken/i

    condition:
        any of them
}

rule Credential_Environment_Files {
    meta:
        description = "Detects environment file access and exposure"
        severity = "HIGH"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Environment files
        $env1 = /\.env\b/
        $env2 = /\.env\.local\b/i
        $env3 = /\.env\.production\b/i
        $env4 = /\.env\.development\b/i
        $env5 = /\.env\.[a-z]+\b/i

        // Environment access methods
        $access1 = /process\.env\./i
        $access2 = /os\.environ\[/i
        $access3 = /getenv\s*\(/i
        $access4 = /\$ENV\{/

        // dotenv patterns
        $dotenv1 = /dotenv\.config/i
        $dotenv2 = /load_dotenv/i

        // Secret/sensitive variable patterns in env
        $secret1 = /SECRET_KEY\s*[=:]/i
        $secret2 = /API_SECRET\s*[=:]/i
        $secret3 = /JWT_SECRET\s*[=:]/i
        $secret4 = /SESSION_SECRET\s*[=:]/i
        $secret5 = /COOKIE_SECRET\s*[=:]/i
        $secret6 = /ENCRYPTION_KEY\s*[=:]/i

    condition:
        any of them
}

rule Credential_Exfiltration_Actions {
    meta:
        description = "Detects credential exfiltration action patterns"
        severity = "CRITICAL"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // File access action words combined with credential targets
        $action1 = /\b(read|cat|open|fetch|retrieve|access|load|dump|steal|grab|extract|leak|exfiltrate)\s+[^;]*\b(password|credential|secret|token|key|certificate)\b/i
        $action2 = /\b(curl|wget|scp|rsync|nc)\s+[^;]*(password|credential|secret|token|\.pem|\.key)/i

        // Transfer with encoding
        $transfer1 = /base64\s+encode\s+[^;]*credential/i
        $transfer2 = /concatenate\s+[^;]*conversation\s+history/i

        // Explicit exfiltration patterns
        $exfil1 = /\b(leak|exfiltrate|export|dump)\s+[^\n]*(parameter|context|files?|credentials?|keys?|tokens?|secrets?)\b/i

        // MCP-specific credential patterns
        $mcp1 = /claude_desktop_config\.json/i
        $mcp2 = /~\/\.cursor\/logs\/conversations/i
        $mcp3 = /plaintext[^\n]*api[^\n]*key/i

        // WhatsApp exploit patterns (from Cisco)
        $whatsapp1 = /_get_all_messages[^\n]*messages\.db/i
        $whatsapp2 = /whatsapp[^\n]*message[^\n]*history/i
        $whatsapp3 = /contact[^\n]*list[^\n]*exfiltrat/i

    condition:
        any of them
}

rule Credential_Hardcoded_Passwords {
    meta:
        description = "Detects hardcoded passwords in code"
        severity = "MEDIUM"
        category = "credential_harvesting"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Common password variable patterns
        $pwd1 = /password\s*[=:]\s*['"][^'"]{8,}['"]/i
        $pwd2 = /passwd\s*[=:]\s*['"][^'"]{8,}['"]/i
        $pwd3 = /secret\s*[=:]\s*['"][^'"]{8,}['"]/i
        $pwd4 = /admin_password\s*[=:]\s*['"][^'"]+['"]/i
        $pwd5 = /root_password\s*[=:]\s*['"][^'"]+['"]/i

        // Database passwords
        $db1 = /db_password\s*[=:]\s*['"][^'"]+['"]/i
        $db2 = /database_password\s*[=:]\s*['"][^'"]+['"]/i

        // Basic auth
        $auth1 = /Authorization:\s*Basic\s+[A-Za-z0-9+\/=]{10,}/i
        $auth2 = /Bearer\s+[A-Za-z0-9\-_\.]{20,}/i

        // Exclusion for test/example files
        $exclude1 = /(test|spec|example|sample|mock|dummy|fake)/i
        $exclude2 = /password123|admin123|test123|changeme/i

    condition:
        any of ($pwd*, $db*, $auth*) and not any of ($exclude*)
}
