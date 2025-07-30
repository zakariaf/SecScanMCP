/*
YARA rules for detecting authentication and session vulnerabilities in MCP
*/

rule MCP_Missing_Authentication
{
    meta:
        description = "Detects missing authentication in MCP servers"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "authentication"

    strings:
        // No auth configuration
        $noauth1 = "authentication: false"
        $noauth2 = "requireAuth: false"
        $noauth3 = "skipAuth: true"
        $noauth4 = "auth: null"
        $noauth5 = "noAuth: true"
        $noauth6 = /"auth":\s*\{\s*\}/

        // Optional auth
        $optional1 = "authentication optional" nocase
        $optional2 = "auth not required" nocase
        $optional3 = /if\s*\(\s*!auth\s*\)\s*\{[^}]*next\(\)/

        // Bypassed middleware
        $bypass1 = /app\.use.*\/\*.*auth/
        $bypass2 = /router\..*\(\s*['"]\/.*public/
        $bypass3 = "// TODO: Add authentication"
        $bypass4 = "// FIXME: Auth disabled for testing"

        // Anonymous access
        $anon1 = "allowAnonymous: true"
        $anon2 = "anonymous_access"
        $anon3 = "guestAccess: true"

    condition:
        any of ($noauth*) or
        any of ($optional*) or
        (any of ($bypass*) and not /test|spec|mock/) or
        any of ($anon*)
}

rule MCP_Weak_Session_Management
{
    meta:
        description = "Detects weak session management practices"
        author = "MCP Security Scanner"
        severity = "high"
        category = "authentication"

    strings:
        // Session in URL
        $url1 = /[?&]sessionId=[a-f0-9\-]+/
        $url2 = /[?&]token=[A-Za-z0-9]+/
        $url3 = /[?&]auth=[A-Za-z0-9]+/
        $url4 = "GET /messages/?sessionId="

        // Weak session generation
        $weak1 = "Math.random()"
        $weak2 = "Date.now()"
        $weak3 = /new Date\(\)\.getTime\(\)/
        $weak4 = /uuid\(\)\.slice\(0,\s*[0-9]\)/
        $weak5 = /Math\.floor.*Math\.random/

        // Predictable tokens
        $predict1 = /[0-9]{13}/  // timestamp
        $predict2 = /user_[0-9]+_session/
        $predict3 = /token_\d{4,8}/

        // No expiration
        $noexp1 = "expires: null"
        $noexp2 = "maxAge: Infinity"
        $noexp3 = /ttl:\s*-1/
        $noexp4 = "permanent_session"

    condition:
        (any of ($url*) and any of ($weak*)) or
        (any of ($predict*) and any of ($noexp*)) or
        (2 of ($weak*))
}

rule MCP_OAuth_Implementation_Flaws
{
    meta:
        description = "Detects OAuth implementation vulnerabilities"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "authentication"

    strings:
        // State parameter issues
        $state1 = /state\s*=\s*["']fixed["']/
        $state2 = /oauth.*callback.*[^&]state/
        $state3 = "// TODO: Validate state parameter"
        $state4 = /generateState.*return\s+["'][^"']+["']/

        // Token storage issues
        $storage1 = /localStorage\.setItem.*token/
        $storage2 = /cookie.*httpOnly:\s*false/
        $storage3 = /document\.cookie.*access_token/
        $storage4 = "store_token_in_url"

        // Redirect URI issues
        $redirect1 = /redirect_uri.*\*/
        $redirect2 = /redirectUri:\s*req\./
        $redirect3 = "redirect_uri_mismatch"
        $redirect4 = /validateRedirect.*return\s+true/

        // PKCE missing
        $pkce1 = "code_challenge"
        $pkce2 = "code_verifier"
        $pkce3 = "S256"

    condition:
        any of ($state*) or
        any of ($storage*) or
        any of ($redirect*) or
        (not any of ($pkce*) and /oauth|oidc|authorization_code/)
}

rule MCP_JWT_Vulnerabilities
{
    meta:
        description = "Detects JWT implementation vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "authentication"

    strings:
        // Weak algorithms
        $alg1 = /"alg":\s*"none"/
        $alg2 = /"alg":\s*"HS256"/
        $alg3 = "algorithm: 'none'"
        $alg4 = "verify: false"

        // Weak secrets
        $secret1 = /secret:\s*["']secret["']/
        $secret2 = /secret:\s*["']password["']/
        $secret3 = /secret:\s*["'][a-z]{1,10}["']/
        $secret4 = "JWT_SECRET=secret"

        // No verification
        $noverify1 = /jwt\.decode.*[^,]*\)/
        $noverify2 = "ignoreExpiration: true"
        $noverify3 = "skipVerification"
        $noverify4 = /verify.*catch.*return/

        // Key confusion
        $confusion1 = /publicKey.*HS256/
        $confusion2 = /RS256.*secret/
        $confusion3 = "key_confusion_vulnerability"

    condition:
        any of ($alg*) or
        any of ($secret*) or
        any of ($noverify*) or
        any of ($confusion*)
}

rule MCP_CORS_Misconfiguration
{
    meta:
        description = "Detects CORS misconfigurations allowing authentication bypass"
        author = "MCP Security Scanner"
        severity = "high"
        category = "authentication"

    strings:
        // Wildcard origin
        $wild1 = "Access-Control-Allow-Origin: *"
        $wild2 = /origin:\s*['"]\*["']/
        $wild3 = "cors: { origin: true }"
        $wild4 = /setHeader.*Origin.*\*/

        // Reflected origin
        $reflect1 = /origin:\s*req\.headers\.origin/
        $reflect2 = /Access-Control-Allow-Origin.*req\.get\(['"]origin/
        $reflect3 = "res.header('Access-Control-Allow-Origin', origin)"

        // Credentials with wildcard
        $cred1 = "Access-Control-Allow-Credentials: true"
        $cred2 = "credentials: true"
        $cred3 = "withCredentials: true"

        // Weak validation
        $weak1 = /origin\.endsWith\(/
        $weak2 = /origin\.includes\(/
        $weak3 = /origin\.indexOf.*>\s*-1/

    condition:
        (any of ($wild*) and any of ($cred*)) or
        (any of ($reflect*) and any of ($cred*)) or
        (any of ($weak*) and not /localhost|127\.0\.0\.1/)
}

rule MCP_API_Key_Exposure
{
    meta:
        description = "Detects exposed API keys and credentials"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "authentication"

    strings:
        // Hardcoded keys
        $key1 = /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{32,}["']/
        $key2 = /secret[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{32,}["']/
        $key3 = /private[_-]?key\s*[:=]\s*["'][a-zA-Z0-9]{32,}["']/

        // Cloud provider keys
        $aws1 = /AKIA[0-9A-Z]{16}/
        $aws2 = /aws[_-]?secret[_-]?access[_-]?key/i
        $gcp1 = /AIza[0-9A-Za-z\-_]{35}/
        $azure1 = /DefaultEndpointsProtocol=https/

        // Authentication tokens
        $token1 = /github[_-]?token\s*[:=]\s*["'][a-zA-Z0-9]{40}["']/
        $token2 = /slack[_-]?token\s*[:=]\s*["']xox[baprs]-/
        $token3 = /npm[_-]?token\s*[:=]\s*["'][a-zA-Z0-9]{36}["']/

        // Database credentials
        $db1 = /mongodb\+srv:\/\/[^:]+:[^@]+@/
        $db2 = /postgres:\/\/[^:]+:[^@]+@/
        $db3 = /mysql:\/\/[^:]+:[^@]+@/

    condition:
        any of ($key*) or
        any of ($aws*, $gcp*, $azure*) or
        any of ($token*) or
        any of ($db*)
}

rule MCP_Session_Fixation
{
    meta:
        description = "Detects session fixation vulnerabilities"
        author      = "MCP Security Scanner"
        severity    = "high"
        category    = "authentication"

    strings:
        // Session ID in response
        $resp1 = /res\.json\s*\(\s*\{[^}]*sessionId/
        $resp2 = /return\s+\{[^}]*session[_-]?id/
        $resp3 = /send\s*\(\s*\{[^}]*token:/

        // No regeneration
        $noregen1    = /login.*\{/
        $noregen2    = "// TODO: Regenerate session"
        $noregen3    = "keepSessionId: true"
        $regen       = /regenerate/
        $destroy     = /destroy/
        $invalidate  = /invalidate/

        // Accepts external session
        $accept1 = /req\.(body|query|params)\.sessionId/
        $accept2 = /session\.id\s*=\s*req\./
        $accept3 = "use_supplied_session_id"

    condition:
        (
            any of ($resp*) and
            (
                ($noregen1 and not any of ($regen, $destroy, $invalidate)) or
                any of ($noregen2, $noregen3)
            )
        )
        or any of ($accept*)
}

rule MCP_Authentication_Bypass_Patterns
{
    meta:
        description = "Detects authentication bypass patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "authentication"

    strings:
        // Debug/test bypasses
        $debug1 = /if\s*\(\s*.*debug.*\)\s*\{[^}]*return\s+true/
        $debug2 = "process.env.SKIP_AUTH"
        $debug3 = "AUTH_DISABLED=true"
        $debug4 = /if\s*\(\s*.*test.*\)\s*\{[^}]*authenticated\s*=\s*true/

        // Logic flaws
        $logic1 = /if\s*\(\s*!user\s*\|\|\s*!password\s*\)\s*\{[^}]*next\(\)/
        $logic2 = /authenticated\s*=\s*true.*authenticated\s*=\s*false/
        $logic3 = /return\s+true.*\/\/\s*TODO/

        // Type confusion
        $type1 = /user\s*==\s*['"]admin["']/
        $type2 = /password\s*==\s*null/
        $type3 = /auth.*toString\(\)\s*===/

        // Race conditions
        $race1 = /async.*authenticate.*await/
        $race2 = /setTimeout.*authenticated\s*=/
        $race3 = "check_auth_later"

    condition:
        any of ($debug*) or
        any of ($logic*) or
        any of ($type*) or
        any of ($race*)
}

rule MCP_Privilege_Escalation_Auth
{
    meta:
        description = "Detects privilege escalation through authentication flaws"
        author      = "MCP Security Scanner"
        severity    = "critical"
        category    = "authentication"

    strings:
        // Role manipulation
        $role1 = /user\.role\s*=\s*req\./
        $role2 = /isAdmin\s*=\s*req\.(body|query|params)/
        $role3 = /permissions\s*=.*JSON\.parse\s*\(\s*req\./

        // IDOR vulnerabilities
        $idor1 = /user[_-]?id\s*=\s*req\.params/
        $idor2 = /findById\s*\(\s*req\.(body|query|params)/
        $idor3 = /WHERE\s+id\s*=\s*\$\{req\./

        // Missing authorization (simplified, see condition for exclusions)
        $noauth1 = "// TODO: Check permissions"
        $noauth2 = /function.*admin.*\{/            /* match admin‐only endpoints */
        $noauth3 = "skipAuthorization: true"

        // Words indicating proper checks
        $auth    = /authorize/
        $perm    = /permission/
        $role    = /role/

        // Default admin misconfiguration
        $default1 = /role:\s*["']admin["']/
        $default2 = "DEFAULT_ADMIN_ROLE"
        $default3 = /new User.*admin:\s*true/

    condition:
        any of ($role*) or
        any of ($idor*) or
        any of ($noauth1, $noauth3) or
        ($noauth2 and not any of ($auth, $perm, $role)) or
        any of ($default*)
}

rule MCP_SSO_Implementation_Flaws
{
    meta:
        description = "Detects SSO implementation vulnerabilities"
        author = "MCP Security Scanner"
        severity = "high"
        category = "authentication"

    strings:
        // SAML vulnerabilities
        $saml1 = "SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\""
        $saml2 = /validateSignature.*return\s+true/
        $saml3 = "// Skip SAML signature validation"
        $saml4 = /X509Certificate.*MIID/

        // Response validation
        $valid1 = /InResponseTo.*TODO/
        $valid2 = "ignoreResponseTo: true"
        $valid3 = /NotOnOrAfter.*9999/

        // Entity ID issues
        $entity1 = /entityId:\s*['"]\*["']/
        $entity2 = /Issuer.*req\./
        $entity3 = "accept_any_entity_id"

    condition:
        any of ($saml*) or
        any of ($valid*) or
        any of ($entity*)
}