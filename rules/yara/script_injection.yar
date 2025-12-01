/*
 * Script Injection Detection Rules
 * Target: JavaScript, VBScript, template injection in MCP tools
 * Author: secscanmcp (merged from Cisco mcp-scanner + custom patterns)
 * Version: 1.0
 */

rule Script_Injection_JavaScript_Tags {
    meta:
        description = "Detects JavaScript script tag injection"
        severity = "CRITICAL"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Script tags
        $tag1 = /<script[^>]*>/i
        $tag2 = /<\/script>/i
        $tag3 = /<script\s+src\s*=/i

        // JavaScript protocol
        $proto1 = /javascript:/i
        $proto2 = /vbscript:/i
        $proto3 = /data:text\/html/i

        // SVG-based script execution
        $svg1 = /<svg[^>]*onload\s*=/i
        $svg2 = /<svg[^>]*onerror\s*=/i

        // Exclusion for documentation
        $exclude1 = /(documentation|tutorial|example|readme)/i

    condition:
        any of ($tag*, $proto*, $svg*) and not $exclude1
}

rule Script_Injection_Event_Handlers {
    meta:
        description = "Detects malicious event handler injection"
        severity = "HIGH"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Common event handlers with code
        $event1 = /\bonload\s*=\s*['"][^'"]*\(/i
        $event2 = /\bonerror\s*=\s*['"][^'"]*\(/i
        $event3 = /\bonclick\s*=\s*['"][^'"]*\(/i
        $event4 = /\bonmouseover\s*=\s*['"][^'"]*\(/i
        $event5 = /\bonfocus\s*=\s*['"][^'"]*\(/i
        $event6 = /\bonblur\s*=\s*['"][^'"]*\(/i
        $event7 = /\bonsubmit\s*=\s*['"][^'"]*\(/i
        $event8 = /\bonchange\s*=\s*['"][^'"]*\(/i

        // Less common but dangerous
        $event9 = /\bonanimationend\s*=/i
        $event10 = /\bontransitionend\s*=/i
        $event11 = /\bonpageshow\s*=/i
        $event12 = /\bonhashchange\s*=/i

        // Dangerous patterns in handlers
        $danger1 = /on\w+\s*=\s*['"]?\s*(eval|alert|confirm|prompt)\s*\(/i
        $danger2 = /on\w+\s*=\s*['"]?\s*document\.(cookie|location)/i

    condition:
        any of ($event*) or any of ($danger*)
}

rule Script_Injection_Execution_Functions {
    meta:
        description = "Detects dangerous JavaScript execution functions"
        severity = "CRITICAL"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Direct execution
        $exec1 = /\beval\s*\(\s*['"]/i
        $exec2 = /\bFunction\s*\(\s*['"]/i
        $exec3 = /\bsetTimeout\s*\(\s*['"]/i
        $exec4 = /\bsetInterval\s*\(\s*['"]/i

        // Dynamic script creation
        $create1 = /document\.createElement\s*\(\s*['"]script['"]\s*\)/i
        $create2 = /\.innerHTML\s*=\s*['"]<script/i
        $create3 = /\.outerHTML\s*=\s*['"]<script/i

        // DOM manipulation with script
        $dom1 = /document\.write\s*\(\s*['"]<script/i
        $dom2 = /document\.writeln\s*\(/i
        $dom3 = /\.insertAdjacentHTML\s*\(/i

        // Indirect execution
        $indirect1 = /\[['"]constructor['"]\]\s*\(/i
        $indirect2 = /window\[['"]eval['"]\]/i

    condition:
        any of them
}

rule Script_Injection_VBScript {
    meta:
        description = "Detects VBScript injection patterns"
        severity = "HIGH"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.1"

    strings:
        // VBScript objects (high confidence indicators)
        $vbs_obj1 = /\bCreateObject\s*\(\s*['"]W[Ss]cript/i
        $vbs_obj2 = /\bCreateObject\s*\(\s*['"]Shell\./i
        $vbs_obj3 = /\bCreateObject\s*\(\s*['"]Scripting\./i
        $vbs_obj4 = /\bWScript\.Shell\b/i
        $vbs_obj5 = /\bShell\.Application\b/i
        $vbs_obj6 = /\bScripting\.FileSystemObject\b/i

        // VBScript methods WITH object context (require WScript/Shell prefix)
        $vbs_method1 = /\bWScript\s*\.\s*Run\s*\(/i
        $vbs_method2 = /\bWScript\s*\.\s*Exec\s*\(/i
        $vbs_method3 = /\bShell\s*\.\s*Run\s*\(/i
        $vbs_method4 = /\bShell\s*\.\s*ShellExecute\s*\(/i
        $vbs_method5 = /\bWSH\s*\.\s*Run\s*\(/i

        // ActiveX controls
        $activex1 = /\bActiveXObject\s*\(\s*['"]/i
        $activex2 = /OBJECT\s+classid\s*=\s*['"]?CLSID:/i

        // WMI access
        $wmi1 = /\bwinmgmts:/i
        $wmi2 = /\bGetObject\s*\(\s*['"]winmgmts/i

        // Registry manipulation with VBScript context
        $reg1 = /\b(WScript|Shell)\s*\.\s*RegWrite\s*\(/i
        $reg2 = /\b(WScript|Shell)\s*\.\s*RegRead\s*\(/i

    condition:
        // Patterns require VBScript-specific context, reducing false positives
        any of them
}

rule Script_Injection_Encoded_Payloads {
    meta:
        description = "Detects encoded script payloads"
        severity = "HIGH"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Base64 encoded data URIs
        $b64_1 = /data:text\/html;base64,/i
        $b64_2 = /data:application\/javascript;base64,/i
        $b64_3 = /data:text\/javascript;base64,/i
        $b64_4 = /data:application\/x-javascript;base64,/i

        // Base64 decode in JavaScript
        $decode1 = /\batob\s*\(/i
        $decode2 = /\bbtoa\s*\(/i
        $decode3 = /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)/i

        // String obfuscation patterns
        $obfusc1 = /String\.fromCharCode\s*\([^)]+\)/i
        $obfusc2 = /\\x[0-9a-f]{2}/i
        $obfusc3 = /\\u[0-9a-f]{4}/i

        // Packed JavaScript
        $pack1 = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/i
        $pack2 = /\['constructor'\]\s*\(\s*['"]return/i

        // JSFuck-style obfuscation
        $jsfuck1 = /\[\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\]/

    condition:
        any of them
}

rule Script_Injection_ANSI_Terminal {
    meta:
        description = "Detects ANSI escape sequence injection for terminal manipulation"
        severity = "MEDIUM"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // ANSI color/formatting codes
        $ansi1 = /\\x1[Bb]\[[0-9;]*m/
        $ansi2 = /\\033\[[0-9;]*m/
        $ansi3 = /\\e\[[0-9;]*m/

        // Cursor manipulation
        $cursor1 = /\\x1[Bb]\[[0-9]*[ABCDEFGJKST]/
        $cursor2 = /\\x1[Bb]\[[0-9]*;[0-9]*[Hf]/

        // Screen clearing/manipulation
        $screen1 = /\\x1[Bb]\[2J/  // Clear screen
        $screen2 = /\\x1[Bb]\[0J/  // Clear from cursor
        $screen3 = /\\x1[Bb]\[1;1H/  // Move to home

        // Hyperlink injection (OSC 8)
        $link1 = /\\x1[Bb]\]8;;/

        // Title bar manipulation
        $title1 = /\\x1[Bb]\]0;/
        $title2 = /\\x1[Bb]\]2;/

        // Cisco pattern
        $cisco1 = /(\\x1[Bb]\[38;5;\d+|\\x1[Bb]\[2F\\x1[Bb]\[1G|\\x1[Bb]\[1;1H\\x1[Bb]\[0J|\\x1[Bb]\]8;;.*\\x1[Bb]\\|\\033\[[0-9;]*m|\\e\[[0-9;]*[mGKHF])/i

    condition:
        any of them
}

rule Script_Injection_Template {
    meta:
        description = "Detects server-side template injection patterns"
        severity = "HIGH"
        category = "template_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Jinja2/Twig/Django templates
        $jinja1 = /\{\{\s*[^}]*\.__class__/i
        $jinja2 = /\{\{\s*[^}]*\.__mro__/i
        $jinja3 = /\{\{\s*[^}]*\.__subclasses__/i
        $jinja4 = /\{\{\s*config\s*\}\}/i
        $jinja5 = /\{\%\s*import\s+/i

        // EJS/ERB templates
        $ejs1 = /<%[-=]?\s*[^%]*require\s*\(/i
        $ejs2 = /<%[-=]?\s*[^%]*process\./i
        $erb1 = /<%=?\s*[^%]*`[^`]+`/i

        // Pug/Jade templates
        $pug1 = /!{.*require\s*\(/i
        $pug2 = /#{.*require\s*\(/i

        // Velocity templates
        $velocity1 = /\$class\.forName\s*\(/i
        $velocity2 = /#set\s*\(\s*\$[^)]*Runtime/i

        // Freemarker templates
        $fm1 = /<#assign\s+[^>]*\.getRuntime\s*\(/i
        $fm2 = /\$\{[^}]*\.getClass\(\)/i

        // Expression Language (EL)
        $el1 = /\$\{[^}]*\.getRuntime\(\)/i
        $el2 = /\$\{[^}]*ProcessBuilder/i

        // Handlebars/Mustache
        $hbs1 = /\{\{\{[^}]*require[^}]*\}\}\}/i

    condition:
        any of them
}

rule Script_Injection_Hidden_Content {
    meta:
        description = "Detects hidden malicious content via CSS/HTML tricks"
        severity = "MEDIUM"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // CSS hiding techniques
        $css1 = /display\s*:\s*none[^;]*;[^}]*<script/i
        $css2 = /visibility\s*:\s*hidden[^;]*;[^}]*<script/i
        $css3 = /position\s*:\s*absolute[^;]*;[^;]*left\s*:\s*-\d{4,}px/i
        $css4 = /opacity\s*:\s*0[^;]*;[^}]*onclick/i

        // Text color hiding
        $color1 = /color\s*:\s*transparent/i
        $color2 = /color\s*:\s*rgba\s*\([^)]*,\s*0\s*\)/i

        // Overflow hiding
        $overflow1 = /overflow\s*:\s*hidden[^;]*;[^}]*padding.*push.*off.*screen/i

        // Font size zero
        $font1 = /font-size\s*:\s*0/i

        // Cisco pattern
        $cisco1 = /\b(padding.*push.*off.*screen|hidden.*scrollbar|overflow.*hidden.*instruction|invisible.*text.*color)\b/i

    condition:
        any of them
}

rule Script_Injection_WebAssembly {
    meta:
        description = "Detects WebAssembly-based code execution attempts"
        severity = "MEDIUM"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // WebAssembly instantiation
        $wasm1 = /WebAssembly\.instantiate\s*\(/i
        $wasm2 = /WebAssembly\.compile\s*\(/i
        $wasm3 = /WebAssembly\.Module\s*\(/i
        $wasm4 = /WebAssembly\.Instance\s*\(/i

        // Inline WASM
        $inline1 = /new\s+Uint8Array\s*\(\s*\[[^\]]*0x00,\s*0x61,\s*0x73,\s*0x6d/i

        // WASM magic bytes (as string)
        $magic1 = { 00 61 73 6d }

    condition:
        any of ($wasm*, $inline*) or $magic1
}

rule Script_Injection_Import_Hijacking {
    meta:
        description = "Detects JavaScript/module import hijacking with suspicious paths"
        severity = "HIGH"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.1"

    strings:
        // Suspicious dynamic imports (path traversal or remote)
        $import_traversal = /import\s*\(\s*['"`][^'"`)]*\.\.\/[^'"`)]*['"`]\s*\)/i
        $import_remote = /import\s*\(\s*['"`]https?:\/\//i
        $import_variable = /import\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/

        // Require hijacking (suspicious patterns only)
        $require_remote = /require\s*\(\s*['"]https?:/i
        $require_env = /require\s*\(\s*process\.env/i

        // Module prototype pollution (these are actual attacks)
        $proto_cache_del = /delete\s+require\.cache/i
        $proto_override = /Object\.defineProperty\s*\(\s*require/i

        // ES module manipulation with path traversal
        $esm_traversal = /import\s*\*\s*as\s*\w+\s*from\s*['"]\.\.\/\.\.\//i

    condition:
        // Patterns are specific enough to avoid false positives
        (filesize < 5MB) and
        any of them
}
