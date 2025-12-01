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
        version = "1.0"

    strings:
        // VBScript objects
        $vbs1 = /\bCreateObject\s*\(/i
        $vbs2 = /\bWScript\.Shell\b/i
        $vbs3 = /\bShell\.Application\b/i
        $vbs4 = /\bScripting\.FileSystemObject\b/i

        // VBScript dangerous methods
        $method1 = /\.Exec\s*\(/i
        $method2 = /\.Run\s*\(/i
        $method3 = /\.ShellExecute\s*\(/i
        $method4 = /\.RegWrite\s*\(/i
        $method5 = /\.RegRead\s*\(/i

        // ActiveX controls
        $activex1 = /\bActiveXObject\s*\(/i
        $activex2 = /OBJECT\s+classid\s*=/i
        $activex3 = /CLSID:/i

        // WMI access
        $wmi1 = /\bwinmgmts:/i
        $wmi2 = /\bGetObject\s*\(\s*['"]winmgmts/i

    condition:
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
        description = "Detects JavaScript/module import hijacking"
        severity = "HIGH"
        category = "script_injection"
        author = "secscanmcp"
        version = "1.0"

    strings:
        // Dynamic import
        $import1 = /import\s*\(\s*['"]/i
        $import2 = /import\s*\(\s*`/i
        $import3 = /import\s*\(\s*\$/i

        // Require hijacking
        $require1 = /require\s*\(\s*['"]\.\.\//i
        $require2 = /require\s*\(\s*['"]https?:/i
        $require3 = /require\s*\(\s*process\.env/i

        // Module prototype pollution
        $proto1 = /require\.cache/i
        $proto2 = /module\.exports\s*=\s*function/i
        $proto3 = /Object\.defineProperty\s*\(\s*require/i

        // ES module manipulation
        $esm1 = /import\.meta/i
        $esm2 = /import\s*\*\s*as\s*\w+\s*from\s*['"]\.\.\//i

    condition:
        any of them
}
