"""
Complex security vulnerabilities that require semantic analysis to detect.
These are examples of what CodeQL excels at finding.
"""

import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# 1. Complex Data Flow - Command Injection
class DataProcessor:
    def __init__(self):
        self.commands = {}

    def register_command(self, name, cmd):
        """Store commands for later execution"""
        self.commands[name] = cmd

    def process_data(self, data):
        """Process data through multiple transformations"""
        # Data flows through multiple functions
        cleaned = self._clean_input(data)
        formatted = self._format_data(cleaned)
        return self._execute_command(formatted)

    def _clean_input(self, data):
        # Insufficient sanitization
        return data.replace(";", "")

    def _format_data(self, data):
        # Further transformation
        return f"echo {data}"

    def _execute_command(self, cmd):
        # Sink: Command injection vulnerability
        # CodeQL tracks data flow from process_data() to here
        return subprocess.check_output(cmd, shell=True)

# 2. Second-Order SQL Injection
class UserManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)

    def store_user_preference(self, user_id, preference):
        """Store user preference (seems safe)"""
        cursor = self.conn.cursor()
        # First insertion - parameterized (safe)
        cursor.execute(
            "INSERT INTO preferences (user_id, pref) VALUES (?, ?)",
            (user_id, preference)
        )
        self.conn.commit()

    def get_users_by_preference(self):
        """Second-order SQL injection"""
        cursor = self.conn.cursor()
        # Fetch stored preferences
        cursor.execute("SELECT pref FROM preferences")
        preferences = cursor.fetchall()

        results = []
        for (pref,) in preferences:
            # Sink: Using stored data in unsafe query
            # CodeQL detects this second-order injection
            query = f"SELECT * FROM users WHERE preference = '{pref}'"
            cursor.execute(query)
            results.extend(cursor.fetchall())

        return results

# 3. Tainted Data Through Complex Control Flow
@app.route('/search')
def search():
    # Source: User input
    query = request.args.get('q', '')

    # Complex control flow
    if len(query) > 10:
        processed = process_long_query(query)
    else:
        processed = process_short_query(query)

    # Data converges here
    return execute_search(processed)

def process_long_query(q):
    # Some processing
    return q.upper()

def process_short_query(q):
    # Different processing
    return q.lower()

def execute_search(query):
    # Sink: OS command execution
    # CodeQL tracks through all control flow paths
    os.system(f"grep {query} /var/log/app.log")
    return "Search complete"

# 4. Unsafe Deserialization with Data Flow
class ConfigManager:
    def __init__(self):
        self.configs = {}

    def load_config(self, config_data):
        """Load configuration from user-provided YAML"""
        # Source: User-provided YAML
        try:
            # Sink: Unsafe YAML loading allows arbitrary object creation
            # CodeQL detects flow from user input to unsafe deserializer
            config = yaml.load(config_data, Loader=yaml.Loader)
            self.process_config(config)
        except:
            pass

    def process_config(self, config):
        # Further processing that might execute injected objects
        for key, value in config.items():
            if hasattr(value, '__call__'):
                # Executing potentially injected callable
                value()

# 5. Authentication Bypass Through Logic Flaw
class AuthManager:
    def __init__(self):
        self.users = {}
        self.sessions = {}

    def authenticate(self, username, password):
        """Authenticate user - contains logic flaw"""
        user = self.users.get(username)

        # Logic flaw: Check password only if user exists
        if user:
            if user['password'] == password:
                return self.create_session(username)
            else:
                return None
        else:
            # BUG: Creating session for non-existent user!
            # CodeQL detects this authentication bypass
            return self.create_session(username)

    def create_session(self, username):
        session_id = os.urandom(16).hex()
        self.sessions[session_id] = username
        return session_id

# 6. Path Traversal Through Indirect Flow
class FileManager:
    def __init__(self, base_path):
        self.base_path = base_path
        self.file_cache = {}

    def cache_file_request(self, filename):
        """Cache file request for later processing"""
        request_id = os.urandom(8).hex()
        # Store user input for later use
        self.file_cache[request_id] = filename
        return request_id

    def process_cached_request(self, request_id):
        """Process cached request - path traversal vulnerability"""
        filename = self.file_cache.get(request_id)
        if filename:
            # Sink: Path traversal through cached data
            # CodeQL tracks from cache_file_request to here
            file_path = os.path.join(self.base_path, filename)
            with open(file_path, 'r') as f:
                return f.read()

# 7. Server-Side Template Injection (SSTI)
@app.route('/welcome')
def welcome():
    # Source: User-controlled template
    name = request.args.get('name', 'Guest')

    # Complex template building
    template_parts = []
    template_parts.append('<h1>Welcome ')
    template_parts.append('{{ ')
    template_parts.append(name)  # User input injected
    template_parts.append(' }}')
    template_parts.append('</h1>')

    template = ''.join(template_parts)

    # Sink: Server-side template injection
    # CodeQL tracks through list operations
    return render_template_string(template)

# 8. Cryptographic Vulnerability with Weak Randomness
import random
import string

class TokenGenerator:
    def __init__(self):
        # Weak: Using predictable random
        random.seed(12345)

    def generate_token(self):
        """Generate 'secure' token - actually insecure"""
        # CodeQL detects weak randomness in security context
        return ''.join(random.choices(string.ascii_letters, k=32))

    def generate_session_id(self):
        """Used for session management - security critical"""
        return self.generate_token()

# 9. Race Condition in Security Check
import threading
import time

class AccessController:
    def __init__(self):
        self.authorized_users = set()
        self.lock = threading.Lock()

    def check_and_authorize(self, user_id, resource):
        """TOCTOU vulnerability - race condition"""
        # Check permission (Time-of-check)
        if self.has_permission(user_id, resource):
            # Delay simulates processing time
            time.sleep(0.01)

            # Use permission (Time-of-use)
            # Another thread might have revoked permission!
            # CodeQL detects this TOCTOU pattern
            return self.access_resource(user_id, resource)

        return None

    def has_permission(self, user_id, resource):
        with self.lock:
            return user_id in self.authorized_users

    def access_resource(self, user_id, resource):
        # Access granted without rechecking
        return f"Access granted to {resource}"

    def revoke_permission(self, user_id):
        with self.lock:
            self.authorized_users.discard(user_id)

# 10. XML External Entity (XXE) Injection
import xml.etree.ElementTree as ET

class XMLProcessor:
    def parse_user_xml(self, xml_data):
        """XXE vulnerability - allows external entity processing"""
        try:
            # Sink: Unsafe XML parsing allows XXE
            # CodeQL detects unsafe XML parsing with user input
            root = ET.fromstring(xml_data)
            return self.process_xml(root)
        except:
            return None

    def process_xml(self, root):
        # Process parsed XML - might expose sensitive files
        results = []
        for child in root:
            results.append(child.text)
        return results

if __name__ == "__main__":
    # These vulnerabilities require semantic analysis to detect
    # Simple pattern matching would miss most of them
    print("Complex vulnerability examples for CodeQL testing")