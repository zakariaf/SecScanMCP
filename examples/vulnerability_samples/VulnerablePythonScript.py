import os
import subprocess
import requests
from flask import Flask, request

app = Flask(__name__)

# Vulnerability 1: Insecure Use of Subprocess (Command Injection)
@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip', '')
    result = subprocess.check_output(['ping', '-c', '4', ip])
    return result

# Vulnerability 2: Hardcoded Credentials
USERNAME = 'admin'
PASSWORD = 'password123'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == USERNAME and password == PASSWORD:
        return "Login successful"
    else:
        return "Login failed", 401

# Vulnerability 3: Insecure Deserialization
@app.route('/unserialize', methods=['POST'])
def unserialize():
    import pickle
    data = request.data
    obj = pickle.loads(data)
    return str(obj)

# Vulnerability 4: Use of Outdated Library with Known Vulnerabilities
@app.route('/requests_example', methods=['GET'])
def requests_example():
    response = requests.get('https://example.com')
    return response.content

# Vulnerability 5: SQL Injection
@app.route('/user', methods=['GET'])
def get_user():
    user_id = request.args.get('id', '')
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    result = run_query(query)  # This function is not defined but simulates a database query
    return str(result)

def run_query(query):
    # Simulating a database query without proper sanitization (SQL Injection risk)
    return "Query result for: " + query

if __name__ == '__main__':
    app.run(debug=True)
