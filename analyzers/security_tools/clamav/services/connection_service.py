"""
ClamAV Connection Service

Manages TCP connections to ClamAV daemon with robust error handling
Following clean architecture with single responsibility
"""

import asyncio
import socket
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class ConnectionService:
    """Manages ClamAV daemon connections and communication"""
    
    # ClamAV connection settings
    CLAMD_HOST = os.environ.get('CLAMAV_HOST', 'clamav')  # Docker service name
    CLAMD_PORT = int(os.environ.get('CLAMAV_PORT', 3310))
    CLAMD_TIMEOUT = 300  # 5 minutes for large files
    
    def __init__(self):
        self._socket: Optional[socket.socket] = None
        self._connected = False
    
    async def connect(self) -> bool:
        """Connect to ClamAV daemon via TCP"""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.CLAMD_TIMEOUT)
            
            # Try connection with retries
            return await self._attempt_connection()
            
        except Exception as e:
            logger.error(f"Failed to connect to ClamAV: {e}")
            return False
    
    async def disconnect(self):
        """Safely disconnect from ClamAV daemon"""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Socket close error: {e}")
            finally:
                self._socket = None
                self._connected = False
    
    async def send_command(self, command: str) -> str:
        """Send command to ClamAV daemon and get response"""
        if not self._connected or not self._socket:
            raise ConnectionError("Not connected to ClamAV daemon")
        
        try:
            # Send command with proper encoding
            self._socket.send(f"z{command}\0".encode())
            
            # Receive response
            response = self._socket.recv(4096).decode().strip()
            if response.endswith('\0'):
                response = response[:-1]
            
            return response
            
        except Exception as e:
            logger.error(f"Command failed: {e}")
            await self.disconnect()
            raise
    
    async def ping(self) -> bool:
        """Test ClamAV daemon connectivity"""
        try:
            response = await self.send_command("PING")
            return response == "PONG"
        except Exception:
            return False
    
    async def get_version(self) -> str:
        """Get ClamAV daemon version"""
        try:
            return await self.send_command("VERSION")
        except Exception as e:
            logger.warning(f"Could not get ClamAV version: {e}")
            return "unknown"
    
    async def _attempt_connection(self) -> bool:
        """Attempt connection with retries"""
        max_retries = 5
        
        for retry in range(max_retries):
            try:
                self._socket.connect((self.CLAMD_HOST, self.CLAMD_PORT))
                self._connected = True
                
                # Verify connection with ping
                if await self.ping():
                    version = await self.get_version()
                    logger.info(f"Connected to ClamAV: {version}")
                    return True
                    
            except ConnectionRefusedError:
                if retry < max_retries - 1:
                    logger.info(f"ClamAV connection attempt {retry + 1} failed, retrying...")
                    await asyncio.sleep(2 ** retry)  # Exponential backoff
                else:
                    logger.error("ClamAV daemon not available")
        
        return False