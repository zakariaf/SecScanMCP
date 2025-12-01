"""Base transport protocol for MCP communication."""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional
from dataclasses import dataclass, asdict
from typing import Dict, Any, Union
import uuid

logger = logging.getLogger(__name__)


class MCPTransport(Enum):
    """MCP transport types."""
    STDIO = "stdio"
    SSE = "sse"
    WEBSOCKET = "websocket"


@dataclass
class MCPRequest:
    """MCP JSON-RPC 2.0 Request."""
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    method: str = ""
    params: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.id is None:
            self.id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MCPResponse:
    """MCP JSON-RPC 2.0 Response."""
    jsonrpc: str
    id: Union[str, int]
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None


class BaseTransport(ABC):
    """Abstract base class for MCP transports."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.connected = False

    @abstractmethod
    async def connect(self, endpoint: str, **kwargs) -> bool:
        """Connect to MCP server."""
        pass

    @abstractmethod
    async def send(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Send request and receive response."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from server."""
        pass
