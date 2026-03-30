from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from app.core.models import ScanRequest, ScanResult


class SecurityTool(Protocol):
    name: str

    def scan(self, request: ScanRequest) -> ScanResult:
        ...


class BaseTool(ABC):
    name: str

    @abstractmethod
    def scan(self, request: ScanRequest) -> ScanResult:
        raise NotImplementedError


class PluginManager:
    """Registers tools so Cadmux Security can scale with additional plugins."""

    def __init__(self) -> None:
        self._tools: dict[str, SecurityTool] = {}

    def register(self, tool: SecurityTool) -> None:
        self._tools[tool.name] = tool

    def get(self, tool_name: str) -> SecurityTool:
        if tool_name not in self._tools:
            known = ", ".join(sorted(self._tools)) or "none"
            raise KeyError(f"Tool '{tool_name}' is not registered. Available: {known}")
        return self._tools[tool_name]

    def list_tools(self) -> list[str]:
        return sorted(self._tools)
