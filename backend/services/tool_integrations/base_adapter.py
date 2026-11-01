"""Base abstract class for ForensicX external tool integrations."""

from abc import ABC, abstractmethod
from typing import Any


class BaseToolAdapter(ABC):
    """Abstract interface that all forensic tool adapters must implement."""

    @property
    @abstractmethod
    def tool_id(self) -> str:
        """Unique machine identifier (e.g. 'adb', 'autopsy', 'cellebrite', 'ios_backup')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Display name of the tool as listed in the project architecture."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Functional forensic category."""
        pass

    @property
    @abstractmethod
    def poster_reference(self) -> str:
        """Poster reference (e.g. 'Tool 1: Android Debug Bridge (ADB)')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Concise description of the integration capabilities."""
        pass

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """Detect and return current installation, licensing, and operational status.
        
        Must never claim a tool is installed or licensed when it is not.
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> list[str]:
        """List human-readable capabilities of this integration."""
        pass
