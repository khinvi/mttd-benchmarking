"""
Service integration layer for the MTTD Benchmarking Framework.

This package contains clients for interacting with different cloud platforms
and security services, providing a standardized interface for the framework.
"""

from .factory import get_platform_client, get_security_client

# Export factory functions
__all__ = [
    "get_platform_client",
    "get_security_client"
]