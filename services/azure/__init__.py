"""
Azure service integration for the MTTD Benchmarking Framework.
"""

from .platform import PlatformClient
from .sentinel import SecurityClient as SentinelClient

# Export main classes
__all__ = [
    "PlatformClient",
    "SentinelClient"
]