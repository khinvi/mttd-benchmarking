"""
Generic client implementations for the MTTD Benchmarking Framework.

These clients provide fallback implementations when specific
cloud service clients are not available or applicable.
"""

from .client import GenericPlatformClient, GenericSecurityClient

# Export main classes
__all__ = [
    "GenericPlatformClient",
    "GenericSecurityClient"
]