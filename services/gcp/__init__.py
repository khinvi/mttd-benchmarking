"""
Google Cloud Platform (GCP) service integration for the MTTD Benchmarking Framework.
"""

from .platform import PlatformClient
from .security import SecurityClient as SecurityCommandClient

# Export main classes
__all__ = [
    "PlatformClient",
    "SecurityCommandClient"
]