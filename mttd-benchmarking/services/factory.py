"""
Factory for creating platform and security service clients.
"""

import logging
import importlib
from typing import Dict, Any, Optional

from ..core.types import CloudProvider

logger = logging.getLogger(__name__)


def get_platform_client(provider: CloudProvider, config: Dict[str, Any] = None, region: str = None) -> Any:
    """
    Get a platform client for the specified cloud provider.
    
    Args:
        provider: Cloud provider (AWS, Azure, GCP)
        config: Configuration for the client
        region: Cloud region
        
    Returns:
        Platform client instance
    """
    # Initialize config if not provided
    if config is None:
        config = {}
    
    # Update config with region if provided
    if region:
        config_with_region = config.copy()
        config_with_region["region"] = region
    else:
        config_with_region = config
    
    # Map providers to module paths
    provider_modules = {
        CloudProvider.AWS: "mttd_benchmarking.services.aws.platform",
        CloudProvider.AZURE: "mttd_benchmarking.services.azure.platform",
        CloudProvider.GCP: "mttd_benchmarking.services.gcp.platform"
    }
    
    # Get module path
    module_path = provider_modules.get(provider)
    
    if not module_path:
        raise ValueError(f"Unsupported cloud provider: {provider}")
    
    try:
        # Import the module
        module = importlib.import_module(module_path)
        
        # Get the client class
        client_class = getattr(module, "PlatformClient")
        
        # Create and return client instance
        return client_class(config_with_region)
        
    except (ImportError, AttributeError) as e:
        logger.error(f"Failed to load platform client for {provider}: {str(e)}")
        
        # Try to use generic client as fallback
        try:
            generic_module = importlib.import_module("mttd_benchmarking.services.generic.client")
            generic_class = getattr(generic_module, "GenericPlatformClient")
            logger.warning(f"Using generic platform client for {provider}")
            
            # Add provider to config for generic client
            config_with_region["provider"] = provider.value
            
            return generic_class(config_with_region)
        except Exception as fallback_e:
            logger.error(f"Failed to load generic platform client: {str(fallback_e)}")
            raise ValueError(f"Could not load any platform client for {provider}")


def get_security_client(
    service_name: str, 
    provider: CloudProvider = None, 
    config: Dict[str, Any] = None,
    region: str = None
) -> Any:
    """
    Get a security service client.
    
    Args:
        service_name: Name of the security service
        provider: Cloud provider
        config: Configuration for the client
        region: Cloud region
        
    Returns:
        Security service client instance
    """
    # Initialize config if not provided
    if config is None:
        config = {}
        
    # Update config with region if provided
    if region:
        config_with_region = config.copy()
        config_with_region["region"] = region
    else:
        config_with_region = config
    
    # Infer provider from service name if not provided
    if provider is None:
        if service_name.startswith("aws_"):
            provider = CloudProvider.AWS
        elif service_name.startswith("azure_"):
            provider = CloudProvider.AZURE
        elif service_name.startswith("gcp_"):
            provider = CloudProvider.GCP
        else:
            # Default to AWS
            provider = CloudProvider.AWS
    
    # Add provider to config for the client
    config_with_region["provider"] = provider.value
    
    # Map service names to module paths
    service_modules = {
        # AWS security services
        "aws_guardduty": "mttd_benchmarking.services.aws.guardduty",
        "aws_securityhub": "mttd_benchmarking.services.aws.securityhub",
        "aws_detective": "mttd_benchmarking.services.aws.detective",
        
        # Azure security services
        "azure_sentinel": "mttd_benchmarking.services.azure.sentinel",
        "azure_defender": "mttd_benchmarking.services.azure.defender",
        "azure_security_center": "mttd_benchmarking.services.azure.security_center",
        
        # GCP security services
        "gcp_security_command": "mttd_benchmarking.services.gcp.security",
        "gcp_cloud_ids": "mttd_benchmarking.services.gcp.cloud_ids",
        
        # Third-party services
        "third_party_service": "mttd_benchmarking.services.third_party.generic"
    }
    
    # Get module path
    module_path = service_modules.get(service_name.lower())
    
    if module_path:
        try:
            # Import the module
            module = importlib.import_module(module_path)
            
            # Get the client class
            client_class = getattr(module, "SecurityClient")
            
            # Create and return client instance
            return client_class(config_with_region)
            
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load security client for {service_name}: {str(e)}")
            # Fall through to provider-specific generic client
    
    # Try provider-specific generic security client
    provider_generic_modules = {
        CloudProvider.AWS: "mttd_benchmarking.services.aws.generic",
        CloudProvider.AZURE: "mttd_benchmarking.services.azure.generic",
        CloudProvider.GCP: "mttd_benchmarking.services.gcp.generic"
    }
    
    module_path = provider_generic_modules.get(provider)
    
    if module_path:
        try:
            # Import the module
            module = importlib.import_module(module_path)
            
            # Get the client class
            client_class = getattr(module, "GenericSecurityClient")
            
            # Update config with service name
            config_with_region["service_name"] = service_name
            
            # Create and return client instance
            logger.warning(f"Using generic {provider.value} security client for {service_name}")
            return client_class(config_with_region)
            
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load generic {provider.value} security client: {str(e)}")
            # Fall through to fully generic client
    
    # As last resort, try fully generic client
    try:
        generic_module = importlib.import_module("mttd_benchmarking.services.generic.client")
        generic_class = getattr(generic_module, "GenericSecurityClient")
        
        # Update config with service name
        config_with_region["service_name"] = service_name
        
        logger.warning(f"Using fully generic security client for {service_name}")
        return generic_class(config_with_region)
    except Exception as fallback_e:
        logger.error(f"Failed to load fully generic security client: {str(fallback_e)}")
        raise ValueError(f"Could not load any security client for {service_name}")