#!/usr/bin/env python3
"""
IP Address Service - Configuration Management
Centralized configuration handling for different deployment environments.
Supports development, staging, and production configurations with robust error handling.
"""

import os
import sys
from typing import Dict, Any, List, Optional

# Try to load dotenv, but don't fail if not available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not available, continue without it
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass

class BaseConfig:
    """
    Base configuration class with common settings and robust defaults.
    All environment-specific configs inherit from this class.
    """
    
    # Flask Core Settings with secure defaults
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Application Settings
    APP_NAME = 'IP Address Service'
    APP_VERSION = '1.1.0'
    
    # Server Configuration with safe defaults
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', '5000'))
    
    # Proxy Configuration - adjust based on your reverse proxy setup
    # Caddy typically adds 1 proxy layer, so x_for=1 is usually correct
    PROXY_COUNT = int(os.getenv('PROXY_COUNT', '1'))
    
    # Logging Configuration with robust defaults
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.getenv('LOG_FILE', '/opt/ip-service/logs/ip_service.log')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', '10485760'))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Security Headers - comprehensive set for production
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none';",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'false').lower() == 'true'
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))
    
    # Trusted Proxy Networks (CIDR notation) with comprehensive defaults
    # Add your Caddy server's IP range here for additional security
    _default_proxies = '127.0.0.1/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
    TRUSTED_PROXIES = os.getenv('TRUSTED_PROXIES', _default_proxies).split(',')
    
    # IP Detection Settings
    MAX_PROXY_HEADERS = int(os.getenv('MAX_PROXY_HEADERS', '10'))
    ENABLE_DEBUG_HEADERS = os.getenv('ENABLE_DEBUG_HEADERS', 'false').lower() == 'true'
    
    # Performance Settings
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', '1024'))  # 1KB max request
    
    @classmethod
    def validate_config(cls) -> List[str]:
        """
        Validate configuration and return list of issues found.
        
        Returns:
            List[str]: List of configuration issues (empty if valid)
        """
        issues = []
        
        # Validate basic settings
        if not isinstance(cls.PORT, int) or cls.PORT < 1 or cls.PORT > 65535:
            issues.append("PORT must be a valid integer between 1 and 65535")
        
        if not cls.HOST:
            issues.append("HOST cannot be empty")
        
        if cls.PROXY_COUNT < 0:
            issues.append("PROXY_COUNT cannot be negative")
        
        if cls.LOG_LEVEL not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            issues.append("LOG_LEVEL must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL")
        
        # Validate trusted proxies format
        try:
            import ipaddress
            for proxy in cls.TRUSTED_PROXIES:
                proxy = proxy.strip()
                if proxy and '/' in proxy:
                    ipaddress.IPv4Network(proxy, strict=False)
                elif proxy:
                    ipaddress.IPv4Address(proxy)
        except (ipaddress.AddressValueError, ValueError) as e:
            issues.append(f"Invalid TRUSTED_PROXIES format: {str(e)}")
        except ImportError:
            # ipaddress module not available, skip validation
            pass
        
        return issues
    
    @classmethod
    def get_gunicorn_config(cls) -> Dict[str, Any]:
        """
        Generate Gunicorn configuration dictionary with robust defaults.
        
        Returns:
            dict: Gunicorn configuration parameters
        """
        # Calculate optimal worker count based on CPU cores
        try:
            import multiprocessing
            default_workers = multiprocessing.cpu_count() * 2 + 1
        except (ImportError, NotImplementedError):
            default_workers = 4
        
        # Get worker count from environment with fallback
        workers = int(os.getenv('GUNICORN_WORKERS', str(default_workers)))
        
        return {
            'bind': f"{cls.HOST}:{cls.PORT}",
            'workers': workers,
            'worker_class': os.getenv('GUNICORN_WORKER_CLASS', 'sync'),
            'worker_connections': int(os.getenv('GUNICORN_WORKER_CONNECTIONS', '1000')),
            'max_requests': int(os.getenv('GUNICORN_MAX_REQUESTS', '1000')),
            'max_requests_jitter': int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', '100')),
            'timeout': int(os.getenv('GUNICORN_TIMEOUT', '30')),
            'keepalive': int(os.getenv('GUNICORN_KEEPALIVE', '5')),
            'graceful_timeout': int(os.getenv('GUNICORN_GRACEFUL_TIMEOUT', '30')),
            'preload_app': True,
            'accesslog': os.getenv('GUNICORN_ACCESS_LOG', '/opt/ip-service/logs/access.log'),
            'errorlog': os.getenv('GUNICORN_ERROR_LOG', '/opt/ip-service/logs/error.log'),
            'loglevel': os.getenv('GUNICORN_LOG_LEVEL', 'info').lower(),
            'capture_output': True,
            'enable_stdio_inheritance': True,
            'forwarded_allow_ips': os.getenv('GUNICORN_FORWARDED_ALLOW_IPS', '*'),
            'proxy_protocol': os.getenv('GUNICORN_PROXY_PROTOCOL', 'false').lower() == 'true',
            'worker_tmp_dir': os.getenv('GUNICORN_WORKER_TMP_DIR', '/tmp'),
            'proc_name': 'ip-address-service',
            'limit_request_line': 4094,
            'limit_request_fields': 100,
            'limit_request_field_size': 8190
        }

class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration.
    Includes debug settings and verbose logging for development work.
    """
    
    DEBUG = True
    TESTING = False
    LOG_LEVEL = 'DEBUG'
    
    # Development-specific settings
    FLASK_ENV = 'development'
    INCLUDE_DEBUG_INFO = True
    ENABLE_DEBUG_HEADERS = True
    
    # Relaxed security for development
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-cache'
    }
    
    # Development server settings
    HOST = os.getenv('HOST', '127.0.0.1')
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-not-for-production-use')

class ProductionConfig(BaseConfig):
    """
    Production environment configuration.
    Optimized for security, performance, and stability in production environments.
    """
    
    DEBUG = False
    TESTING = False
    
    # Production-specific settings
    FLASK_ENV = 'production'
    INCLUDE_DEBUG_INFO = False
    ENABLE_DEBUG_HEADERS = False
    
    # Enhanced security in production
    SECRET_KEY = os.getenv('SECRET_KEY')
    
    # Production logging with more conservative defaults
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'WARNING')
    
    # Production performance settings
    MAX_CONTENT_LENGTH = 512  # Smaller limit for production
    
    @classmethod
    def validate_production_config(cls) -> None:
        """
        Validate that all required production settings are properly configured.
        Raises ConfigurationError if critical settings are missing or invalid.
        """
        issues = cls.validate_config()
        
        # Additional production-specific validation
        if not cls.SECRET_KEY or cls.SECRET_KEY in [
            'dev-secret-key-change-in-production',
            'dev-secret-key-not-for-production-use'
        ]:
            issues.append("SECRET_KEY must be set to a secure value for production deployment")
        
        if len(cls.SECRET_KEY) < 32:
            issues.append("SECRET_KEY should be at least 32 characters long for production")
        
        # Validate that we're not running with development defaults
        if cls.DEBUG:
            issues.append("DEBUG must be False in production")
        
        if cls.HOST == '0.0.0.0' and not os.getenv('ALLOW_EXTERNAL_ACCESS'):
            issues.append("HOST=0.0.0.0 requires ALLOW_EXTERNAL_ACCESS=true for security")
        
        if issues:
            raise ConfigurationError(
                f"Production configuration validation failed:\n" + 
                "\n".join(f"  - {issue}" for issue in issues)
            )

class StagingConfig(BaseConfig):
    """
    Staging environment configuration.
    Similar to production but with additional debugging capabilities for testing.
    """
    
    DEBUG = False
    TESTING = False
    FLASK_ENV = 'staging'
    INCLUDE_DEBUG_INFO = True
    ENABLE_DEBUG_HEADERS = True
    
    # Staging-specific logging (more verbose than production)
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # Use production-like security but allow some debugging
    SECRET_KEY = os.getenv('SECRET_KEY', 'staging-secret-key-change-me')

class TestingConfig(BaseConfig):
    """
    Testing environment configuration.
    Optimized for automated testing with fast performance and comprehensive logging.
    """
    
    DEBUG = False
    TESTING = True
    FLASK_ENV = 'testing'
    INCLUDE_DEBUG_INFO = True
    ENABLE_DEBUG_HEADERS = True
    
    # Testing-specific settings
    LOG_LEVEL = 'DEBUG'
    SECRET_KEY = 'testing-secret-key-not-secure'
    HOST = '127.0.0.1'
    PORT = 5001  # Different port to avoid conflicts
    
    # Disable security headers for easier testing
    SECURITY_HEADERS = {}
    
    # Fast timeouts for testing
    REQUEST_TIMEOUT = 5
    
    @classmethod
    def get_gunicorn_config(cls) -> Dict[str, Any]:
        """Override for testing with minimal workers."""
        config = super().get_gunicorn_config()
        config.update({
            'workers': 1,
            'timeout': 5,
            'accesslog': '-',  # stdout
            'errorlog': '-',   # stderr
        })
        return config

# Configuration mapping with all available environments
config_mapping = {
    'development': DevelopmentConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(environment: Optional[str] = None) -> BaseConfig:
    """
    Get configuration class based on environment with comprehensive error handling.
    
    Args:
        environment: Environment name (development, staging, production, testing)
        
    Returns:
        BaseConfig: Configuration class instance
        
    Raises:
        ConfigurationError: If configuration validation fails
    """
    if environment is None:
        environment = os.getenv('FLASK_ENV', 'development').lower()
    
    # Normalize environment name
    environment = environment.lower().strip()
    
    # Get configuration class
    config_class = config_mapping.get(environment, config_mapping['default'])
    
    # Validate configuration based on environment
    try:
        if environment == 'production':
            config_class.validate_production_config()
        else:
            issues = config_class.validate_config()
            if issues:
                print(f"Configuration warnings for {environment}:", file=sys.stderr)
                for issue in issues:
                    print(f"  - {issue}", file=sys.stderr)
    except Exception as e:
        if environment == 'production':
            raise ConfigurationError(f"Configuration validation failed: {str(e)}")
        else:
            print(f"Configuration warning: {str(e)}", file=sys.stderr)
    
    return config_class

def print_config_summary(config_class: BaseConfig) -> None:
    """
    Print a summary of the current configuration for debugging.
    
    Args:
        config_class: Configuration class to summarize
    """
    print("=== IP Address Service Configuration Summary ===")
    print(f"Environment: {getattr(config_class, 'FLASK_ENV', 'unknown')}")
    print(f"Host: {config_class.HOST}")
    print(f"Port: {config_class.PORT}")
    print(f"Debug: {getattr(config_class, 'DEBUG', False)}")
    print(f"Log Level: {config_class.LOG_LEVEL}")
    print(f"Proxy Count: {config_class.PROXY_COUNT}")
    print(f"Trusted Proxies: {len(config_class.TRUSTED_PROXIES)} networks")
    print("=" * 45)

# Module-level configuration for easy import
try:
    current_config = get_config()
except Exception as e:
    print(f"Warning: Configuration error: {e}", file=sys.stderr)
    current_config = DevelopmentConfig()

# Export commonly used settings
APP_NAME = current_config.APP_NAME
APP_VERSION = current_config.APP_VERSION
SECRET_KEY = current_config.SECRET_KEY
HOST = current_config.HOST
PORT = current_config.PORT

if __name__ == '__main__':
    # Configuration testing and debugging
    import sys
    
    env = sys.argv[1] if len(sys.argv) > 1 else None
    
    try:
        config = get_config(env)
        print_config_summary(config)
        
        print("\nGunicorn Configuration:")
        gunicorn_config = config.get_gunicorn_config()
        for key, value in sorted(gunicorn_config.items()):
            print(f"  {key}: {value}")
            
        print(f"\nConfiguration loaded successfully for environment: {env or 'default'}")
        
    except ConfigurationError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
