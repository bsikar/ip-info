#!/usr/bin/env python3
"""
IP Address Service - Configuration Management
Centralized configuration handling for different deployment environments.
Supports development, staging, and production configurations.
"""

import os
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

class BaseConfig:
    """
    Base configuration class with common settings.
    All environment-specific configs inherit from this class.
    """
    
    # Flask Core Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # Application Settings
    APP_NAME = 'IP Address Service'
    APP_VERSION = '1.0.0'
    
    # Server Configuration
    HOST = os.getenv('HOST', '127.0.0.1')
    PORT = int(os.getenv('PORT', 5000))
    
    # Proxy Configuration - adjust based on your reverse proxy setup
    # Caddy typically adds 1 proxy layer, so x_for=1 is usually correct
    PROXY_COUNT = int(os.getenv('PROXY_COUNT', 1))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'ip_service.log')
    LOG_MAX_BYTES = int(os.getenv('LOG_MAX_BYTES', 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 5))
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none';"
    }
    
    # Rate Limiting (if implemented)
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'false').lower() == 'true'
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 60))
    
    # Trusted Proxy Networks (CIDR notation)
    # Add your Caddy server's IP range here for additional security
    TRUSTED_PROXIES = os.getenv('TRUSTED_PROXIES', '127.0.0.1/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16').split(',')
    
    @classmethod
    def get_gunicorn_config(cls) -> Dict[str, Any]:
        """
        Generate Gunicorn configuration dictionary.
        
        Returns:
            dict: Gunicorn configuration parameters
        """
        return {
            'bind': f"{cls.HOST}:{cls.PORT}",
            'workers': int(os.getenv('GUNICORN_WORKERS', 4)),
            'worker_class': 'sync',
            'worker_connections': int(os.getenv('GUNICORN_WORKER_CONNECTIONS', 1000)),
            'max_requests': int(os.getenv('GUNICORN_MAX_REQUESTS', 1000)),
            'max_requests_jitter': int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', 100)),
            'timeout': int(os.getenv('GUNICORN_TIMEOUT', 30)),
            'keepalive': int(os.getenv('GUNICORN_KEEPALIVE', 2)),
            'preload_app': True,
            'accesslog': os.getenv('GUNICORN_ACCESS_LOG', '-'),
            'errorlog': os.getenv('GUNICORN_ERROR_LOG', '-'),
            'loglevel': os.getenv('GUNICORN_LOG_LEVEL', 'info').lower(),
            'capture_output': True,
            'enable_stdio_inheritance': True
        }

class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration.
    Includes debug settings and verbose logging.
    """
    
    DEBUG = True
    TESTING = False
    LOG_LEVEL = 'DEBUG'
    
    # Development-specific settings
    FLASK_ENV = 'development'
    INCLUDE_DEBUG_INFO = True
    
    # Disable some security features for easier development
    SECURITY_HEADERS = {}

class ProductionConfig(BaseConfig):
    """
    Production environment configuration.
    Optimized for security, performance, and stability.
    """
    
    DEBUG = False
    TESTING = False
    
    # Production-specific settings
    FLASK_ENV = 'production'
    INCLUDE_DEBUG_INFO = False
    
    # Enhanced security in production
    SECRET_KEY = os.getenv('SECRET_KEY')  # Must be set in production
    
    # Production logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'WARNING')
    
    @classmethod
    def validate_production_config(cls):
        """
        Validate that all required production settings are configured.
        Raises ValueError if critical settings are missing.
        """
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev-secret-key-change-in-production':
            raise ValueError("SECRET_KEY must be set for production deployment")
        
        # Validate other critical settings
        required_env_vars = ['HOST', 'PORT']
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

class StagingConfig(BaseConfig):
    """
    Staging environment configuration.
    Similar to production but with additional debugging capabilities.
    """
    
    DEBUG = False
    TESTING = False
    FLASK_ENV = 'staging'
    INCLUDE_DEBUG_INFO = True
    
    # Staging-specific logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Configuration mapping
config_mapping = {
    'development': DevelopmentConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config(environment: str = None) -> BaseConfig:
    """
    Get configuration class based on environment.
    
    Args:
        environment: Environment name (development, staging, production)
        
    Returns:
        BaseConfig: Configuration class instance
    """
    if environment is None:
        environment = os.getenv('FLASK_ENV', 'development')
    
    config_class = config_mapping.get(environment, config_mapping['default'])
    
    # Validate production configuration
    if environment == 'production':
        config_class.validate_production_config()
    
    return config_class

