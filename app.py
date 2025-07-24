#!/usr/bin/env python3
"""
IP Address Service - Main Application
A lightweight web service that returns client IP addresses in JSON format,
similar to ipinfo.io functionality. Designed to work behind reverse proxies
like Caddy, Nginx, or Apache with comprehensive error handling and logging.
"""

import json
import logging
import ipaddress
import re
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
from flask import Flask, request, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix

# Add current directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import configuration with error handling
try:
    from config import get_config, ConfigurationError, current_config
    config = current_config
except ImportError as e:
    print(f"Warning: Could not import config module: {e}", file=sys.stderr)
    print("Using minimal default configuration", file=sys.stderr)
    
    # Minimal configuration fallback
    class MinimalConfig:
        SECRET_KEY = os.getenv('SECRET_KEY', 'fallback-secret-key')
        HOST = os.getenv('HOST', '127.0.0.1')
        PORT = int(os.getenv('PORT', '5000'))
        LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
        PROXY_COUNT = int(os.getenv('PROXY_COUNT', '1'))
        FLASK_ENV = os.getenv('FLASK_ENV', 'production')
        DEBUG = FLASK_ENV == 'development'
        TRUSTED_PROXIES = ['127.0.0.1/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        SECURITY_HEADERS = {
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        }
    
    config = MinimalConfig()

# Configure logging with robust error handling
def setup_logging():
    """Setup logging configuration with fallback handling."""
    try:
        log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
        log_file = getattr(config, 'LOG_FILE', 'ip_service.log')
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file) if '/' in log_file else '.'
        if log_dir and log_dir != '.' and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except PermissionError:
                # Fall back to current directory
                log_file = 'ip_service.log'
        
        # Configure logging
        handlers = [logging.StreamHandler(sys.stdout)]
        
        try:
            # Try to add file handler
            handlers.append(logging.FileHandler(log_file))
        except (PermissionError, OSError) as e:
            print(f"Warning: Could not create log file {log_file}: {e}", file=sys.stderr)
            print("Logging to stdout only", file=sys.stderr)
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers,
            force=True  # Override any existing configuration
        )
        
    except Exception as e:
        # Ultimate fallback - basic logging to stdout
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            stream=sys.stdout,
            force=True
        )
        print(f"Warning: Error setting up logging: {e}", file=sys.stderr)

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

class IPAddressService:
    """
    Core service class for extracting and validating client IP addresses.
    Handles various proxy scenarios and provides comprehensive IP detection
    with improved error handling and security.
    """
    
    # Trusted proxy headers in order of preference
    PROXY_HEADERS = [
        'X-Forwarded-For',      # Standard proxy header (most common)
        'X-Real-IP',            # Nginx/Caddy common header
        'X-Client-IP',          # Alternative proxy header
        'CF-Connecting-IP',     # Cloudflare header
        'True-Client-IP',       # Akamai header
        'X-Forwarded',          # Less common variant
        'Forwarded-For',        # RFC 7239 variant
        'Forwarded'             # RFC 7239 standard
    ]
    
    # Private/internal IP ranges (RFC 1918, RFC 4193, etc.)
    PRIVATE_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),       # Class A private
        ipaddress.IPv4Network('172.16.0.0/12'),    # Class B private
        ipaddress.IPv4Network('192.168.0.0/16'),   # Class C private
        ipaddress.IPv4Network('127.0.0.0/8'),      # Loopback
        ipaddress.IPv4Network('169.254.0.0/16'),   # Link-local
        ipaddress.IPv4Network('224.0.0.0/4'),      # Multicast
        ipaddress.IPv4Network('240.0.0.0/4'),      # Reserved
        ipaddress.IPv4Network('0.0.0.0/8'),        # "This" network
        ipaddress.IPv4Network('100.64.0.0/10'),    # RFC 6598 Carrier Grade NAT
    ]
    
    def __init__(self):
        """Initialize the IP address service with logging configuration."""
        logger.info("Initializing IP Address Service v%s", getattr(config, 'APP_VERSION', '1.1.0'))
        logger.info("Configuration: Host=%s, Port=%s, Debug=%s", 
                   config.HOST, config.PORT, getattr(config, 'DEBUG', False))
        
    def is_private_ip(self, ip_str: str) -> bool:
        """
        Check if the given IP address is private/internal.
        
        Args:
            ip_str: IP address string to check
            
        Returns:
            bool: True if IP is private, False if public
        """
        try:
            ip = ipaddress.IPv4Address(ip_str)
            is_private = any(ip in network for network in self.PRIVATE_RANGES)
            logger.debug(f"IP {ip_str} is {'private' if is_private else 'public'}")
            return is_private
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.warning(f"Invalid IP address format: {ip_str} - {e}")
            return True  # Treat invalid IPs as private for security
    
    def validate_ipv4(self, ip_str: str) -> bool:
        """
        Validate if string is a proper IPv4 address format.
        
        Args:
            ip_str: String to validate as IPv4
            
        Returns:
            bool: True if valid IPv4, False otherwise
        """
        if not ip_str or not isinstance(ip_str, str):
            return False
            
        try:
            # Basic format check first
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip_str):
                return False
                
            ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def sanitize_header_value(self, header_value: str) -> str:
        """
        Sanitize header value to prevent injection attacks.
        
        Args:
            header_value: Raw header value
            
        Returns:
            str: Sanitized header value
        """
        if not header_value:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[^\w\.,:\s-]', '', str(header_value))
        
        # Limit length to prevent memory attacks
        return sanitized[:500]
    
    def extract_ip_from_forwarded_header(self, header_value: str) -> Optional[str]:
        """
        Extract IP address from X-Forwarded-For or similar headers.
        These headers can contain multiple IPs separated by commas.
        
        Args:
            header_value: Value from proxy header
            
        Returns:
            str or None: First valid public IP found, or None
        """
        if not header_value:
            return None
        
        # Sanitize the header value
        header_value = self.sanitize_header_value(header_value)
        
        # Split by comma and strip whitespace
        ip_list = [ip.strip() for ip in header_value.split(',')]
        
        # Limit number of IPs to process to prevent DoS
        max_ips = getattr(config, 'MAX_PROXY_HEADERS', 10)
        ip_list = ip_list[:max_ips]
        
        for ip in ip_list:
            if not ip:
                continue
                
            # Remove port if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
            ip_clean = ip.split(':')[0].strip('[]"\'')
            
            if self.validate_ipv4(ip_clean) and not self.is_private_ip(ip_clean):
                logger.debug(f"Found valid public IP in header: {ip_clean}")
                return ip_clean
                
        return None
    
    def extract_ip_from_rfc7239_header(self, header_value: str) -> Optional[str]:
        """
        Extract IP from RFC 7239 Forwarded header format.
        Format: Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
        
        Args:
            header_value: RFC 7239 formatted header value
            
        Returns:
            str or None: Extracted public IP or None
        """
        if not header_value:
            return None
        
        # Sanitize header value
        header_value = self.sanitize_header_value(header_value)
        
        # Extract IP from for= parameter
        match = re.search(r'for=([^;,\s]+)', header_value, re.IGNORECASE)
        if match:
            ip = match.group(1).strip('"[]\'')
            
            # Handle IPv6 format in square brackets
            if ip.startswith('[') and ']' in ip:
                ip = ip.split(']')[0][1:]
            
            # Remove port if present
            if ':' in ip and not ip.count(':') > 1:  # Not IPv6
                ip = ip.split(':')[0]
            
            if self.validate_ipv4(ip) and not self.is_private_ip(ip):
                logger.debug(f"Found valid public IP in RFC 7239 header: {ip}")
                return ip
        
        return None
    
    def is_trusted_proxy(self, proxy_ip: str) -> bool:
        """
        Check if the proxy IP is in the trusted proxy list.
        
        Args:
            proxy_ip: IP address of the proxy
            
        Returns:
            bool: True if trusted, False otherwise
        """
        if not hasattr(config, 'TRUSTED_PROXIES'):
            return True  # Trust all if not configured
        
        try:
            proxy_addr = ipaddress.IPv4Address(proxy_ip)
            for trusted_network in config.TRUSTED_PROXIES:
                if '/' in trusted_network:
                    network = ipaddress.IPv4Network(trusted_network.strip(), strict=False)
                    if proxy_addr in network:
                        return True
                else:
                    trusted_addr = ipaddress.IPv4Address(trusted_network.strip())
                    if proxy_addr == trusted_addr:
                        return True
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.warning(f"Invalid proxy IP or trusted network format: {e}")
        
        return False
    
    def get_client_ip(self, request_obj) -> Optional[str]:
        """
        Extract the client's real IP address from the request with comprehensive validation.
        Checks proxy headers first, falls back to remote_addr.
        
        Args:
            request_obj: Flask request object
            
        Returns:
            str or None: Client's public IP address or None if not found
        """
        remote_addr = getattr(request_obj, 'remote_addr', 'unknown')
        logger.debug(f"Processing IP extraction. Remote addr: {remote_addr}")
        
        # Check if we trust the proxy
        if remote_addr and remote_addr != 'unknown':
            if not self.is_trusted_proxy(remote_addr):
                logger.warning(f"Untrusted proxy detected: {remote_addr}")
                # Still process but log the warning
        
        # Check proxy headers in order of preference
        for header in self.PROXY_HEADERS:
            header_value = request_obj.headers.get(header)
            if not header_value:
                continue
                
            logger.debug(f"Checking header {header}: {header_value[:100]}...")
            
            try:
                if header == 'Forwarded':
                    # RFC 7239 format
                    ip = self.extract_ip_from_rfc7239_header(header_value)
                else:
                    # Standard comma-separated format
                    ip = self.extract_ip_from_forwarded_header(header_value)
                
                if ip:
                    logger.info(f"Client IP extracted from {header}: {ip}")
                    return ip
                    
            except Exception as e:
                logger.error(f"Error processing header {header}: {str(e)}")
                continue
        
        # Fallback to direct connection IP
        if remote_addr and remote_addr != 'unknown':
            if self.validate_ipv4(remote_addr) and not self.is_private_ip(remote_addr):
                logger.info(f"Client IP from direct connection: {remote_addr}")
                return remote_addr
        
        logger.warning("No valid public IP address found in request")
        return None
    
    def generate_response(self, ip_address: Optional[str], request_obj, error_message: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate the JSON response with IP information and comprehensive metadata.
        
        Args:
            ip_address: The detected IP address
            request_obj: Flask request object for additional context
            error_message: Optional custom error message
            
        Returns:
            dict: Response data structure
        """
        # Generate timestamp with timezone info
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        
        response_data = {
            "ip": ip_address,
            "timestamp": timestamp,
            "status": "success" if ip_address else "error"
        }
        
        if not ip_address:
            response_data["error"] = error_message or "Unable to determine public IP address"
            response_data["message"] = "No valid public IPv4 address found in request"
        
        # Add debug information in development mode or if explicitly enabled
        include_debug = (getattr(config, 'FLASK_ENV', '') == 'development' or 
                        getattr(config, 'ENABLE_DEBUG_HEADERS', False))
        
        if include_debug:
            debug_info = {
                "remote_addr": getattr(request_obj, 'remote_addr', 'unknown'),
                "user_agent": request_obj.headers.get('User-Agent', 'Unknown')[:200],
                "method": request_obj.method,
                "path": request_obj.path
            }
            
            # Add proxy headers for debugging
            proxy_headers = {}
            for header in self.PROXY_HEADERS:
                value = request_obj.headers.get(header)
                if value:
                    proxy_headers[header] = value[:100]  # Truncate for safety
            
            if proxy_headers:
                debug_info["proxy_headers"] = proxy_headers
            
            response_data["debug"] = debug_info
        
        return response_data


# Initialize Flask application with proper error handling
def create_app():
    """Create and configure Flask application."""
    app = Flask(__name__)
    
    # Configure Flask app for production use
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    app.config['MAX_CONTENT_LENGTH'] = getattr(config, 'MAX_CONTENT_LENGTH', 1024)
    
    # Set secret key
    app.config['SECRET_KEY'] = config.SECRET_KEY
    
    # Configure proxy handling - adjust num_proxies based on your setup
    proxy_count = getattr(config, 'PROXY_COUNT', 1)
    app.wsgi_app = ProxyFix(
        app.wsgi_app, 
        x_for=proxy_count, 
        x_proto=proxy_count, 
        x_host=proxy_count, 
        x_prefix=proxy_count
    )
    
    logger.info(f"Flask app configured with {proxy_count} proxy layers")
    return app

# Create the Flask app
app = create_app()

# Initialize service
ip_service = IPAddressService()

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    try:
        security_headers = getattr(config, 'SECURITY_HEADERS', {})
        for header, value in security_headers.items():
            response.headers[header] = value
    except Exception as e:
        logger.warning(f"Error adding security headers: {e}")
    
    return response

@app.route('/', methods=['GET'])
def get_ip():
    """
    Main endpoint for retrieving client IP address.
    Returns JSON with the client's public IPv4 address.
    """
    start_time = datetime.now(timezone.utc)
    client_ip = None
    request_id = id(request)  # Simple request ID for logging
    
    try:
        logger.debug(f"[{request_id}] Processing IP request from {request.remote_addr}")
        
        # Validate request method
        if request.method != 'GET':
            logger.warning(f"[{request_id}] Invalid method: {request.method}")
            return jsonify({
                "ip": None,
                "timestamp": start_time.isoformat().replace('+00:00', 'Z'),
                "status": "error",
                "error": "Method not allowed",
                "message": "Only GET requests are supported"
            }), 405
        
        # Extract client IP address
        client_ip = ip_service.get_client_ip(request)
        
        # Generate response
        response_data = ip_service.generate_response(client_ip, request)
        
        # Log the request with additional context
        user_agent = request.headers.get('User-Agent', 'Unknown')[:100]
        logger.info(f"[{request_id}] IP request completed - Client: {client_ip}, "
                   f"User-Agent: {user_agent}")
        
        # Create JSON response with proper headers
        response = jsonify(response_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        
        # Set appropriate HTTP status code
        status_code = 200 if client_ip else 422  # 422 = Unprocessable Entity
        response.status_code = status_code
        
        return response
        
    except Exception as e:
        logger.error(f"[{request_id}] Error processing IP request: {str(e)}", exc_info=True)
        
        error_response = {
            "ip": None,
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "status": "error",
            "error": "Internal server error",
            "message": "An error occurred while processing your request"
        }
        
        # Add error details in development mode
        if getattr(config, 'DEBUG', False):
            error_response["debug"] = {
                "error_type": type(e).__name__,
                "error_details": str(e)
            }
        
        return jsonify(error_response), 500
    
    finally:
        # Log request timing
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds() * 1000
        logger.debug(f"[{request_id}] Request processed in {duration:.2f}ms")

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and load balancer probes.
    Returns service status and basic metrics.
    """
    try:
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "service": getattr(config, 'APP_NAME', 'IP Address Service'),
            "version": getattr(config, 'APP_VERSION', '1.1.0'),
            "environment": getattr(config, 'FLASK_ENV', 'unknown')
        }
        
        # Add system information if in debug mode
        if getattr(config, 'DEBUG', False):
            import platform
            health_data["system"] = {
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "host": config.HOST,
                "port": config.PORT
            }
        
        response = jsonify(health_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}", exc_info=True)
        
        error_health = {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "error": str(e)
        }
        
        return jsonify(error_health), 500

@app.route('/info', methods=['GET'])
def service_info():
    """
    Service information endpoint providing API documentation and usage.
    """
    try:
        info_data = {
            "service": getattr(config, 'APP_NAME', 'IP Address Service'),
            "version": getattr(config, 'APP_VERSION', '1.1.0'),
            "description": "A lightweight web service that returns client IP addresses in JSON format",
            "endpoints": {
                "/": {
                    "method": "GET",
                    "description": "Returns the client's public IP address",
                    "response_format": {
                        "ip": "string|null",
                        "timestamp": "ISO8601 timestamp",
                        "status": "success|error"
                    }
                },
                "/health": {
                    "method": "GET",
                    "description": "Health check endpoint for monitoring",
                    "response_format": {
                        "status": "healthy|unhealthy",
                        "timestamp": "ISO8601 timestamp",
                        "service": "string",
                        "version": "string"
                    }
                },
                "/info": {
                    "method": "GET",
                    "description": "Service information and API documentation"
                }
            },
            "supported_headers": list(ip_service.PROXY_HEADERS),
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
        response = jsonify(info_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        return response
        
    except Exception as e:
        logger.error(f"Info endpoint error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors with JSON response."""
    logger.warning(f"404 error for path: {request.path} from {request.remote_addr}")
    
    error_response = {
        "status": "error",
        "error": "Not Found",
        "message": "The requested endpoint does not exist",
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "available_endpoints": ["/", "/health", "/info"]
    }
    
    response = jsonify(error_response)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response, 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors with JSON response."""
    logger.warning(f"405 error: {request.method} {request.path} from {request.remote_addr}")
    
    error_response = {
        "status": "error",
        "error": "Method Not Allowed",
        "message": f"The {request.method} method is not allowed for this endpoint",
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "allowed_methods": ["GET"]
    }
    
    response = jsonify(error_response)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response, 405

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle 413 errors with JSON response."""
    logger.warning(f"413 error: Request too large from {request.remote_addr}")
    
    error_response = {
        "status": "error",
        "error": "Request Entity Too Large",
        "message": "The request payload is too large",
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    }
    
    return jsonify(error_response), 413

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with JSON response."""
    logger.error(f"500 error: {str(error)} from {request.remote_addr}", exc_info=True)
    
    error_response = {
        "status": "error",
        "error": "Internal Server Error",
        "message": "An internal server error occurred",
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    }
    
    # Add debug information in development
    if getattr(config, 'DEBUG', False):
        error_response["debug"] = {
            "error_type": type(error).__name__,
            "error_details": str(error)
        }
    
    return jsonify(error_response), 500

@app.before_first_request
def startup_message():
    """Log startup information."""
    logger.info("=" * 50)
    logger.info(f"IP Address Service v{getattr(config, 'APP_VERSION', '1.1.0')} starting up")
    logger.info(f"Environment: {getattr(config, 'FLASK_ENV', 'unknown')}")
    logger.info(f"Debug mode: {getattr(config, 'DEBUG', False)}")
    logger.info(f"Listening on: {config.HOST}:{config.PORT}")
    logger.info(f"Proxy layers: {getattr(config, 'PROXY_COUNT', 1)}")
    logger.info("=" * 50)

if __name__ == '__main__':
    # Configuration for different environments
    try:
        port = config.PORT
        debug = getattr(config, 'DEBUG', False)
        host = config.HOST
        
        logger.info(f"Starting IP Address Service on {host}:{port}")
        logger.info(f"Debug mode: {debug}")
        logger.info(f"Environment: {getattr(config, 'FLASK_ENV', 'unknown')}")
        
        # Additional startup validation
        if not config.SECRET_KEY or config.SECRET_KEY == 'dev-secret-key-change-in-production':
            logger.warning("Using default SECRET_KEY - change this in production!")
        
        # Run the application
        app.run(
            host=host, 
            port=port, 
            debug=debug,
            threaded=True,
            use_reloader=debug
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}", exc_info=True)
        sys.exit(1)
