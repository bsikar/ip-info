#!/usr/bin/env python3
"""
IP Address Service - Main Application
A lightweight web service that returns client IP addresses in JSON format,
similar to ipinfo.io functionality. Designed to work behind reverse proxies
like Caddy, Nginx, or Apache.
"""

import json
import logging
import ipaddress
import re
from datetime import datetime
from typing import Optional, Dict, Any
from flask import Flask, request, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ip_service.log')
    ]
)

logger = logging.getLogger(__name__)

class IPAddressService:
    """
    Core service class for extracting and validating client IP addresses.
    Handles various proxy scenarios and provides comprehensive IP detection.
    """
    
    # Trusted proxy headers in order of preference
    PROXY_HEADERS = [
        'X-Forwarded-For',      # Standard proxy header
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
    ]
    
    def __init__(self):
        """Initialize the IP address service with logging configuration."""
        logger.info("Initializing IP Address Service")
        
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
            return any(ip in network for network in self.PRIVATE_RANGES)
        except (ipaddress.AddressValueError, ValueError):
            logger.warning(f"Invalid IP address format: {ip_str}")
            return True  # Treat invalid IPs as private for security
    
    def validate_ipv4(self, ip_str: str) -> bool:
        """
        Validate if string is a proper IPv4 address format.
        
        Args:
            ip_str: String to validate as IPv4
            
        Returns:
            bool: True if valid IPv4, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
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
            
        # Split by comma and strip whitespace
        ip_list = [ip.strip() for ip in header_value.split(',')]
        
        for ip in ip_list:
            # Remove port if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
            ip_clean = ip.split(':')[0]
            
            if self.validate_ipv4(ip_clean) and not self.is_private_ip(ip_clean):
                logger.debug(f"Found valid public IP in header: {ip_clean}")
                return ip_clean
                
        return None
    
    def get_client_ip(self, request_obj) -> Optional[str]:
        """
        Extract the client's real IP address from the request.
        Checks proxy headers first, falls back to remote_addr.
        
        Args:
            request_obj: Flask request object
            
        Returns:
            str or None: Client's public IP address or None if not found
        """
        logger.debug(f"Extracting IP from request. Remote addr: {request_obj.remote_addr}")
        
        # Check proxy headers in order of preference
        for header in self.PROXY_HEADERS:
            header_value = request_obj.headers.get(header)
            if header_value:
                logger.debug(f"Checking header {header}: {header_value}")
                
                if header == 'Forwarded':
                    # RFC 7239 format: Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
                    match = re.search(r'for=([^;,\s]+)', header_value)
                    if match:
                        ip = match.group(1).strip('"[]')
                        if self.validate_ipv4(ip) and not self.is_private_ip(ip):
                            logger.info(f"Client IP extracted from {header}: {ip}")
                            return ip
                else:
                    # Standard comma-separated format
                    ip = self.extract_ip_from_forwarded_header(header_value)
                    if ip:
                        logger.info(f"Client IP extracted from {header}: {ip}")
                        return ip
        
        # Fallback to direct connection IP
        direct_ip = request_obj.remote_addr
        if direct_ip and self.validate_ipv4(direct_ip) and not self.is_private_ip(direct_ip):
            logger.info(f"Client IP from direct connection: {direct_ip}")
            return direct_ip
        
        logger.warning("No valid public IP address found in request")
        return None
    
    def generate_response(self, ip_address: Optional[str], request_obj) -> Dict[str, Any]:
        """
        Generate the JSON response with IP information.
        
        Args:
            ip_address: The detected IP address
            request_obj: Flask request object for additional context
            
        Returns:
            dict: Response data structure
        """
        response_data = {
            "ip": ip_address,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "success" if ip_address else "error"
        }
        
        if not ip_address:
            response_data["error"] = "Unable to determine public IP address"
            response_data["message"] = "No valid public IPv4 address found in request"
        
        # Add debug information in development mode
        if os.getenv('FLASK_ENV') == 'development':
            response_data["debug"] = {
                "remote_addr": request_obj.remote_addr,
                "headers": dict(request_obj.headers),
                "user_agent": request_obj.headers.get('User-Agent', 'Unknown')
            }
        
        return response_data


# Initialize Flask application
app = Flask(__name__)

# Configure Flask app for production use
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Configure proxy handling - adjust num_proxies based on your setup
# If you have Caddy directly forwarding to this app, use num_proxies=1
# If you have multiple proxy layers, increase accordingly
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialize service
ip_service = IPAddressService()

@app.route('/', methods=['GET'])
def get_ip():
    """
    Main endpoint for retrieving client IP address.
    Returns JSON with the client's public IPv4 address.
    """
    start_time = datetime.utcnow()
    client_ip = None
    
    try:
        # Extract client IP address
        client_ip = ip_service.get_client_ip(request)
        
        # Generate response
        response_data = ip_service.generate_response(client_ip, request)
        
        # Log the request
        user_agent = request.headers.get('User-Agent', 'Unknown')
        logger.info(f"IP request - Client: {client_ip}, User-Agent: {user_agent[:100]}")
        
        # Return JSON response
        response = jsonify(response_data)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing IP request: {str(e)}", exc_info=True)
        
        error_response = {
            "ip": None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "error",
            "error": "Internal server error",
            "message": "An error occurred while processing your request"
        }
        
        return jsonify(error_response), 500
    
    finally:
        # Log request timing
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds() * 1000
        logger.debug(f"Request processed in {duration:.2f}ms")

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and load balancer probes.
    Returns service status and basic metrics.
    """
    try:
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "service": "IP Address Service",
            "version": "1.0.0"
        }
        
        response = jsonify(health_data)
        response.headers['Content-Type'] = 'application/json'
        return response
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}", exc_info=True)
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors with JSON response."""
    logger.warning(f"404 error for path: {request.path}")
    
    error_response = {
        "status": "error",
        "error": "Not Found",
        "message": "The requested endpoint does not exist",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    return jsonify(error_response), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with JSON response."""
    logger.error(f"500 error: {str(error)}", exc_info=True)
    
    error_response = {
        "status": "error",
        "error": "Internal Server Error",
        "message": "An internal server error occurred",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    return jsonify(error_response), 500

if __name__ == '__main__':
    # Configuration for different environments
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    host = os.getenv('HOST', '127.0.0.1')
    
    logger.info(f"Starting IP Address Service on {host}:{port}")
    logger.info(f"Debug mode: {debug}")
    
    # Run the application
    app.run(host=host, port=port, debug=debug)

