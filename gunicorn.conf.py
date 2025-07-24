#!/usr/bin/env python3
"""
Gunicorn Configuration for IP Address Service
Production-ready WSGI server configuration with optimized settings
for handling IP lookup requests efficiently and securely with robust error handling.
"""

import os
import sys
import multiprocessing

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    if os.path.exists('.env'):
        load_dotenv()
except ImportError:
    # dotenv not available, continue without it
    pass

# Helper function to get environment variables with defaults
def get_env_int(key, default):
    """Get environment variable as integer with fallback."""
    try:
        return int(os.getenv(key, default))
    except (ValueError, TypeError):
        return default

def get_env_bool(key, default=False):
    """Get environment variable as boolean with fallback."""
    value = os.getenv(key, '').lower()
    if value in ('true', '1', 'yes', 'on'):
        return True
    elif value in ('false', '0', 'no', 'off'):
        return False
    else:
        return default

def get_optimal_workers():
    """Calculate optimal number of workers based on CPU count."""
    try:
        cpu_count = multiprocessing.cpu_count()
        # For CPU-bound tasks like IP parsing: (2 * CPU) + 1
        # For I/O-bound tasks: (2 * CPU) + 1 to (4 * CPU) + 1
        optimal = (cpu_count * 2) + 1
        # Cap at 8 workers for most deployments
        return min(optimal, 8)
    except (NotImplementedError, AttributeError):
        # Fallback if multiprocessing.cpu_count() fails
        return 4

# ============================================================================
# Server Socket Configuration
# ============================================================================

# Get host and port from environment
host = os.getenv('HOST', '127.0.0.1')
port = get_env_int('PORT', 5000)

# Primary bind address
bind = f"{host}:{port}"

# Socket backlog (number of pending connections)
backlog = get_env_int('GUNICORN_BACKLOG', 2048)

# ============================================================================
# Worker Process Configuration
# ============================================================================

# Number of worker processes
workers = get_env_int('GUNICORN_WORKERS', get_optimal_workers())

# Worker class - sync for CPU-bound, gevent/eventlet for I/O-bound
worker_class = os.getenv('GUNICORN_WORKER_CLASS', 'sync')

# Maximum number of simultaneous clients per worker (for async workers)
worker_connections = get_env_int('GUNICORN_WORKER_CONNECTIONS', 1000)

# Worker process recycling for memory management
max_requests = get_env_int('GUNICORN_MAX_REQUESTS', 1000)
max_requests_jitter = get_env_int('GUNICORN_MAX_REQUESTS_JITTER', 100)

# ============================================================================
# Timeout Configuration
# ============================================================================

# Request timeout in seconds
timeout = get_env_int('GUNICORN_TIMEOUT', 30)

# Keep-alive timeout for persistent connections
keepalive = get_env_int('GUNICORN_KEEPALIVE', 5)

# Graceful shutdown timeout
graceful_timeout = get_env_int('GUNICORN_GRACEFUL_TIMEOUT', 30)

# ============================================================================
# Application Configuration
# ============================================================================

# Preload application for better performance and memory sharing
preload_app = get_env_bool('GUNICORN_PRELOAD_APP', True)

# Reload application on code changes (development only)
reload = get_env_bool('GUNICORN_RELOAD', False)

# Process naming for easier monitoring
proc_name = 'ip-address-service'

# ============================================================================
# Security Configuration
# ============================================================================

# User and group to run workers as (if started as root)
user = os.getenv('GUNICORN_USER', None)
group = os.getenv('GUNICORN_GROUP', None)

# Forwarded IP configuration for proxy setups
forwarded_allow_ips = os.getenv('GUNICORN_FORWARDED_ALLOW_IPS', '*')

# Proxy protocol support (for load balancers that support it)
proxy_protocol = get_env_bool('GUNICORN_PROXY_PROTOCOL', False)

# Request limits for security
limit_request_line = get_env_int('GUNICORN_LIMIT_REQUEST_LINE', 4094)
limit_request_fields = get_env_int('GUNICORN_LIMIT_REQUEST_FIELDS', 100)
limit_request_field_size = get_env_int('GUNICORN_LIMIT_REQUEST_FIELD_SIZE', 8190)

# ============================================================================
# Logging Configuration
# ============================================================================

# Access log file
accesslog = os.getenv('GUNICORN_ACCESS_LOG', '/opt/ip-service/logs/access.log')

# Error log file
errorlog = os.getenv('GUNICORN_ERROR_LOG', '/opt/ip-service/logs/error.log')

# Log level
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info').lower()

# Custom access log format with more detailed information
access_log_format = os.getenv(
    'GUNICORN_ACCESS_LOG_FORMAT',
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s %(L)s'
)

# Capture application output
capture_output = get_env_bool('GUNICORN_CAPTURE_OUTPUT', True)

# Enable stdio inheritance for better logging
enable_stdio_inheritance = get_env_bool('GUNICORN_ENABLE_STDIO_INHERITANCE', True)

# ============================================================================
# Performance Tuning
# ============================================================================

# Worker temporary directory (use RAM disk if available for better performance)
worker_tmp_dir = os.getenv('GUNICORN_WORKER_TMP_DIR', '/dev/shm')

# Fallback to /tmp if /dev/shm is not available
if not os.path.exists(worker_tmp_dir) or not os.access(worker_tmp_dir, os.W_OK):
    worker_tmp_dir = '/tmp'

# SSL Configuration (if terminating SSL at Gunicorn level)
# Note: With Caddy as reverse proxy, SSL is typically handled by Caddy
keyfile = os.getenv('GUNICORN_KEYFILE', None)
certfile = os.getenv('GUNICORN_CERTFILE', None)

if keyfile and certfile:
    # SSL settings
    ssl_version = 2  # TLSv1.2 minimum
    ciphers = os.getenv('GUNICORN_CIPHERS', 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')

# ============================================================================
# Environment-Specific Configuration
# ============================================================================

flask_env = os.getenv('FLASK_ENV', 'production').lower()

if flask_env == 'development':
    # Development settings - more verbose logging, auto-reload
    reload = True
    workers = 1  # Single worker for easier debugging
    loglevel = 'debug'
    timeout = 0  # Disable timeout for debugging
    preload_app = False  # Disable preloading for reload to work
    accesslog = '-'  # Log to stdout
    errorlog = '-'   # Log to stderr
elif flask_env == 'testing':
    # Testing settings - minimal workers, fast timeouts
    workers = 1
    timeout = 10
    keepalive = 2
    loglevel = 'warning'
    max_requests = 100
elif flask_env == 'staging':
    # Staging settings - production-like but with more logging
    loglevel = 'info'
    workers = min(workers, 4)  # Limit workers in staging
else:
    # Production settings - optimized for performance and security
    loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'warning').lower()

# ============================================================================
# Hook Functions for Custom Behavior
# ============================================================================

def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("=" * 60)
    server.log.info("Starting IP Address Service with Gunicorn")
    server.log.info(f"Environment: {flask_env}")
    server.log.info(f"Workers: {workers} ({worker_class})")
    server.log.info(f"Bind: {bind}")
    server.log.info(f"Timeout: {timeout}s")
    server.log.info(f"Preload App: {preload_app}")
    server.log.info("=" * 60)

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    server.log.info("Reloading IP Address Service workers")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info(f"Worker {worker.pid} received INT/QUIT signal")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.debug(f"Pre-forking worker {worker.pid}")

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    worker.log.debug(f"Worker {worker.pid} started")
    
    # Initialize any worker-specific resources here
    # For example, database connections, cache connections, etc.

def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Pre-executing new master process")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("=" * 60)
    server.log.info(f"IP Address Service ready on {bind}")
    server.log.info(f"Master PID: {os.getpid()}")
    server.log.info(f"Log Level: {loglevel}")
    server.log.info(f"Access Log: {accesslog}")
    server.log.info(f"Error Log: {errorlog}")
    server.log.info("Service is ready to accept connections")
    server.log.info("=" * 60)

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.warning(f"Worker {worker.pid} aborted")

def pre_request(worker, req):
    """Called just before a worker processes the request."""
    # Log high-level request info for monitoring (debug level only)
    worker.log.debug(f"Processing: {req.method} {req.path}")

def post_request(worker, req, environ, resp):
    """Called after a worker processes the request."""
    # Log response info for monitoring (debug level only)
    worker.log.debug(f"Response: {resp.status_code} for {req.method} {req.path}")

def child_exit(server, worker):
    """Called just after a worker has been exited."""
    server.log.info(f"Worker {worker.pid} exited with code {worker.exitcode}")

def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    server.log.debug(f"Worker {worker.pid} cleanup completed")

def nworkers_changed(server, new_value, old_value):
    """Called just after num_workers has been changed."""
    server.log.info(f"Number of workers changed from {old_value} to {new_value}")

def on_exit(server):
    """Called just before exiting."""
    server.log.info("IP Address Service shutting down")
    server.log.info("Goodbye!")

# ============================================================================
# Configuration Validation
# ============================================================================

def validate_config():
    """Validate configuration parameters."""
    errors = []
    
    if workers < 1:
        errors.append("workers must be >= 1")
    
    if workers > 32:
        errors.append("workers should not exceed 32 for most deployments")
    
    if timeout < 1:
        errors.append("timeout must be >= 1 (or 0 for development)")
    
    if keepalive < 1:
        errors.append("keepalive must be >= 1")
    
    if port < 1 or port > 65535:
        errors.append("port must be between 1 and 65535")
    
    # Check if log directories exist and are writable
    for log_path in [accesslog, errorlog]:
        if log_path not in ['-', None]:
            log_dir = os.path.dirname(log_path)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except (OSError, PermissionError):
                    errors.append(f"Cannot create log directory: {log_dir}")
    
    return errors

# Run validation
config_errors = validate_config()
if config_errors:
    print("Gunicorn configuration errors:", file=sys.stderr)
    for error in config_errors:
        print(f"  - {error}", file=sys.stderr)
    # Don't exit here, let Gunicorn handle the errors

# ============================================================================
# Configuration Summary (for debugging)
# ============================================================================

def print_config_summary():
    """Print configuration summary for debugging."""
    print("=" * 60)
    print("Gunicorn Configuration Summary")
    print("=" * 60)
    print(f"Bind: {bind}")
    print(f"Workers: {workers} ({worker_class})")
    print(f"Environment: {flask_env}")
    print(f"Timeout: {timeout}s")
    print(f"Keepalive: {keepalive}s")
    print(f"Preload App: {preload_app}")
    print(f"Access Log: {accesslog}")
    print(f"Error Log: {errorlog}")
    print(f"Log Level: {loglevel}")
    print(f"Worker Temp Dir: {worker_tmp_dir}")
    print("=" * 60)

# Print config summary if running in debug mode
if loglevel == 'debug' or os.getenv('GUNICORN_DEBUG_CONFIG', '').lower() == 'true':
    print_config_summary()

# ============================================================================
# Export Configuration (for programmatic access)
# ============================================================================

# Configuration dictionary for external access
config_dict = {
    'bind': bind,
    'workers': workers,
    'worker_class': worker_class,
    'worker_connections': worker_connections,
    'timeout': timeout,
    'keepalive': keepalive,
    'preload_app': preload_app,
    'reload': reload,
    'user': user,
    'group': group,
    'loglevel': loglevel,
    'accesslog': accesslog,
    'errorlog': errorlog,
    'proc_name': proc_name,
    'forwarded_allow_ips': forwarded_allow_ips,
    'limit_request_line': limit_request_line,
    'limit_request_fields': limit_request_fields,
    'limit_request_field_size': limit_request_field_size
}

# Allow external access to configuration
def get_config():
    """Return configuration dictionary."""
    return config_dict.copy()

