#!/usr/bin/env python3
"""
Gunicorn Configuration for IP Address Service
Production-ready WSGI server configuration with optimized settings
for handling IP lookup requests efficiently and securely.
"""

import os
import multiprocessing
from config import get_config

# Get configuration based on environment
config = get_config()

# Server socket configuration
bind = f"{config.HOST}:{config.PORT}"
backlog = 2048

# Worker process configuration
# For CPU-bound tasks like IP parsing, use more workers
# For I/O-bound tasks, fewer workers with async worker class
workers = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = os.getenv('GUNICORN_WORKER_CLASS', 'sync')
worker_connections = int(os.getenv('GUNICORN_WORKER_CONNECTIONS', 1000))
max_requests = int(os.getenv('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = int(os.getenv('GUNICORN_MAX_REQUESTS_JITTER', 100))

# Timeout configuration
timeout = int(os.getenv('GUNICORN_TIMEOUT', 30))
keepalive = int(os.getenv('GUNICORN_KEEPALIVE', 5))
graceful_timeout = int(os.getenv('GUNICORN_GRACEFUL_TIMEOUT', 30))

# Application preloading for better performance
preload_app = True
reload = os.getenv('GUNICORN_RELOAD', 'false').lower() == 'true'

# Process naming for easier monitoring
proc_name = 'ip-address-service'

# User and group (set these if running as root)
user = os.getenv('GUNICORN_USER', None)
group = os.getenv('GUNICORN_GROUP', None)

# Logging configuration
accesslog = os.getenv('GUNICORN_ACCESS_LOG', '-')  # stdout
errorlog = os.getenv('GUNICORN_ERROR_LOG', '-')    # stderr
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Capture output for better logging integration
capture_output = True
enable_stdio_inheritance = True

# Security settings
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# SSL settings (if using HTTPS directly with Gunicorn)
# Note: With Caddy as reverse proxy, SSL termination is handled by Caddy
keyfile = os.getenv('GUNICORN_KEYFILE', None)
certfile = os.getenv('GUNICORN_CERTFILE', None)
ssl_version = 2  # TLSv1.2 minimum
ciphers = 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'

# Development vs Production settings
if os.getenv('FLASK_ENV') == 'development':
    # Development settings
    reload = True
    workers = 1
    loglevel = 'debug'
    timeout = 0  # Disable timeout for debugging

# Hook functions for custom behavior
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting IP Address Service with Gunicorn")
    server.log.info(f"Configuration: {workers} workers, {worker_class} worker class")

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
    server.log.debug(f"Post-forking worker {worker.pid}")

def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Pre-executing new master process")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info(f"IP Address Service ready on {bind}")
    server.log.info(f"Master PID: {os.getpid()}")

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.warning(f"Worker {worker.pid} aborted")

def pre_request(worker, req):
    """Called just before a worker processes the request."""
    # Log high-level request info for monitoring
    worker.log.debug(f"Processing request: {req.method} {req.path}")

def post_request(worker, req, environ, resp):
    """Called after a worker processes the request."""
    # Log response info for monitoring
    worker.log.debug(f"Request completed: {resp.status_code}")

# Additional settings for monitoring and health checks
forwarded_allow_ips = os.getenv('GUNICORN_FORWARDED_ALLOW_IPS', '*')
proxy_protocol = os.getenv('GUNICORN_PROXY_PROTOCOL', 'false').lower() == 'true'

# Memory and resource limits
max_requests_jitter = max_requests_jitter
worker_tmp_dir = os.getenv('GUNICORN_WORKER_TMP_DIR', '/dev/shm')  # Use RAM disk if available

# Custom application factory if needed
# wsgi_module = 'app:app'  # This is the default, pointing to app.py:app

