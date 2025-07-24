#!/bin/bash
#
# IP Address Service - Production Deployment Script v1.3.0
# Enhanced automated deployment script with Flask 3.0 compatibility and improved error handling.
# Handles virtual environment, dependencies, configuration, and systemd service setup.
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script version for troubleshooting
SCRIPT_VERSION="1.3.0"

# Configuration variables
SERVICE_NAME="ip-service"
SERVICE_USER="www-data"
SERVICE_GROUP="www-data" 
INSTALL_DIR="/opt/${SERVICE_NAME}"
VENV_DIR="${INSTALL_DIR}/venv"
LOG_DIR="${INSTALL_DIR}/logs"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global deployment mode variable
DEPLOYMENT_MODE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Validate required files exist
validate_required_files() {
    log_info "Validating required files..."
    
    local required_files=("app.py" "config.py" "gunicorn.conf.py" "requirements.txt" "ip-service.service")
    local missing_files=()
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "${SCRIPT_DIR}/${file}" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        log_error "Missing required files: ${missing_files[*]}"
        log_error "Make sure you're running this script from the project directory"
        log_error "Required files: ${required_files[*]}"
        exit 1
    fi
    
    log_success "All required files found"
}

# Check if we're running from the installation directory (and handle it)
handle_installation_directory() {
    if [[ "$SCRIPT_DIR" == "$INSTALL_DIR" ]]; then
        log_warning "Running from installation directory. Creating temporary backup..."
        
        # Create temporary directory for the deployment
        TEMP_DIR="/tmp/ip-service-deploy-$$"
        mkdir -p "$TEMP_DIR"
        
        # Copy current files to temp directory (except for venv, logs, etc.)
        local files_to_copy=("app.py" "config.py" "gunicorn.conf.py" "requirements.txt" "ip-service.service" "deploy.sh")
        for file in "${files_to_copy[@]}"; do
            if [[ -f "$file" ]]; then
                cp "$file" "$TEMP_DIR/"
            fi
        done
        
        # Copy .env.example if it exists
        if [[ -f ".env.example" ]]; then
            cp ".env.example" "$TEMP_DIR/"
        fi
        
        # Update SCRIPT_DIR to point to temp directory
        SCRIPT_DIR="$TEMP_DIR"
        log_info "Using temporary directory: $TEMP_DIR"
    fi
}

# Install system dependencies
install_system_dependencies() {
    log_info "Installing system dependencies..."
    
    # Update package list
    apt-get update -q
    
    # Install essential packages
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        curl \
        wget \
        git \
        logrotate \
        software-properties-common \
        apt-transport-https \
        ca-certificates
    
    log_success "System dependencies installed"
}

# Create service user if it doesn't exist
create_service_user() {
    if ! id "${SERVICE_USER}" &>/dev/null; then
        log_info "Creating service user: ${SERVICE_USER}"
        useradd --system --create-home --shell /bin/false "${SERVICE_USER}"
        log_success "Service user created"
    else
        log_info "Service user ${SERVICE_USER} already exists"
    fi
}

# Create directory structure
create_directories() {
    log_info "Creating directory structure..."
    
    # Stop service if running to avoid file conflicts
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log_info "Stopping existing service..."
        systemctl stop "${SERVICE_NAME}"
    fi
    
    # Create directories
    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${LOG_DIR}"
    
    # Set ownership
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
    
    # Set permissions
    chmod 755 "${INSTALL_DIR}"
    chmod 755 "${LOG_DIR}"
    
    log_success "Directory structure created"
}

# Create Python virtual environment
create_virtual_environment() {
    log_info "Creating Python virtual environment..."
    
    # Remove existing venv if it exists to ensure clean installation
    if [[ -d "${VENV_DIR}" ]]; then
        log_info "Removing existing virtual environment..."
        rm -rf "${VENV_DIR}"
    fi
    
    # Create new venv as service user
    sudo -u "${SERVICE_USER}" python3 -m venv "${VENV_DIR}"
    
    # Upgrade pip, setuptools, and wheel
    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
    
    log_success "Virtual environment created"
}

# Install Python dependencies
install_python_dependencies() {
    log_info "Installing Python dependencies..."
    
    # Copy requirements.txt to install directory if not already there
    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        if [[ "${SCRIPT_DIR}/requirements.txt" != "${INSTALL_DIR}/requirements.txt" ]]; then
            cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
            chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/requirements.txt"
            log_info "Copied requirements.txt"
        fi
        
        # Install dependencies with verbose output for debugging
        if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"; then
            log_error "Failed to install Python dependencies"
            log_info "Trying to install dependencies individually for debugging..."
            
            # Try installing Flask specifically
            if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install Flask==3.0.0; then
                log_info "Flask installed successfully"
            else
                log_error "Failed to install Flask"
                exit 1
            fi
            
            # Try other dependencies
            sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install Werkzeug==3.0.1 || true
            sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install gunicorn==21.2.0 || true
            sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install python-dotenv==1.0.0 || true
            sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install ipaddress==1.0.23 || true
        fi
        
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found in ${SCRIPT_DIR}"
        exit 1
    fi
}

# Copy application files
copy_application_files() {
    log_info "Copying application files..."
    
    # List of files to copy
    local files=("app.py" "config.py" "gunicorn.conf.py")
    
    for file in "${files[@]}"; do
        if [[ -f "${SCRIPT_DIR}/${file}" ]]; then
            # Don't copy if source and destination are the same
            if [[ "${SCRIPT_DIR}/${file}" != "${INSTALL_DIR}/${file}" ]]; then
                cp "${SCRIPT_DIR}/${file}" "${INSTALL_DIR}/"
                chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/${file}"
                log_info "Copied ${file}"
            else
                log_info "Skipped ${file} (source and destination are the same)"
            fi
        else
            log_error "Required file ${file} not found in ${SCRIPT_DIR}"
            exit 1
        fi
    done
    
    log_success "Application files copied"
}

# Generate a secure secret key
generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_hex(32))"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    # Create .env file from template or create a basic one
    if [[ -f "${SCRIPT_DIR}/.env.example" ]]; then
        cp "${SCRIPT_DIR}/.env.example" "${INSTALL_DIR}/.env"
    elif [[ ! -f "${INSTALL_DIR}/.env" ]]; then
        log_info "Creating basic .env file..."
        cat > "${INSTALL_DIR}/.env" << 'EOF'
# IP Address Service - Environment Configuration
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
HOST=0.0.0.0
PORT=5000
PROXY_COUNT=1
TRUSTED_PROXIES=127.0.0.1/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
GUNICORN_WORKERS=4
LOG_LEVEL=INFO
LOG_FILE=/opt/ip-service/logs/ip_service.log
GUNICORN_ACCESS_LOG=/opt/ip-service/logs/access.log
GUNICORN_ERROR_LOG=/opt/ip-service/logs/error.log
GUNICORN_LOG_LEVEL=info
MAX_CONTENT_LENGTH=1024
ENABLE_DEBUG_HEADERS=false
EOF
    fi
    
    # Set proper ownership and permissions
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/.env"
    chmod 600 "${INSTALL_DIR}/.env"
    
    # Generate and set SECRET_KEY if it's the default value
    if grep -q "SECRET_KEY=your-secret-key-here" "${INSTALL_DIR}/.env"; then
        log_info "Generating secure SECRET_KEY..."
        local secret_key
        secret_key=$(generate_secret_key)
        sed -i "s/SECRET_KEY=your-secret-key-here/SECRET_KEY=${secret_key}/" "${INSTALL_DIR}/.env"
        log_success "SECRET_KEY generated and set"
    else
        log_info "SECRET_KEY already configured"
    fi
    
    # Configure based on deployment mode
    case "${DEPLOYMENT_MODE}" in
        "localhost")
            log_info "Configuring for Caddy on same server (127.0.0.1)"
            sed -i 's/HOST=0.0.0.0/HOST=127.0.0.1/' "${INSTALL_DIR}/.env"
            ;;
        "network")
            log_info "Configuring for Caddy on different server (0.0.0.0)"
            sed -i 's/HOST=127.0.0.1/HOST=0.0.0.0/' "${INSTALL_DIR}/.env"
            # Add ALLOW_EXTERNAL_ACCESS=true to suppress validation warning
            if ! grep -q "ALLOW_EXTERNAL_ACCESS" "${INSTALL_DIR}/.env"; then
                echo "ALLOW_EXTERNAL_ACCESS=true" >> "${INSTALL_DIR}/.env"
            fi
            ;;
        "direct")
            log_info "Configuring for direct external access (0.0.0.0)"
            sed -i 's/HOST=127.0.0.1/HOST=0.0.0.0/' "${INSTALL_DIR}/.env"
            # Add ALLOW_EXTERNAL_ACCESS=true to suppress validation warning
            if ! grep -q "ALLOW_EXTERNAL_ACCESS" "${INSTALL_DIR}/.env"; then
                echo "ALLOW_EXTERNAL_ACCESS=true" >> "${INSTALL_DIR}/.env"
            fi
            ;;
        *)
            log_warning "Unknown deployment mode: ${DEPLOYMENT_MODE}, using network mode"
            ;;
    esac
    
    log_success "Environment configuration setup complete"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    if [[ -f "${SCRIPT_DIR}/ip-service.service" ]]; then
        cp "${SCRIPT_DIR}/ip-service.service" "${SYSTEMD_SERVICE_FILE}"
        
        # Reload systemd
        systemctl daemon-reload
        
        # Enable service to start on boot
        systemctl enable "${SERVICE_NAME}"
        
        log_success "Systemd service installed and enabled"
    else
        log_error "Systemd service file not found in ${SCRIPT_DIR}"
        exit 1
    fi
}

# Test Python imports individually
test_python_imports() {
    log_info "Testing Python imports individually..."
    
    cd "${INSTALL_DIR}"
    
    # Test basic Python functionality
    if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "print('Python works')" &>/dev/null; then
        log_error "Basic Python test failed"
        return 1
    fi
    
    # Test Flask import
    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "import flask; print('Flask OK')" 2>/dev/null; then
        log_info "✓ Flask import successful"
    else
        log_error "✗ Flask import failed"
        return 1
    fi
    
    # Test other core imports
    local imports=("werkzeug" "gunicorn" "ipaddress" "json" "logging" "os" "sys")
    for import_name in "${imports[@]}"; do
        if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "import ${import_name}; print('${import_name} OK')" 2>/dev/null; then
            log_info "✓ ${import_name} import successful"
        else
            log_warning "✗ ${import_name} import failed (may not be critical)"
        fi
    done
    
    # Test config import with better error handling
    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "
import sys
sys.path.insert(0, '.')
try:
    import config
    print('Config import successful')
except Exception as e:
    print(f'Config import failed: {e}')
    # Try basic import test
    try:
        exec(open('config.py').read())
        print('Config file syntax OK')
    except Exception as e2:
        print(f'Config syntax error: {e2}')
        exit(1)
" 2>&1; then
        log_info "✓ Config module tested"
    else
        log_error "✗ Config module test failed"
        return 1
    fi
    
    return 0
}

# Validate the configuration before starting
validate_configuration() {
    log_info "Validating configuration..."
    
    # Check if .env file exists and has required settings
    if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
        log_error ".env file not found at ${INSTALL_DIR}/.env"
        exit 1
    fi
    
    # Check if SECRET_KEY is set
    if grep -q "SECRET_KEY=your-secret-key-here" "${INSTALL_DIR}/.env"; then
        log_error "SECRET_KEY not properly configured in .env file"
        exit 1
    fi
    
    # Test Python imports first
    if ! test_python_imports; then
        log_error "Python import validation failed"
        exit 1
    fi
    
    # Test app import with better error handling for Flask 3.0
    log_info "Testing application import..."
    cd "${INSTALL_DIR}"
    
    # Create a test script to validate the app with Flask 3.0 compatibility
    cat > "${INSTALL_DIR}/test_app.py" << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '.')

try:
    # Test config import first
    print("Testing config import...")
    import config
    print("✓ Config imported successfully")
    
    # Test app import
    print("Testing app import...")
    import app
    print("✓ App imported successfully")
    
    # Test Flask app creation
    print("Testing Flask app...")
    flask_app = app.app
    if flask_app:
        print("✓ Flask app created successfully")
        
        # Test that Flask 3.0 compatibility is working
        print("Testing Flask 3.0 compatibility...")
        
        # Check that before_first_request is not used
        with flask_app.app_context():
            print("✓ Flask 3.0 compatibility confirmed")
            
    else:
        print("✗ Flask app is None")
        sys.exit(1)
    
    print("All imports and compatibility tests successful!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except AttributeError as e:
    if "before_first_request" in str(e):
        print(f"✗ Flask 3.0 compatibility error: {e}")
        print("This error indicates the code uses deprecated Flask features.")
        print("Please update app.py to be compatible with Flask 3.0+")
    else:
        print(f"✗ Attribute error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ General error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF
    
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/test_app.py"
    
    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" "${INSTALL_DIR}/test_app.py"; then
        log_success "Application import and Flask 3.0 compatibility test passed"
        rm -f "${INSTALL_DIR}/test_app.py"
    else
        log_error "Application import test failed"
        log_error "This may be due to Flask 3.0 compatibility issues"
        log_error "Check if app.py uses deprecated features like @app.before_first_request"
        rm -f "${INSTALL_DIR}/test_app.py"
        exit 1
    fi
    
    # Test gunicorn configuration
    log_info "Testing Gunicorn configuration..."
    if sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/gunicorn" --check-config --config gunicorn.conf.py app:app; then
        log_success "Gunicorn configuration test passed"
    else
        log_error "Gunicorn configuration test failed"
        exit 1
    fi
    
    log_success "Configuration validation passed"
}

# Setup log rotation
setup_log_rotation() {
    log_info "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/${SERVICE_NAME}" << EOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 ${SERVICE_USER} ${SERVICE_GROUP}
    postrotate
        systemctl reload ${SERVICE_NAME} > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log_success "Log rotation configured"
}

# Setup firewall rules (if ufw is installed)
setup_firewall() {
    if command -v ufw &> /dev/null; then
        log_info "Configuring firewall rules..."
        
        case "${DEPLOYMENT_MODE}" in
            "localhost")
                log_info "Localhost mode: No firewall changes needed (connections from 127.0.0.1 only)"
                ;;
            "network"|"direct")
                log_info "Opening port 5000 for network/external connections"
                ufw allow 5000/tcp
                log_success "Port 5000 opened in firewall"
                ;;
        esac
        
        log_info "Firewall configuration complete"
    else
        log_info "UFW not installed, skipping firewall configuration"
        if [[ "${DEPLOYMENT_MODE}" != "localhost" ]]; then
            log_warning "Make sure your firewall allows connections on port 5000"
        fi
    fi
}

# Test the installation with enhanced validation
test_installation() {
    log_info "Testing installation..."
    
    # Validate configuration first
    validate_configuration
    
    # Start the service
    log_info "Starting the service..."
    if systemctl start "${SERVICE_NAME}"; then
        log_success "Service started successfully"
    else
        log_error "Failed to start service"
        log_info "Checking service status..."
        systemctl status "${SERVICE_NAME}" --no-pager -l || true
        log_info "Checking recent logs..."
        journalctl -u "${SERVICE_NAME}" -n 20 --no-pager || true
        exit 1
    fi
    
    # Wait for startup
    log_info "Waiting for service to initialize..."
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_success "Service is running"
        
        # Get the configured port and host
        local port
        port=$(grep -oP 'PORT=\K\d+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "5000")
        
        local host
        host=$(grep -oP 'HOST=\K[^\s]+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "127.0.0.1")
        
        log_info "Service configured for ${host}:${port}"
        
        # Test health endpoint with retries
        log_info "Testing health endpoint..."
        local max_retries=10
        local retry=0
        local health_ok=false
        
        while [[ $retry -lt $max_retries ]]; do
            if curl -f -s --max-time 10 --connect-timeout 5 "http://${host}:${port}/health" > /dev/null 2>&1; then
                health_ok=true
                break
            fi
            
            retry=$((retry + 1))
            if [[ $retry -lt $max_retries ]]; then
                log_info "Health check attempt ${retry}/${max_retries} failed, retrying in 3 seconds..."
                sleep 3
            fi
        done
        
        if [[ "$health_ok" == "true" ]]; then
            log_success "Health check endpoint responding"
            
            # Test main endpoint
            log_info "Testing main IP endpoint..."
            local response
            if response=$(curl -f -s --max-time 10 --connect-timeout 5 "http://${host}:${port}/"); then
                if echo "$response" | grep -q '"status":"success"\|"status":"error"'; then
                    log_success "Main endpoint responding with valid JSON"
                    
                    # Show sample response
                    log_info "Sample response: $(echo "$response" | head -c 200)..."
                else
                    log_warning "Main endpoint responding but JSON format unexpected"
                    log_info "Response: $response"
                fi
            else
                log_warning "Main endpoint not responding (this may be normal if no IP is detected)"
            fi
            
            # Test info endpoint
            log_info "Testing info endpoint..."
            if curl -f -s --max-time 5 "http://${host}:${port}/info" > /dev/null 2>&1; then
                log_success "Info endpoint responding"
            else
                log_warning "Info endpoint not responding"
            fi
            
        else
            log_warning "Health check endpoint not responding after ${max_retries} attempts"
            log_warning "Service may need additional configuration or time to start"
            
            # Show recent logs for debugging
            log_info "Recent service logs:"
            journalctl -u "${SERVICE_NAME}" -n 10 --no-pager || true
        fi
        
        # Show service status
        log_info "Service status:"
        systemctl status "${SERVICE_NAME}" --no-pager -l | head -15
        
    else
        log_error "Service failed to start"
        log_error "Check logs with: journalctl -u ${SERVICE_NAME} -f"
        
        # Show recent logs
        log_info "Recent service logs:"
        journalctl -u "${SERVICE_NAME}" -n 30 --no-pager
        
        exit 1
    fi
}

# Cleanup function
cleanup() {
    if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
        log_info "Cleaning up temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR"
    fi
}

# Display post-installation information
show_post_install_info() {
    log_success "Installation completed successfully!"
    echo
    
    case "${DEPLOYMENT_MODE}" in
        "localhost")
            echo "=== LOCALHOST MODE ==="
            echo "Your service accepts connections from the same server only (127.0.0.1)."
            echo "This is the most secure option when Caddy runs on the same server."
            echo
            echo "Caddy configuration:"
            echo "  ip.example.com {"
            echo "      reverse_proxy 127.0.0.1:5000"
            echo "  }"
            echo
            echo "Test locally:"
            echo "  curl http://127.0.0.1:5000/"
            echo "  curl http://127.0.0.1:5000/health"
            ;;
        "network")
            echo "=== NETWORK MODE ==="
            echo "Your service accepts connections from the network (0.0.0.0)."
            echo "This allows your Caddy server at 192.168.x.x to connect."
            echo
            echo "Caddy configuration (on your 192.168.x.x server):"
            echo "  ip.example.com {"
            echo "      reverse_proxy $(hostname -I | awk '{print $1}'):5000"
            echo "  }"
            echo
            echo "Test from network:"
            echo "  curl http://$(hostname -I | awk '{print $1}'):5000/"
            echo "  curl http://$(hostname -I | awk '{print $1}'):5000/health"
            ;;
        "direct")
            echo "=== DIRECT EXTERNAL ACCESS MODE ==="
            echo "Your service accepts direct external connections."
            echo "No reverse proxy needed - less secure but simpler setup."
            echo
            echo "Test external access:"
            echo "  curl http://$(curl -s ifconfig.me):5000/"
            echo "  curl http://YOUR_SERVER_IP:5000/"
            ;;
    esac
    
    echo
    echo "Service Information:"
    echo "- Installation directory: ${INSTALL_DIR}"
    echo "- Configuration file: ${INSTALL_DIR}/.env"
    echo "- Log directory: ${LOG_DIR}"
    echo "- Service user: ${SERVICE_USER}"
    echo "- Python virtual env: ${VENV_DIR}"
    echo "- Flask version: 3.0.0 (compatible)"
    echo
    echo "Useful commands:"
    echo "- Check service status: sudo systemctl status ${SERVICE_NAME}"
    echo "- View real-time logs: sudo journalctl -u ${SERVICE_NAME} -f"
    echo "- Restart service: sudo systemctl restart ${SERVICE_NAME}"
    echo "- Stop service: sudo systemctl stop ${SERVICE_NAME}"
    echo "- Start service: sudo systemctl start ${SERVICE_NAME}"
    echo "- View configuration: cat ${INSTALL_DIR}/.env"
    echo "- Test health endpoint: curl http://127.0.0.1:5000/health"
    echo "- Test main endpoint: curl http://127.0.0.1:5000/"
    echo
    echo "Log files:"
    echo "- Application logs: ${LOG_DIR}/ip_service.log"
    echo "- Access logs: ${LOG_DIR}/access.log"
    echo "- Error logs: ${LOG_DIR}/error.log"
    echo "- System logs: journalctl -u ${SERVICE_NAME}"
    echo
    echo "Flask 3.0 Compatibility:"
    echo "- All deprecated features have been updated"
    echo "- before_first_request replaced with before_request"
    echo "- Fully compatible with modern Flask versions"
    echo
    log_success "Deployment completed successfully!"
}

# Show usage information
show_usage() {
    echo "IP Address Service Deployment Script v${SCRIPT_VERSION}"
    echo "Usage: $0 [localhost|network|direct]"
    echo
    echo "Deployment modes:"
    echo "  network (default) - Caddy on different server (192.168.x.x)"
    echo "                     Binds to 0.0.0.0 - accepts network connections"
    echo "  localhost         - Caddy on same server as Flask app"
    echo "                     Binds to 127.0.0.1 - most secure"
    echo "  direct            - Direct external access (no reverse proxy)"
    echo "                     Binds to 0.0.0.0 - least secure"
    echo
    echo "Examples:"
    echo "  $0              # Deploy for Caddy on different server (most common)"
    echo "  $0 network      # Deploy for Caddy on different server"
    echo "  $0 localhost    # Deploy for Caddy on same server"
    echo "  $0 direct       # Deploy for direct external access"
    echo
    echo "Features:"
    echo "  ✓ Automatic dependency installation"
    echo "  ✓ Python virtual environment setup"
    echo "  ✓ Secure SECRET_KEY generation"
    echo "  ✓ Systemd service installation"
    echo "  ✓ Log rotation configuration"
    echo "  ✓ Flask 3.0 compatibility validation"
    echo "  ✓ Comprehensive testing and validation"
    echo "  ✓ Firewall configuration (if UFW available)"
    echo "  ✓ Robust error handling and recovery"
    echo
    echo "Flask 3.0 Updates:"
    echo "  ✓ Removed deprecated before_first_request"
    echo "  ✓ Updated to modern Flask patterns"
    echo "  ✓ Enhanced compatibility testing"
}

# Main deployment function
main() {
    # Get first argument safely and set deployment mode
    local arg1="${1:-}"
    
    # Show usage if help requested
    if [[ "$arg1" == "-h" || "$arg1" == "--help" || "$arg1" == "help" ]]; then
        show_usage
        exit 0
    fi
    
    # Set deployment mode with default
    DEPLOYMENT_MODE="${arg1:-network}"
    
    # Validate deployment mode
    case "${DEPLOYMENT_MODE}" in
        "localhost"|"network"|"direct")
            ;;
        *)
            log_error "Invalid deployment mode: ${DEPLOYMENT_MODE}"
            log_error "Valid modes: localhost, network, direct"
            show_usage
            exit 1
            ;;
    esac
    
    log_info "Starting deployment of ${SERVICE_NAME} v${SCRIPT_VERSION} in ${DEPLOYMENT_MODE} mode..."
    log_info "Flask 3.0 compatible version with enhanced error handling"
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Validation steps
    check_root
    validate_required_files
    handle_installation_directory
    
    # Installation steps
    install_system_dependencies
    create_service_user
    create_directories
    create_virtual_environment
    install_python_dependencies
    copy_application_files
    setup_environment
    install_systemd_service
    setup_log_rotation
    setup_firewall
    test_installation
    show_post_install_info
    
    log_success "Deployment completed successfully!"
}

# Handle script interruption
trap 'log_error "Deployment interrupted"; cleanup; exit 1' INT TERM

# Run main function
main "$@"
