#!/bin/bash
#
# IP Address Service - Production Deployment Script
# Automated deployment script for setting up the IP service on a production server.
# Handles virtual environment, dependencies, configuration, and systemd service setup.
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script version for troubleshooting
SCRIPT_VERSION="1.1.0"

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
        log_warning "Running from installation directory. This is not recommended."
        log_info "Creating temporary backup and working directory..."
        
        # Create temporary directory for the deployment
        TEMP_DIR="/tmp/ip-service-deploy-$"
        mkdir -p "$TEMP_DIR"
        
        # Copy current files to temp directory (except for venv, logs, etc.)
        local files_to_copy=("app.py" "config.py" "gunicorn.conf.py" "requirements.txt" "ip-service.service" "deploy.sh")
        for file in "${files_to_copy[@]}"; do
            if [[ -f "$file" ]]; then
                cp "$file" "$TEMP_DIR/"
            fi
        done
        
        # Update SCRIPT_DIR to point to temp directory
        SCRIPT_DIR="$TEMP_DIR"
        log_info "Using temporary directory: $TEMP_DIR"
    fi
}

# Install system dependencies
install_system_dependencies() {
    log_info "Installing system dependencies..."
    
    apt-get update -q
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        curl \
        wget \
        git \
        logrotate
    
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
    
    # Create venv as service user
    sudo -u "${SERVICE_USER}" python3 -m venv "${VENV_DIR}"
    
    # Upgrade pip
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
        else
            log_info "requirements.txt already in place"
        fi
        
        # Install dependencies
        sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
        
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
    
    # Create .env file from template
    if [[ -f "${SCRIPT_DIR}/.env.example" ]]; then
        cp "${SCRIPT_DIR}/.env.example" "${INSTALL_DIR}/.env"
    elif [[ ! -f "${INSTALL_DIR}/.env" ]]; then
        log_warning ".env.example not found, creating basic .env file"
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
            ;;
        "direct")
            log_info "Configuring for direct external access (0.0.0.0)"
            sed -i 's/HOST=127.0.0.1/HOST=0.0.0.0/' "${INSTALL_DIR}/.env"
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
    
    # Test Python environment and imports
    log_info "Testing Python environment..."
    if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "import app; print('App imported successfully')" &>/dev/null; then
        log_error "Failed to import Flask application"
        log_info "Testing imports individually..."
        
        # Test individual components
        if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "import flask; print('Flask OK')" 2>/dev/null; then
            log_error "Flask import failed"
        fi
        
        if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/python" -c "import config; print('Config OK')" 2>/dev/null; then
            log_error "Config import failed"
        fi
        
        exit 1
    fi
    
    # Test gunicorn configuration
    log_info "Testing Gunicorn configuration..."
    cd "${INSTALL_DIR}"
    if ! sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/gunicorn" --check-config --config gunicorn.conf.py app:app; then
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

# Test the installation
test_installation() {
    log_info "Testing installation..."
    
    # Validate configuration first
    validate_configuration
    
    # Start the service
    log_info "Starting the service..."
    systemctl start "${SERVICE_NAME}"
    
    # Wait a moment for startup
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_success "Service is running"
        
        # Get the configured port
        local port
        port=$(grep -oP 'PORT=\K\d+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "5000")
        
        # Get the configured host
        local host
        host=$(grep -oP 'HOST=\K[^\s]+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "127.0.0.1")
        
        # Test health endpoint with retries
        log_info "Testing health endpoint..."
        local max_retries=5
        local retry=0
        local health_ok=false
        
        while [[ $retry -lt $max_retries ]]; do
            if curl -f -s --max-time 5 "http://${host}:${port}/health" > /dev/null 2>&1; then
                health_ok=true
                break
            fi
            
            retry=$((retry + 1))
            if [[ $retry -lt $max_retries ]]; then
                log_info "Health check attempt ${retry} failed, retrying in 2 seconds..."
                sleep 2
            fi
        done
        
        if [[ "$health_ok" == "true" ]]; then
            log_success "Health check endpoint responding"
            
            # Test main endpoint
            log_info "Testing main IP endpoint..."
            local response
            if response=$(curl -f -s --max-time 5 "http://${host}:${port}/"); then
                if echo "$response" | grep -q '"status":"success"\|"status":"error"'; then
                    log_success "Main endpoint responding with valid JSON"
                else
                    log_warning "Main endpoint responding but JSON format unexpected"
                fi
            else
                log_warning "Main endpoint not responding (this may be normal if no IP is detected)"
            fi
        else
            log_warning "Health check endpoint not responding after ${max_retries} attempts"
            log_warning "Service may need additional configuration"
        fi
        
        # Show service status
        log_info "Service status:"
        systemctl status "${SERVICE_NAME}" --no-pager -l | head -10
        
    else
        log_error "Service failed to start"
        log_error "Check logs with: journalctl -u ${SERVICE_NAME} -f"
        
        # Show recent logs
        log_info "Recent service logs:"
        journalctl -u "${SERVICE_NAME}" -n 20 --no-pager
        
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
            ;;
        "network")
            echo "=== NETWORK MODE ==="
            echo "Your service accepts connections from the network (0.0.0.0)."
            echo "This allows your Caddy server at 192.168.x.x to connect."
            echo
            echo "Caddy configuration (on your 192.168.x.x server):"
            echo "  ip.example.com {"
            echo "      reverse_proxy YOUR_FLASK_SERVER_IP:5000"
            echo "  }"
            echo
            echo "Replace YOUR_FLASK_SERVER_IP with this server's IP address."
            ;;
        "direct")
            echo "=== DIRECT EXTERNAL ACCESS MODE ==="
            echo "Your service accepts direct external connections."
            echo "No reverse proxy needed - less secure but simpler setup."
            echo
            echo "Test external access:"
            echo "  curl http://YOUR_SERVER_IP:5000/"
            ;;
    esac
    
    echo
    echo "Next steps:"
    echo "1. Edit the configuration file: ${INSTALL_DIR}/.env"
    echo "2. Set your SECRET_KEY and other environment variables"
    if [[ "${DEPLOYMENT_MODE}" != "direct" ]]; then
        echo "3. Configure your Caddy server to point to this Flask app"
    fi
    echo "4. Restart the service: sudo systemctl restart ${SERVICE_NAME}"
    echo
    echo "Useful commands:"
    echo "- Check service status: sudo systemctl status ${SERVICE_NAME}"
    echo "- View logs: sudo journalctl -u ${SERVICE_NAME} -f"
    echo "- Stop service: sudo systemctl stop ${SERVICE_NAME}"
    echo "- Start service: sudo systemctl start ${SERVICE_NAME}"
    echo "- Restart service: sudo systemctl restart ${SERVICE_NAME}"
    echo
    echo "Configuration file: ${INSTALL_DIR}/.env"
    echo "Application logs: ${LOG_DIR}/"
    echo "Service file: ${SYSTEMD_SERVICE_FILE}"
}

# Main deployment function
main() {
    # Get first argument safely and set deployment mode
    local arg1="${1:-}"
    DEPLOYMENT_MODE="${arg1:-network}"  # 'localhost', 'network', or 'direct'
    
    # Show usage if help requested
    if [[ "$arg1" == "-h" || "$arg1" == "--help" ]]; then
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
        echo "The script will:"
        echo "  - Install system dependencies"
        echo "  - Create Python virtual environment"
        echo "  - Install Python packages"
        echo "  - Configure application files"
        echo "  - Generate secure SECRET_KEY automatically"
        echo "  - Install and enable systemd service"
        echo "  - Test the installation"
        exit 0
    fi
    
    log_info "Starting deployment of ${SERVICE_NAME} v${SCRIPT_VERSION} in ${DEPLOYMENT_MODE} mode..."
    
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
trap 'log_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"
