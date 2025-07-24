#!/bin/bash
#
# IP Address Service - Production Deployment Script
# Automated deployment script for setting up the IP service on a production server.
# Handles virtual environment, dependencies, configuration, and systemd service setup.
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration variables
SERVICE_NAME="ip-service"
SERVICE_USER="www-data"
SERVICE_GROUP="www-data" 
INSTALL_DIR="/opt/${SERVICE_NAME}"
VENV_DIR="${INSTALL_DIR}/venv"
LOG_DIR="${INSTALL_DIR}/logs"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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
    
    # Copy requirements.txt to install directory
    if [[ -f "requirements.txt" ]]; then
        cp requirements.txt "${INSTALL_DIR}/"
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/requirements.txt"
        
        # Install dependencies
        sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
        
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found in current directory"
        exit 1
    fi
}

# Copy application files
copy_application_files() {
    log_info "Copying application files..."
    
    # List of files to copy
    local files=("app.py" "config.py" "gunicorn.conf.py")
    
    for file in "${files[@]}"; do
        if [[ -f "${file}" ]]; then
            cp "${file}" "${INSTALL_DIR}/"
            chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/${file}"
            log_info "Copied ${file}"
        else
            log_error "Required file ${file} not found"
            exit 1
        fi
    done
    
    log_success "Application files copied"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    if [[ -f ".env.example" ]]; then
        cp ".env.example" "${INSTALL_DIR}/.env"
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}/.env"
        chmod 600 "${INSTALL_DIR}/.env"  # Secure permissions for env file
        
        # Configure based on deployment mode
        case "${DEPLOYMENT_MODE}" in
            "localhost")
                log_info "Configuring for Caddy on same server (127.0.0.1)"
                sed -i 's/HOST=0.0.0.0/HOST=127.0.0.1/' "${INSTALL_DIR}/.env"
                sed -i 's/# HOST=127.0.0.1/HOST=127.0.0.1/' "${INSTALL_DIR}/.env"
                ;;
            "network")
                log_info "Configuring for Caddy on different server (0.0.0.0)"
                # Default configuration is already set for network mode
                ;;
            "direct")
                log_info "Configuring for direct external access (0.0.0.0)"
                # Default configuration works for direct access too
                ;;
            *)
                log_warning "Unknown deployment mode: ${DEPLOYMENT_MODE}, using network mode"
                ;;
        esac
        
        log_warning "Environment file created from template"
        log_warning "Please edit ${INSTALL_DIR}/.env to configure your settings"
    fi
    
    log_success "Environment configuration setup complete"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    if [[ -f "ip-service.service" ]]; then
        cp "ip-service.service" "${SYSTEMD_SERVICE_FILE}"
        
        # Reload systemd
        systemctl daemon-reload
        
        # Enable service to start on boot
        systemctl enable "${SERVICE_NAME}"
        
        log_success "Systemd service installed and enabled"
    else
        log_error "Systemd service file not found"
        exit 1
    fi
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
    
    # Start the service
    systemctl start "${SERVICE_NAME}"
    
    # Wait a moment for startup
    sleep 3
    
    # Check service status
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_success "Service is running"
        
        # Test health endpoint
        local port=$(grep -oP 'PORT=\K\d+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "5000")
        if curl -f -s "http://127.0.0.1:${port}/health" > /dev/null; then
            log_success "Health check endpoint responding"
        else
            log_warning "Health check endpoint not responding (this may be normal if not configured)"
        fi
        
        # Show service status
        systemctl status "${SERVICE_NAME}" --no-pager -l
        
    else
        log_error "Service failed to start"
        log_error "Check logs with: journalctl -u ${SERVICE_NAME} -f"
        exit 1
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
        exit 0
    fi
    
    log_info "Starting deployment of ${SERVICE_NAME} in ${DEPLOYMENT_MODE} mode..."
    
    check_root
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
