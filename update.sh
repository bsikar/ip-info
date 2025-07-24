#!/bin/bash
#
# IP Address Service - Update Script
# Updates an existing installation with new code while preserving configuration
#

set -euo pipefail

# Configuration
SERVICE_NAME="ip-service"
INSTALL_DIR="/opt/${SERVICE_NAME}"
BACKUP_DIR="/tmp/ip-service-backup-$(date +%Y%m%d-%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Check if service is installed
check_installation() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "IP service not found at $INSTALL_DIR"
        log_error "Use the main deploy script for initial installation"
        exit 1
    fi
    
    if ! systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
        log_error "Systemd service not found: ${SERVICE_NAME}.service"
        log_error "Use the main deploy script for initial installation"
        exit 1
    fi
}

# Create backup
create_backup() {
    log_info "Creating backup at $BACKUP_DIR..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup current files
    cp -r "$INSTALL_DIR" "$BACKUP_DIR/"
    
    # Backup systemd service
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        cp "/etc/systemd/system/${SERVICE_NAME}.service" "$BACKUP_DIR/"
    fi
    
    log_success "Backup created at $BACKUP_DIR"
}

# Stop service
stop_service() {
    log_info "Stopping service..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        log_success "Service stopped"
    else
        log_info "Service was not running"
    fi
}

# Update application files
update_files() {
    log_info "Updating application files..."
    
    # Get script directory
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Update Python files
    local files=("app.py" "config.py" "gunicorn.conf.py")
    
    for file in "${files[@]}"; do
        if [[ -f "${script_dir}/${file}" ]]; then
            cp "${script_dir}/${file}" "${INSTALL_DIR}/"
            chown www-data:www-data "${INSTALL_DIR}/${file}"
            log_info "Updated ${file}"
        else
            log_warning "File not found: ${file}"
        fi
    done
    
    # Update requirements.txt and install new dependencies
    if [[ -f "${script_dir}/requirements.txt" ]]; then
        cp "${script_dir}/requirements.txt" "${INSTALL_DIR}/"
        chown www-data:www-data "${INSTALL_DIR}/requirements.txt"
        
        log_info "Installing updated dependencies..."
        sudo -u www-data "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
        log_success "Dependencies updated"
    fi
    
    # Update systemd service file
    if [[ -f "${script_dir}/ip-service.service" ]]; then
        cp "${script_dir}/ip-service.service" "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        log_info "Updated systemd service"
    fi
    
    log_success "Files updated"
}

# Validate update
validate_update() {
    log_info "Validating update..."
    
    # Test Python imports
    cd "$INSTALL_DIR"
    if ! sudo -u www-data "${INSTALL_DIR}/venv/bin/python" -c "import app; print('App import OK')" &>/dev/null; then
        log_error "App import failed after update"
        return 1
    fi
    
    # Test gunicorn config
    if ! sudo -u www-data "${INSTALL_DIR}/venv/bin/gunicorn" --check-config --config gunicorn.conf.py app:app; then
        log_error "Gunicorn configuration test failed"
        return 1
    fi
    
    log_success "Update validation passed"
}

# Start service
start_service() {
    log_info "Starting service..."
    
    systemctl start "$SERVICE_NAME"
    
    # Wait and check
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "Service started successfully"
        
        # Test endpoint
        local port
        port=$(grep -oP 'PORT=\K\d+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "5000")
        local host
        host=$(grep -oP 'HOST=\K[^\s]+' "${INSTALL_DIR}/.env" 2>/dev/null || echo "127.0.0.1")
        
        if curl -f -s --max-time 5 "http://${host}:${port}/health" > /dev/null 2>&1; then
            log_success "Health check passed"
        else
            log_warning "Health check failed, but service is running"
        fi
    else
        log_error "Service failed to start"
        return 1
    fi
}

# Rollback function
rollback() {
    log_warning "Rolling back to previous version..."
    
    # Stop service
    systemctl stop "$SERVICE_NAME" || true
    
    # Restore from backup
    if [[ -d "${BACKUP_DIR}/ip-service" ]]; then
        rm -rf "${INSTALL_DIR}/"*
        cp -r "${BACKUP_DIR}/ip-service/"* "${INSTALL_DIR}/"
        chown -R www-data:www-data "${INSTALL_DIR}"
    fi
    
    # Restore systemd service
    if [[ -f "${BACKUP_DIR}/${SERVICE_NAME}.service" ]]; then
        cp "${BACKUP_DIR}/${SERVICE_NAME}.service" "/etc/systemd/system/"
        systemctl daemon-reload
    fi
    
    # Start service
    systemctl start "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed - manual intervention required"
        log_error "Backup is available at: $BACKUP_DIR"
    fi
}

# Main function
main() {
    log_info "Starting IP Address Service update..."
    
    check_root
    check_installation
    create_backup
    
    # Stop service
    stop_service
    
    # Update files
    if ! update_files; then
        log_error "Update failed during file update"
        rollback
        exit 1
    fi
    
    # Validate update
    if ! validate_update; then
        log_error "Update validation failed"
        rollback
        exit 1
    fi
    
    # Start service
    if ! start_service; then
        log_error "Service failed to start after update"
        rollback
        exit 1
    fi
    
    log_success "Update completed successfully!"
    log_info "Backup preserved at: $BACKUP_DIR"
    log_info "Remove backup when you're satisfied with the update"
    
    # Show status
    systemctl status "$SERVICE_NAME" --no-pager -l | head -10
}

# Handle script interruption
trap 'log_error "Update interrupted"; exit 1' INT TERM

# Run main function
main "$@"
