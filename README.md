# IP Address Service

A lightweight, production-ready web service that returns client IP addresses in JSON format, similar to ipinfo.io. Designed to work seamlessly behind reverse proxies like Caddy, providing accurate public IP detection for web applications and API consumers.

## Features

- **Accurate IP Detection**: Properly handles various proxy headers (X-Forwarded-For, X-Real-IP, etc.)
- **Production Ready**: Built with Flask and Gunicorn for high-performance deployment
- **Security Focused**: Input validation, rate limiting support, and secure defaults
- **Comprehensive Logging**: Structured logging with configurable levels and rotation
- **Health Monitoring**: Built-in health check endpoint for load balancer integration
- **Easy Deployment**: Automated deployment scripts and systemd integration
- **Caddy Compatible**: Optimized for Caddy reverse proxy configurations

## API Endpoints

### GET /
Returns the client's public IP address in JSON format.

**Response Format:**
```json
{
    "ip": "203.0.113.1",
    "timestamp": "2025-07-24T10:30:00Z",
    "status": "success"
}
```

**Error Response:**
```json
{
    "ip": null,
    "timestamp": "2025-07-24T10:30:00Z",
    "status": "error",
    "error": "Unable to determine public IP address",
    "message": "No valid public IPv4 address found in request"
}
```

### GET /health
Health check endpoint for monitoring and load balancer probes.

**Response Format:**
```json
{
    "status": "healthy",
    "timestamp": "2025-07-24T10:30:00Z",
    "service": "IP Address Service",
    "version": "1.0.0"
}
```

## Quick Start (5 Minutes)

The updated deployment script makes installation foolproof:

```bash
# Clone the repository
git clone https://github.com/your-org/ip-service.git
cd ip-service

# Run the one-command deployment (uses network mode by default)
sudo ./deploy.sh

# That's it! The service is now running and ready for your Caddy configuration.
```

The script automatically:
- Generates a secure SECRET_KEY
- Configures networking for your setup
- Tests everything before completing
- Provides ready-to-use Caddy configuration examples

## Installation

### Prerequisites

- Ubuntu 20.04+ or similar Linux distribution
- Python 3.8 or higher
- Caddy web server (already configured)
- Root or sudo access for system installation

### Recent Improvements

**Version 1.1.0** of the deployment script includes major robustness improvements:

- **Smart Directory Handling**: Can be run from any directory, even the target installation directory
- **Automatic SECRET_KEY Generation**: No more manual editing of configuration files
- **Comprehensive Validation**: Validates all files, imports, and configuration before deployment
- **Better Error Handling**: Clear error messages and automatic cleanup on failure
- **Thorough Testing**: Tests all endpoints and provides detailed status reports
- **Zero-Configuration**: Works out of the box for most common setups

Users who had issues with previous versions should try the updated script!

### Automatic Installation (Recommended)

The deployment script now handles all edge cases and provides a robust installation experience:

1. **Download or clone the project**:
   ```bash
   git clone https://github.com/your-org/ip-service.git
   cd ip-service
   ```

2. **Make the deployment script executable**:
   ```bash
   chmod +x deploy.sh
   ```

3. **Run the deployment script** with the appropriate mode:

   **For Caddy on different server (192.168.x.x) - Most Common:**
   ```bash
   sudo ./deploy.sh network
   ```

   **For Caddy on same server - Most Secure:**
   ```bash
   sudo ./deploy.sh localhost
   ```

   **For direct external access - Least Secure:**
   ```bash
   sudo ./deploy.sh direct
   ```

   **Or simply run with defaults (network mode):**
   ```bash
   sudo ./deploy.sh
   ```

#### What the Script Does Automatically

The enhanced deployment script will:
- ✅ **Validate all required files** before starting
- ✅ **Handle running from any directory** (even the target directory)
- ✅ **Install system dependencies** (Python, pip, build tools)
- ✅ **Create dedicated service user** (www-data)
- ✅ **Set up Python virtual environment** with proper permissions
- ✅ **Install all Python packages** from requirements.txt
- ✅ **Copy and configure application files** with correct ownership
- ✅ **Generate secure SECRET_KEY automatically** (no manual editing needed!)
- ✅ **Configure networking** based on your chosen deployment mode
- ✅ **Install and enable systemd service**
- ✅ **Set up log rotation**
- ✅ **Configure firewall rules** (if ufw is available)
- ✅ **Validate configuration** and test all imports
- ✅ **Test Gunicorn configuration** before starting
- ✅ **Start the service** and verify it's working
- ✅ **Test health and main endpoints** with retries
- ✅ **Provide detailed status and next steps**

#### Troubleshooting

If the deployment fails, the script provides detailed error messages and logs. Common issues are now handled automatically:

- **Missing files**: Script validates all required files exist
- **Permission issues**: Script sets correct ownership and permissions
- **Configuration errors**: Script validates configuration before starting
- **Service startup**: Script tests the service thoroughly before completing

### Manual Installation

If you prefer manual installation or need to customize the process:

1. **Install system dependencies**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv python3-dev build-essential
   ```

2. **Create service user**:
   ```bash
   sudo useradd --system --create-home --shell /bin/false www-data
   ```

3. **Create application directory**:
   ```bash
   sudo mkdir -p /opt/ip-service/logs
   sudo chown -R www-data:www-data /opt/ip-service
   ```

4. **Set up Python environment**:
   ```bash
   cd /opt/ip-service
   sudo -u www-data python3 -m venv venv
   sudo -u www-data venv/bin/pip install -r requirements.txt
   ```

5. **Copy application files**:
   ```bash
   sudo cp app.py config.py gunicorn.conf.py .env.example /opt/ip-service/
   sudo chown www-data:www-data /opt/ip-service/*
   ```

6. **Install systemd service**:
   ```bash
   sudo cp ip-service.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable ip-service
   ```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and customize the following settings:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `FLASK_ENV` | Environment mode | `production` | Yes |
| `SECRET_KEY` | Flask secret key | N/A | Yes (Production) |
| `HOST` | Bind host address | `127.0.0.1` | No |
| `PORT` | Bind port number | `5000` | No |
| `PROXY_COUNT` | Number of proxy layers | `1` | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `GUNICORN_WORKERS` | Number of worker processes | `4` | No |

### Production Configuration

For production deployment, ensure you set:

```bash
# Generate a secure secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Set production environment
FLASK_ENV=production

# Configure for your server
HOST=127.0.0.1
PORT=5000

# Adjust worker count based on your server specs
GUNICORN_WORKERS=4
```

### Network Configuration

#### Option 1: Caddy on Different Server (Most Common)

When Caddy runs on a different server (e.g., 192.168.1.50) than your Flask app:

**Application Configuration:**
```bash
HOST=0.0.0.0    # Accept connections from network
PORT=5000
TRUSTED_PROXIES=192.168.0.0/16  # Trust your network range
```

**Caddy Configuration (on 192.168.1.50):**
```caddy
ip.example.com {
    reverse_proxy 192.168.1.100:5000  # Your Flask server IP
}
```

**Firewall:**
```bash
# Open port 5000 for network access
sudo ufw allow 5000/tcp
```

#### Option 2: Caddy on Same Server (High Security)

When Caddy runs on the same server as your Flask app:

**Application Configuration:**
```bash
HOST=127.0.0.1  # Only accept localhost connections
PORT=5000
```

**Caddy Configuration:**
```caddy
ip.example.com {
    reverse_proxy 127.0.0.1:5000
}
```

**Firewall:** No changes needed (localhost only)

#### Option 3: Direct External Access (Not Recommended)

If you want to skip the reverse proxy entirely:

**Application Configuration:**
```bash
HOST=0.0.0.0    # Accept connections from all interfaces
PORT=5000       # Or your preferred port
```

**Firewall Configuration:**
```bash
# Allow the application port through firewall
sudo ufw allow 5000/tcp
```

## Service Management

### Systemd Commands

```bash
# Start the service
sudo systemctl start ip-service

# Stop the service
sudo systemctl stop ip-service

# Restart the service
sudo systemctl restart ip-service

# Check service status
sudo systemctl status ip-service

# Enable auto-start on boot
sudo systemctl enable ip-service

# Disable auto-start on boot
sudo systemctl disable ip-service
```

### Viewing Logs

```bash
# View real-time logs
sudo journalctl -u ip-service -f

# View recent logs
sudo journalctl -u ip-service -n 100

# View application logs
sudo tail -f /opt/ip-service/logs/ip_service.log

# View access logs
sudo tail -f /opt/ip-service/logs/access.log
```

## Monitoring and Health Checks

### Health Check Endpoint

The service provides a health check endpoint at `/health` that returns the service status. This can be used by load balancers, monitoring systems, or orchestration platforms.

```bash
# Check service health
curl http://127.0.0.1:5000/health
```

### Log Monitoring

The service logs all requests and errors. Key log messages include:

- Client IP extraction results
- Request processing times
- Error conditions and warnings
- Service startup and shutdown events

### Performance Monitoring

Monitor these key metrics:

- **Response Time**: Should be under 50ms for normal requests
- **Error Rate**: Should be under 1% in normal conditions
- **Worker Utilization**: Monitor Gunicorn worker processes
- **Memory Usage**: Typical usage should be under 100MB per worker

## Security Considerations

### IP Address Validation

The service implements comprehensive IP address validation:

- Validates IPv4 format using Python's `ipaddress` module
- Filters out private/internal IP addresses
- Handles proxy header injection attempts
- Logs suspicious IP extraction attempts

### Proxy Security

When running behind a reverse proxy:

- Configure `TRUSTED_PROXIES` to limit which IPs can set forwarded headers
- Set `PROXY_COUNT` to match your actual proxy setup
- Monitor logs for unexpected proxy header values

### Rate Limiting

While the service doesn't implement rate limiting directly, you can add it at the Caddy level:

```caddy
ip.example.com {
    rate_limit {
        zone ip_service {
            key {remote_host}
            events 100  # requests per window
            window 1m   # time window
        }
    }
    reverse_proxy 127.0.0.1:5000
}
```

## Troubleshooting

### Common Issues

#### Service Won't Start

1. **Check configuration**:
   ```bash
   sudo systemctl status ip-service
   sudo journalctl -u ip-service -n 50
   ```

2. **Verify Python environment**:
   ```bash
   sudo -u www-data /opt/ip-service/venv/bin/python -c "import flask; print('Flask imported successfully')"
   ```

3. **Check port availability**:
   ```bash
   sudo netstat -tlnp | grep :5000
   ```

#### Incorrect IP Detection

1. **Check proxy headers**:
   ```bash
   curl -H "X-Forwarded-For: 203.0.113.1" http://127.0.0.1:5000/
   ```

2. **Verify Caddy configuration**:
   - Ensure Caddy is passing the correct headers
   - Check `PROXY_COUNT` setting matches your setup

3. **Review logs**:
   ```bash
   sudo journalctl -u ip-service -f
   ```

#### High Memory Usage

1. **Reduce worker count**:
   ```bash
   # Edit /opt/ip-service/.env
   GUNICORN_WORKERS=2
   sudo systemctl restart ip-service
   ```

2. **Enable worker recycling**:
   ```bash
   # Edit /opt/ip-service/.env
   GUNICORN_MAX_REQUESTS=500
   sudo systemctl restart ip-service
   ```

### Performance Tuning

#### For High Traffic

```bash
# Increase worker count
GUNICORN_WORKERS=8

# Use async workers for I/O bound workloads
GUNICORN_WORKER_CLASS=gevent
GUNICORN_WORKER_CONNECTIONS=1000

# Enable worker recycling
GUNICORN_MAX_REQUESTS=1000
GUNICORN_MAX_REQUESTS_JITTER=100
```

#### For Low Latency

```bash
# Use RAM disk for temporary files
GUNICORN_WORKER_TMP_DIR=/dev/shm

# Reduce timeout for faster failure detection
GUNICORN_TIMEOUT=10

# Enable keep-alive
GUNICORN_KEEPALIVE=5
```

## Development

### Running in Development Mode

```bash
# Set up development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set development environment
export FLASK_ENV=development
export FLASK_DEBUG=true

# Run development server
python3 app.py
```

### Testing Your Setup

#### Test Caddy on Different Server (192.168.x.x)
```bash
# Test the Flask app directly from Flask server
curl http://0.0.0.0:5000/

# Test from Caddy server (192.168.1.50)
curl http://192.168.1.100:5000/  # Replace with Flask server IP

# Test through Caddy (should show real external IP)
curl http://ip.example.com/

# Test that external access works
curl http://YOUR_FLASK_SERVER_EXTERNAL_IP:5000/
```

#### Test Caddy on Same Server
```bash
# Test the Flask app directly (should work)
curl http://127.0.0.1:5000/

# Test through Caddy (should work and show external IP)
curl http://ip.example.com/

# Test external access directly to Flask (should fail - this is good!)
curl http://your-server-ip:5000/  # Should timeout/refuse connection
```

#### Test Direct External Access
```bash
# Test the Flask app locally (should work)
curl http://127.0.0.1:5000/

# Test external access directly (should work)
curl http://your-server-ip:5000/
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review the application logs
3. Create an issue with detailed information about your setup and the problem

## Changelog

### Version 1.0.0
- Initial release
- Basic IP detection functionality
- Caddy reverse proxy support
- Production-ready deployment scripts
- Comprehensive logging and monitoring
