#!/bin/bash

# Colors for better display
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to display colored messages
print_message() {
    echo -e "${1}${2}${NC}"
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_message "$RED" "This script must be run as root!"
        print_message "$YELLOW" "Please try with 'sudo'."
        exit 1
    fi
}

# Function to check service status
check_service_status() {
    service_name=$1
    if systemctl is-active --quiet $service_name; then
        echo "ACTIVE"
    else
        echo "INACTIVE"
    fi
}

# Function to check if package is installed
is_installed() {
    if dpkg -l | grep -q $1; then
        echo "INSTALLED"
    else
        echo "NOT INSTALLED"
    fi
}

# Function to display service status
display_status() {
    echo "╭───────────────────────────────────────────────────╮"    
    print_message "$PURPLE" "           🔒 VPN SERVICES STATUS 🔒             "
    echo "╰───────────────────────────────────────────────────╯"
    
    # Check packages
    oc_status=$(is_installed "openconnect")
    pptp_status=$(is_installed "pptpd")
    wg_status=$(is_installed "wireguard")
    
    # Check services
    ocserv_service="$(check_service_status "ocserv")"
    pptp_service="$(check_service_status "pptpd")"
    wg_service="$(check_service_status "wg-quick@wg0")"
    
    echo "┌───────────────────────────────────────────────────┐"
    
    # Print OpenConnect status with color and emoji
    echo -n "│ "
    if [ "$oc_status" = "INSTALLED" ]; then
        print_message "$GREEN" "💻 OpenConnect package:  ✓ INSTALLED"
    else
        print_message "$RED" "💻 OpenConnect package:  ✗ NOT INSTALLED"
    fi
    
    # Print PPTP status with color and emoji
    echo -n "│ "
    if [ "$pptp_status" = "INSTALLED" ]; then
        print_message "$GREEN" "📡 PPTP package:        ✓ INSTALLED"
    else
        print_message "$RED" "📡 PPTP package:        ✗ NOT INSTALLED"
    fi
    
    # Print WireGuard status with color and emoji
    echo -n "│ "
    if [ "$wg_status" = "INSTALLED" ]; then
        print_message "$GREEN" "🔒 WireGuard package:  ✓ INSTALLED"
    else
        print_message "$RED" "🔒 WireGuard package:  ✗ NOT INSTALLED"
    fi
    
    echo "├───────────────────────────────────────────────────┤"
    
    # Print OpenConnect service status with color and emoji
    echo -n "│ "
    if [ "$ocserv_service" = "ACTIVE" ]; then
        print_message "$GREEN" "🟢 OpenConnect service:  ▶ ACTIVE"
    else
        print_message "$RED" "🔴 OpenConnect service:  ■ INACTIVE"
    fi
    
    # Print PPTP service status with color and emoji
    echo -n "│ "
    if [ "$pptp_service" = "ACTIVE" ]; then
        print_message "$GREEN" "🟢 PPTP service:        ▶ ACTIVE"
    else
        print_message "$RED" "🔴 PPTP service:        ■ INACTIVE"
    fi
    
    # Print WireGuard service status with color and emoji
    echo -n "│ "
    if [ "$wg_service" = "ACTIVE" ]; then
        print_message "$GREEN" "🟢 WireGuard service:  ▶ ACTIVE"
    else
        print_message "$RED" "🔴 WireGuard service:  ■ INACTIVE"
    fi
    
    echo "└───────────────────────────────────────────────────┘"
}

# Function to install required packages
install_packages() {
    print_message "$BLUE" "Installing required packages..."
    apt-get update -y
    apt-get install -y openconnect network-manager-openconnect network-manager-openconnect-gnome
    apt-get install -y pptpd ppp
    apt-get install -y wireguard wireguard-tools
    print_message "$GREEN" "Required packages installed successfully!"
}

# Function to configure PPTP
configure_pptp() {
    print_message "$BLUE" "Configuring PPTP..."
    
    # Configure IP addresses for PPTP
    cat > /etc/pptpd.conf << EOF
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.0.1
remoteip 192.168.0.100-200
EOF
    
    # Configure DNS servers
    cat > /etc/ppp/pptpd-options << EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
lock
nobsdcomp 
novj
novjccomp
nologfd
EOF
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables for NAT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables.rules
    
    # Save iptables rules for reboot
    cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
    
    chmod +x /etc/network/if-up.d/iptables
    
    # Restart service
    systemctl restart pptpd
    systemctl enable pptpd
    
    print_message "$GREEN" "PPTP configuration completed successfully!"
}

# Function to configure OpenConnect (ocserv)
configure_openconnect() {
    print_message "$BLUE" "Configuring OpenConnect..."
    
    # Check if ocserv is already installed
    if [ "$(is_installed "ocserv")" == "INSTALLED" ]; then
        print_message "$YELLOW" "OpenConnect is already installed. Checking if reinstallation is needed..."
        if systemctl is-active --quiet ocserv; then
            print_message "$YELLOW" "OpenConnect service is running. Do you want to reinstall it? (y/n)"
            read -r reinstall
            if [[ "$reinstall" != "y" && "$reinstall" != "Y" ]]; then
                print_message "$GREEN" "Skipping reinstallation."
                return 0
            fi
        fi
    fi
    
    print_message "$BLUE" "Installing OpenConnect dependencies..."
    
    # Install required dependencies with error handling
    apt-get update -y || { 
        print_message "$RED" "Failed to update package lists. Checking internet connection..."
        if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
            print_message "$RED" "No internet connection. Please check your network settings."
            return 1
        else
            print_message "$YELLOW" "Internet connection is working. Repository issue. Trying alternative method..."
            # Try another mirror
            sed -i 's/deb.debian.org/ftp.de.debian.org/g' /etc/apt/sources.list
            apt-get update -y || {
                print_message "$RED" "Failed to update package lists. Please fix repository issues manually."
                return 1
            }
        fi
    }
    
    # Install dependencies
    install_packages=(
        ocserv
        openssl
        libgnutls30
        gnutls-bin
        iptables
        iptables-persistent
    )
    
    for pkg in "${install_packages[@]}"; do
        print_message "$YELLOW" "Installing $pkg..."
        apt-get install -y "$pkg" || {
            print_message "$RED" "Failed to install $pkg. This may cause issues."
            sleep 2
        }
    done
    
    # Verify ocserv installation
    if [ "$(is_installed "ocserv")" != "INSTALLED" ]; then
        print_message "$RED" "Failed to install ocserv! Trying alternative method..."
        
        # Try to install from source if package is not available
        apt-get install -y build-essential libgnutls28-dev libev-dev \
        libwrap0-dev libpam0g-dev liblz4-dev libseccomp-dev libreadline-dev \
        libnl-route-3-dev libkrb5-dev libradcli-dev || {
            print_message "$RED" "Failed to install build dependencies."
            return 1
        }
        
        # Create temporary directory
        TMP_DIR=$(mktemp -d)
        cd "$TMP_DIR" || {
            print_message "$RED" "Failed to create temporary directory."
            return 1
        }
        
        # Download ocserv source
        print_message "$YELLOW" "Downloading ocserv source..."
        wget https://www.infradead.org/ocserv/download/ocserv-1.1.6.tar.xz || {
            print_message "$RED" "Failed to download ocserv source."
            rm -rf "$TMP_DIR"
            return 1
        }
        
        # Extract and compile
        tar -xf ocserv-1.1.6.tar.xz || {
            print_message "$RED" "Failed to extract source archive."
            rm -rf "$TMP_DIR"
            return 1
        }
        
        cd ocserv-1.1.6 || {
            print_message "$RED" "Failed to enter source directory."
            rm -rf "$TMP_DIR"
            return 1
        }
        
        ./configure && make && make install || {
            print_message "$RED" "Failed to compile ocserv from source."
            rm -rf "$TMP_DIR"
            return 1
        }
        
        # Cleanup
        cd /
        rm -rf "$TMP_DIR"
        
        # Check if installed successfully
        if ! command -v ocserv >/dev/null 2>&1 && ! command -v ocpasswd >/dev/null 2>&1; then
            print_message "$RED" "Failed to install ocserv from source."
            return 1
        fi
        
        # Create systemd service file if needed
        if [ ! -f "/etc/systemd/system/ocserv.service" ] && [ ! -f "/lib/systemd/system/ocserv.service" ]; then
            print_message "$YELLOW" "Creating systemd service file..."
            cat > /etc/systemd/system/ocserv.service << EOF
[Unit]
Description=OpenConnect SSL VPN server
Documentation=man:ocserv(8)
After=network-online.target
Requires=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/ocserv --foreground --config=/etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP \$MAINPID
ProtectHome=true
ProtectSystem=full
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
        fi
    fi
    
    # Create ocserv configuration directories
    mkdir -p /etc/ocserv/ssl
    cd /etc/ocserv/ssl || {
        print_message "$RED" "Failed to create/access certificate directory."
        return 1
    }
    
    # Generate certificates with proper error handling
    print_message "$YELLOW" "Generating SSL certificates for OpenConnect..."
    
    # Generate CA key
    print_message "$YELLOW" "Creating CA certificate..."
    if [ ! -f "ca-key.pem" ]; then
        openssl genrsa -out ca-key.pem 4096 2>/dev/null || {
            print_message "$RED" "Failed to generate CA key."
            return 1
        }
    fi
    
    # Generate CA certificate
    if [ ! -f "ca-cert.pem" ]; then
        openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=VPN-CA/CN=VPN-Root-CA" 2>/dev/null || {
            print_message "$RED" "Failed to generate CA certificate."
            return 1
        }
    fi
    
    # Generate server key
    print_message "$YELLOW" "Creating server key..."
    if [ ! -f "server-key.pem" ]; then
        openssl genrsa -out server-key.pem 2048 2>/dev/null || {
            print_message "$RED" "Failed to generate server key."
            return 1
        }
    fi
    
    # Generate server certificate signing request
    SERVER_HOSTNAME=$(hostname)
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    
    print_message "$YELLOW" "Creating certificate request..."
    if [ ! -f "server-req.pem" ]; then
        openssl req -new -key server-key.pem -out server-req.pem \
        -subj "/C=US/ST=State/L=City/O=VPN-Server/CN=$SERVER_HOSTNAME" 2>/dev/null || {
            print_message "$RED" "Failed to generate certificate request."
            return 1
        }
    fi
    
    # Create openssl extension file for SAN
    cat > san.ext << EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = $SERVER_HOSTNAME
IP.1 = $SERVER_IP
EOF
    
    # Sign the server certificate with our CA
    print_message "$YELLOW" "Signing server certificate with CA..."
    openssl x509 -req -days 3650 -in server-req.pem \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -extfile san.ext \
    -out server-cert.pem 2>/dev/null || {
        print_message "$RED" "Failed to sign server certificate."
        return 1
    }
    
    # Verify the certificate
    openssl verify -CAfile ca-cert.pem server-cert.pem || {
        print_message "$RED" "Certificate verification failed."
        return 1
    }
    
    # Set proper permissions
    chmod 600 ca-key.pem server-key.pem
    chmod 644 ca-cert.pem server-cert.pem
    
    # Create initial ocpasswd file if it doesn't exist
    if [ ! -f "/etc/ocserv/ocpasswd" ]; then
        touch /etc/ocserv/ocpasswd
        chmod 600 /etc/ocserv/ocpasswd
    fi
    
    # Create user-expiry file if it doesn't exist
    if [ ! -f "/etc/ocserv/user-expiry" ]; then
        touch /etc/ocserv/user-expiry
        chmod 600 /etc/ocserv/user-expiry
    fi
    
    # Detect the main network interface
    MAIN_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
    if [ -z "$MAIN_INTERFACE" ]; then
        print_message "$YELLOW" "Could not auto-detect the network interface. Using eth0 as fallback."
        MAIN_INTERFACE="eth0"
    fi
    
    # Create ocserv.conf file with optimal settings
    print_message "$YELLOW" "Creating OpenConnect configuration..."
    cat > /etc/ocserv/ocserv.conf << EOF
# OpenConnect Server (ocserv) optimized configuration
# Maintained as part of VPN Setup Script

# User authentication
auth = "plain[passwd=/etc/ocserv/ocpasswd]"

# Network settings
tcp-port = 4443
udp-port = 4443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket

# TLS/SSL settings
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true

# Isolation and security
isolate-workers = true
max-clients = 128
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
cookie-validate = true
rekey-time = 172800
rekey-method = ssl
use-occtl = true
device = vpns
predictable-ips = true
output-buffer = 1000

# Connection settings
mtu = 1400
switch-to-tcp-timeout = 25
try-mtu-discovery = true

# DNS and routing
default-domain = vpn.local
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.10.0/255.255.255.0
ping-leases = true

# Compatibility
cisco-client-compat = true
dtls-legacy = true
user-profile = profile.xml

# Logging and debugging
syslog = true
log-level = 1
EOF
    
    # Create a directory for runtime files if it doesn't exist
    mkdir -p /var/run/
    chmod 755 /var/run/
    
    # Enable IP forwarding
    print_message "$YELLOW" "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-vpn-forward.conf
    sysctl -p /etc/sysctl.d/60-vpn-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Configure firewall rules with error handling
    print_message "$YELLOW" "Configuring firewall rules for OpenConnect..."
    
    # Clear previous rules
    iptables -t nat -F
    
    # Add new NAT rule for OpenConnect
    iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o "$MAIN_INTERFACE" -j MASQUERADE || {
        print_message "$RED" "Failed to set up NAT rules."
        print_message "$YELLOW" "Manual NAT setup may be required."
    }
    
    # Persist iptables rules
    if command -v iptables-save >/dev/null 2>&1; then
        if [ -d "/etc/iptables" ]; then
            iptables-save > /etc/iptables/rules.v4
        else
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
        fi
    else
        print_message "$YELLOW" "iptables-save not found. Installing iptables-persistent..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        iptables-save > /etc/iptables/rules.v4
    fi
    
    # Create a script to restore iptables rules on boot
    cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
EOF
    chmod +x /etc/network/if-up.d/iptables
    
    # Restart and enable ocserv
    print_message "$YELLOW" "Starting OpenConnect service..."
    systemctl daemon-reload
    systemctl restart ocserv || {
        print_message "$RED" "Failed to start ocserv service."
        print_message "$YELLOW" "Checking error logs..."
        journalctl -u ocserv --no-pager -n 20
        return 1
    }
    systemctl enable ocserv
    
    # Verify service status with comprehensive checks
    print_message "$YELLOW" "Verifying OpenConnect service..."
    
    # Check service status
    if systemctl is-active --quiet ocserv; then
        print_message "$GREEN" "✅ OpenConnect service started successfully!"
    else
        print_message "$RED" "❌ OpenConnect service failed to start."
        print_message "$YELLOW" "Attempting to diagnose the issue..."
        
        # Check for common issues
        if ! command -v ocserv >/dev/null 2>&1; then
            print_message "$RED" "ocserv binary not found in PATH. Installation failed."
        fi
        
        # Check certificate files
        for cert_file in "/etc/ocserv/ssl/ca-cert.pem" "/etc/ocserv/ssl/server-cert.pem" "/etc/ocserv/ssl/server-key.pem"; do
            if [ ! -f "$cert_file" ]; then
                print_message "$RED" "Certificate file missing: $cert_file"
            else
                print_message "$GREEN" "Certificate file exists: $cert_file"
            fi
        done
        
        # Check socket file path
        if ! grep -q "socket-file = /var/run/ocserv-socket" /etc/ocserv/ocserv.conf; then
            print_message "$RED" "Socket file configuration is incorrect."
        fi
        
        # Check for port conflicts
        if netstat -tuln | grep -q ":4443"; then
            print_message "$RED" "Port 4443 is already in use by another service. This will prevent OpenConnect from starting."
            netstat -tuln | grep ":4443"
        fi
        
        print_message "$YELLOW" "OpenConnect service log:"
        journalctl -u ocserv --no-pager -n 30
        
        print_message "$YELLOW" "Please fix the issues above and then run 'systemctl restart ocserv'."
        return 1
    fi
    
    # Check if ports are open
    if netstat -tuln | grep -q ":4443"; then
        print_message "$GREEN" "✅ OpenConnect port 4443 is open and listening."
    else
        print_message "$RED" "❌ OpenConnect port 4443 is NOT listening."
        print_message "$YELLOW" "This may indicate a configuration issue. Checking connections..."
        netstat -tuln
    fi
    
    # Provide connection information
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    print_message "$GREEN" "OpenConnect configuration completed!"
    print_message "$YELLOW" "Connection Information:"
    print_message "$YELLOW" "Server: $SERVER_IP"
    print_message "$YELLOW" "Port: 4443"
    print_message "$YELLOW" "Protocol: OpenConnect/AnyConnect"
    print_message "$YELLOW" "To create users, use the 'Create VPN User' option from the main menu."
    
    return 0
}

# Function to create PPTP user
create_pptp_user() {
    username=$1
    password=$2
    expiry_days=$3
    
    print_message "$BLUE" "Creating PPTP user: $username"
    
    # Add user to chap-secrets file
    echo "$username pptpd $password *" >> /etc/ppp/chap-secrets
    
    # Set expiry date
    if [ ! -z "$expiry_days" ]; then
        expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
        echo "$username:$expiry_date" >> /etc/ppp/user-expiry
    fi
    
    print_message "$GREEN" "PPTP user '$username' created successfully!"
    if [ ! -z "$expiry_days" ]; then
        print_message "$YELLOW" "This account will expire on $expiry_date."
    fi
}

# Function to create OpenConnect user
create_openconnect_user() {
    username=$1
    password=$2
    expiry_days=$3
    
    print_message "$BLUE" "Creating OpenConnect user: $username"
    
    # Create user in ocserv
    echo "$password" | ocpasswd -c /etc/ocserv/ocpasswd "$username"
    
    # Set expiry date
    if [ ! -z "$expiry_days" ]; then
        expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
        echo "$username:$expiry_date" >> /etc/ocserv/user-expiry
    fi
    
    print_message "$GREEN" "OpenConnect user '$username' created successfully!"
    if [ ! -z "$expiry_days" ]; then
        print_message "$YELLOW" "This account will expire on $expiry_date."
    fi
}

# Function to check and remove expired users
check_expired_users() {
    current_date=$(date +%Y-%m-%d)
    
    print_message "$BLUE" "Checking for expired users..."
    
    # Check expired PPTP users
    if [ -f "/etc/ppp/user-expiry" ]; then
        while IFS=: read -r username expiry_date; do
            if [[ "$current_date" > "$expiry_date" ]]; then
                print_message "$YELLOW" "PPTP user '$username' has expired. Removing..."
                sed -i "/^$username pptpd/d" /etc/ppp/chap-secrets
                sed -i "/^$username:/d" /etc/ppp/user-expiry
                print_message "$GREEN" "PPTP user '$username' removed successfully!"
            fi
        done < /etc/ppp/user-expiry
    fi
    
    # Check expired OpenConnect users
    if [ -f "/etc/ocserv/user-expiry" ]; then
        while IFS=: read -r username expiry_date; do
            if [[ "$current_date" > "$expiry_date" ]]; then
                print_message "$YELLOW" "OpenConnect user '$username' has expired. Removing..."
                ocpasswd -c /etc/ocserv/ocpasswd -d "$username"
                sed -i "/^$username:/d" /etc/ocserv/user-expiry
                print_message "$GREEN" "OpenConnect user '$username' removed successfully!"
            fi
        done < /etc/ocserv/user-expiry
    fi
    
    print_message "$GREEN" "Expired user check completed!"
}

# Function to setup cron job for automatic expired user check
setup_expiry_cron() {
    print_message "$BLUE" "Setting up cron job for automatic expired user check..."
    
    # Create script to be run by cron
    cat > /usr/local/bin/check_vpn_users.sh << EOF
#!/bin/bash
$(declare -f print_message)
$(declare -f check_expired_users)
check_expired_users
EOF
    
    chmod +x /usr/local/bin/check_vpn_users.sh
    
    # Add cron job to run script daily
    (crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/check_vpn_users.sh") | crontab -
    
    print_message "$GREEN" "Cron job setup successfully!"
}

# Debug function for VPN services
debug_vpn_services() {
    print_message "$BLUE" "Starting advanced debugging and fixing process..."
    
    # Create debug log if it doesn't exist
    touch /var/log/vpn_setup_debug.log
    
    # Log debug start time
    echo "$(date) - Advanced debug process started" >> /var/log/vpn_setup_debug.log
    
    # Check system for necessary tools
    print_message "$BLUE" "Checking system tools..."
    for tool in netstat ip iptables grep sed; do
        if ! which $tool > /dev/null 2>&1; then
            print_message "$YELLOW" "Installing required tool: $tool"
            apt-get update -y && apt-get install -y net-tools iproute2 iptables grep sed
            break
        fi
    done
    
    # Check Internet connectivity
    print_message "$BLUE" "Checking internet connectivity..."
    if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
        print_message "$RED" "WARNING: No internet connectivity detected! VPN server needs internet access."
        echo "$(date) - No internet connectivity" >> /var/log/vpn_setup_debug.log
    else
        print_message "$GREEN" "Internet connectivity: OK"
    fi
    
    # Check main network interface
    MAIN_INTERFACE=$(ip route | grep default | awk '{print $5}')
    print_message "$BLUE" "Main network interface detected: $MAIN_INTERFACE"
    echo "$(date) - Main interface: $MAIN_INTERFACE" >> /var/log/vpn_setup_debug.log
    
    # Reset and reinstall packages if requested
    print_message "$YELLOW" "Performing complete check and reinstallation of VPN packages..."
    # Completely remove and reinstall OpenConnect
    apt-get purge -y ocserv
    apt-get update -y
    apt-get install -y ocserv
    
    # Reinstall PPTP
    apt-get purge -y pptpd
    apt-get update -y
    apt-get install -y pptpd ppp
    
    # Reinstall WireGuard
    apt-get purge -y wireguard
    apt-get update -y
    apt-get install -y wireguard
    
    # ------- Fix PPTP Configuration -------
    print_message "$BLUE" "Fixing PPTP configuration..."
    
    # Configure PPTP for correct network interface
    cat > /etc/pptpd.conf << EOF
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.0.1
remoteip 192.168.0.100-200
EOF
    
    # Configure PPTP options properly
    cat > /etc/ppp/pptpd-options << EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
lock
nobsdcomp 
novj
novjccomp
nologfd
debug
EOF
    
    # Check if chap-secrets exists, if not create it
    if [ ! -f "/etc/ppp/chap-secrets" ]; then
        touch /etc/ppp/chap-secrets
        chmod 600 /etc/ppp/chap-secrets
    fi
    
    # ------- Fix OpenConnect Configuration -------
    print_message "$BLUE" "Fixing OpenConnect configuration..."
    
    # Create certificates directory and generate new certificates
    mkdir -p /etc/ocserv/ssl
    cd /etc/ocserv/ssl
    
    # Generate new certificate files
    openssl genrsa -out server-key.pem 2048
    openssl req -new -x509 -days 3650 -key server-key.pem -out server-cert.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=$(hostname)"
    
    # Set proper permissions
    chmod 600 server-key.pem
    chmod 644 server-cert.pem
    
    # Create a more compatible OpenConnect configuration
    cat > /etc/ocserv/ocserv.conf << EOF
# OpenConnect Server (ocserv) optimized configuration
# Maintained as part of VPN Setup Script

# User authentication
auth = "plain[passwd=/etc/ocserv/ocpasswd]"

# Network settings
tcp-port = 4443
udp-port = 4443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket

# TLS/SSL settings
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/server-cert.pem
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true

# Isolation and security
isolate-workers = true
max-clients = 100
max-same-clients = 2
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
denied-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.10.0/255.255.255.0
no-route = 192.168.0.0/255.255.255.0
cisco-client-compat = true
dtls-legacy = true
user-profile = profile.xml

# Compatibility
cisco-client-compat = true
dtls-legacy = true
EOF
    
    # Create ocpasswd file if it doesn't exist
    if [ ! -f "/etc/ocserv/ocpasswd" ]; then
        touch /etc/ocserv/ocpasswd
        chmod 600 /etc/ocserv/ocpasswd
    fi
    
    # ------- Fix IP forwarding and firewall rules -------
    print_message "$BLUE" "Configuring IP forwarding and firewall..."
    
    # Enable IP forwarding in sysctl.conf and apply immediately
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Flush existing rules
    iptables -F
    iptables -t nat -F
    
    # Set up NAT for VPN traffic with detected interface
    iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o "$MAIN_INTERFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o "$MAIN_INTERFACE" -j MASQUERADE
    
    # Allow forwarding
    iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    
    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    # Make iptables persistent
    cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
EOF
    chmod +x /etc/network/if-up.d/iptables
    
    # ------- Fix permissions and restart services -------
    print_message "$BLUE" "Setting correct permissions and restarting services..."
    
    # Fix permissions
    chown -R root:root /etc/ppp
    chmod 600 /etc/ppp/chap-secrets
    
    chown -R root:root /etc/ocserv
    chmod 700 /etc/ocserv/ssl
    chmod 600 /etc/ocserv/ssl/server-key.pem
    chmod 644 /etc/ocserv/ssl/server-cert.pem
    chmod 600 /etc/ocserv/ocpasswd
    
    # Restart services
    systemctl daemon-reload
    
    print_message "$YELLOW" "Restarting PPTP service..."
    systemctl restart pptpd
    systemctl enable pptpd
    
    print_message "$YELLOW" "Restarting OpenConnect service..."
    systemctl restart ocserv
    systemctl enable ocserv
    
    # Wait for services to start properly
    sleep 3
    
    # ------- Test connectivity -------
    print_message "$BLUE" "Testing VPN connectivity..."
    
    # Check if services are running
    pptp_status=$(systemctl is-active pptpd)
    ocserv_status=$(systemctl is-active ocserv)
    
    print_message "$YELLOW" "PPTP service status: $pptp_status"
    print_message "$YELLOW" "OpenConnect service status: $ocserv_status"
    
    # Check if ports are open
    print_message "$BLUE" "Checking if VPN ports are open and listening..."
    if netstat -tuln | grep -q ":1723"; then
        print_message "$GREEN" "PPTP port (1723) is open and listening"
    else
        print_message "$RED" "PPTP port (1723) is NOT listening - service may not be working properly"
    fi
    
    if netstat -tuln | grep -q ":4443"; then
        print_message "$GREEN" "OpenConnect port (4443) is open and listening"
    else
        print_message "$RED" "OpenConnect port (4443) is NOT listening - service may not be working properly"
    fi
    
    # Show connection information for client
    print_message "$BLUE" "===== VPN CONNECTION INFORMATION ====="
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    print_message "$GREEN" "PPTP Connection Information:"
    print_message "$YELLOW" "  Server: $SERVER_IP"
    print_message "$YELLOW" "  Username: (as created in the user menu)"
    print_message "$YELLOW" "  Password: (as created in the user menu)"
    print_message "$YELLOW" "  Encryption: MPPE 128-bit"
    
    print_message "$GREEN" "OpenConnect (AnyConnect) Connection Information:"
    print_message "$YELLOW" "  Server: $SERVER_IP:4443"
    print_message "$YELLOW" "  Username: (as created in the user menu)"
    print_message "$YELLOW" "  Password: (as created in the user menu)"
    
    # Final log entry
    echo "$(date) - Debug process completed" >> /var/log/vpn_setup_debug.log
    print_message "$BLUE" "Debug log saved to /var/log/vpn_setup_debug.log"
    
    print_message "$GREEN" "====================================="
    print_message "$GREEN" "VPN services have been reconfigured and restarted."
    print_message "$GREEN" "If you still have connection issues:"
    print_message "$YELLOW" "1. Make sure your server firewall allows ports 1723 (PPTP) and 4443 (OpenConnect)"
    print_message "$YELLOW" "2. Try creating a new user using menu option 2"
    print_message "$YELLOW" "3. Check your client VPN settings match the connection information above"
    print_message "$GREEN" "====================================="
}

# Function to create users for both VPN systems at once
create_vpn_user() {
    # Check if arguments were provided, if not prompt for them
    local username=$1
    local password=$2
    local expiry_days=$3
    
    # If no username provided, prompt for it
    if [ -z "$username" ]; then
        echo -n "Enter username for the new VPN user: "
        read -r username
        
        # Verify username is not empty
        if [ -z "$username" ]; then
            print_message "$RED" "Error: Username cannot be empty!"
            return 1
        fi
    fi
    
    # Check if username already exists
    if grep -q "^$username " /etc/ppp/chap-secrets || grep -q "^$username:" /etc/ocserv/ocpasswd 2>/dev/null; then
        print_message "$RED" "Error: User '$username' already exists!"
        return 1
    fi
    
    # If no password provided, prompt for it
    if [ -z "$password" ]; then
        echo -n "Enter password for user '$username': "
        read -r password
        
        # Verify password is not empty
        if [ -z "$password" ]; then
            print_message "$RED" "Error: Password cannot be empty!"
            return 1
        fi
    fi
    
    # If no expiry days provided, ask if user wants to set it
    if [ -z "$expiry_days" ]; then
        echo -n "Set expiry date in days (leave empty for no expiry): "
        read -r expiry_days
    fi
    
    print_message "$BLUE" "Creating VPN user for both PPTP and OpenConnect: $username"
    
    # Create user in PPTP
    echo "$username pptpd $password *" >> /etc/ppp/chap-secrets
    
    # Create user in OpenConnect
    echo "$password" | ocpasswd -c /etc/ocserv/ocpasswd "$username"
    
    # Set expiry date if provided
    if [ ! -z "$expiry_days" ] && [[ "$expiry_days" =~ ^[0-9]+$ ]]; then
        expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
        
        # Set expiry for PPTP
        echo "$username:$expiry_date" >> /etc/ppp/user-expiry
        
        # Set expiry for OpenConnect
        echo "$username:$expiry_date" >> /etc/ocserv/user-expiry
        
        print_message "$YELLOW" "This account will expire on $expiry_date."
    fi
    
    # Restart PPTP service to apply changes immediately
    print_message "$BLUE" "Restarting PPTP service to apply changes..."
    systemctl restart pptpd
    
    print_message "$GREEN" "VPN user '$username' successfully created for both services!"
}

# Function to create WireGuard VPN user
create_wireguard_user() {
    print_message "$BLUE" "Creating WireGuard VPN user..."
    
    # Check if WireGuard is installed
    if ! command -v wg &> /dev/null; then
        print_message "$RED" "WireGuard is not installed! Please install it first."
        read -p "Do you want to install WireGuard now? (y/n): " install_wg
        if [[ "$install_wg" =~ ^[Yy]$ ]]; then
            install_wireguard
        else
            return 1
        fi
    fi
    
    # Check if server is configured
    WG_DIR="/etc/wireguard"
    if [ ! -f "$WG_DIR/wg0.conf" ]; then
        print_message "$RED" "WireGuard server configuration not found!"
        print_message "$YELLOW" "Setting up WireGuard server configuration..."
        install_wireguard
    fi
    
    # Get username
    print_message "$YELLOW" "Please enter a username for the WireGuard client:"
    read -r username
    
    # Validate username
    if [ -z "$username" ]; then
        print_message "$RED" "Username cannot be empty!"
        return 1
    fi
    
    # Check if client directory exists
    CLIENT_DIR="$WG_DIR/clients"
    mkdir -p "$CLIENT_DIR"
    
    # Check if user already exists
    if [ -f "$CLIENT_DIR/$username.conf" ]; then
        print_message "$RED" "A user with this name already exists!"
        read -p "Do you want to overwrite? (y/n): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    # Generate client keys
    print_message "$YELLOW" "Generating client keys..."
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # Get server information
    SERVER_PUBLIC_KEY=$(cat "$WG_DIR/server_public.key")
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    SERVER_PORT=$(grep -oP 'ListenPort = \K\d+' "$WG_DIR/wg0.conf" || echo "51820")
    
    # Find an available IP in the 10.10.10.0/24 subnet
    # First check how many peers we already have
    PEER_COUNT=$(grep -c "\[Peer\]" "$WG_DIR/wg0.conf")
    # Start from client IP .2 (.1 is server)
    CLIENT_IP_LAST_OCTET=$((PEER_COUNT + 2))
    # Ensure we stay in valid range
    if [ "$CLIENT_IP_LAST_OCTET" -gt 254 ]; then
        print_message "$RED" "Maximum number of clients reached!"
        return 1
    fi
    CLIENT_IP="10.10.10.$CLIENT_IP_LAST_OCTET"
    
    # Create client configuration
    print_message "$YELLOW" "Creating client configuration..."
    cat > "$CLIENT_DIR/$username.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Set permissions
    chmod 600 "$CLIENT_DIR/$username.conf"
    
    # Add peer to server configuration
    print_message "$YELLOW" "Adding client to server configuration..."
    
    # Create a temporary config to add the peer
    cat >> "$WG_DIR/wg0.conf" << EOF

# Client: $username
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32
EOF
    
    # Restart WireGuard to apply changes
    print_message "$YELLOW" "Restarting WireGuard service to apply changes..."
    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || systemctl restart wg-quick@wg0
    
    # Create QR code for easy mobile setup
    if command -v qrencode &> /dev/null; then
        print_message "$YELLOW" "Generating QR code for mobile setup..."
        qrencode -t ansiutf8 < "$CLIENT_DIR/$username.conf"
    else
        print_message "$YELLOW" "QR code generation requires qrencode package. Installing..."
        apt-get update && apt-get install -y qrencode
        if command -v qrencode &> /dev/null; then
            print_message "$GREEN" "QR code generation ready."
            qrencode -t ansiutf8 < "$CLIENT_DIR/$username.conf"
        else
            print_message "$RED" "Failed to install qrencode. QR code not available."
        fi
    fi
    
    # Display connection information
    print_message "$GREEN" "✅ WireGuard VPN user created successfully!"
    print_message "$YELLOW" "Configuration file saved to: $CLIENT_DIR/$username.conf"
    print_message "$YELLOW" "To connect, transfer this file to the client device."
    print_message "$YELLOW" "For mobile devices, scan the QR code above with the WireGuard app."
    print_message "$BLUE" "Connection details:"
    print_message "$YELLOW" "Server: $SERVER_IP"
    print_message "$YELLOW" "Port: $SERVER_PORT"
    print_message "$YELLOW" "Client IP: $CLIENT_IP"
    
    return 0
}

# Function to change OpenConnect port
change_openconnect_port() {
    print_message "$BLUE" "Change OpenConnect Port"
    echo ""
    
    # Check if OpenConnect configuration file exists
    if [ ! -f "/etc/ocserv/ocserv.conf" ]; then
        print_message "$RED" "OpenConnect configuration file not found! Please run option 5 first to fix issues."
        return
    fi
    
    # Get current port
    current_tcp_port=$(grep -E "^tcp-port =" /etc/ocserv/ocserv.conf | awk '{print $3}')
    current_udp_port=$(grep -E "^udp-port =" /etc/ocserv/ocserv.conf | awk '{print $3}')
    
    print_message "$YELLOW" "Current TCP port: $current_tcp_port"
    print_message "$YELLOW" "Current UDP port: $current_udp_port"
    echo ""
    
    # Ask for new port
    echo -n "Enter new port number (1024-65535): "
    read -r new_port
    
    # Validate input
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        print_message "$RED" "Invalid port number! Port must be between 1024-65535."
        return
    fi
    
    # Check if port is already in use
    if netstat -tuln | grep -q ":$new_port "; then
        print_message "$RED" "Port $new_port is already in use by another service!"
        print_message "$YELLOW" "Please choose a different port."
        return
    fi
    
    # Update port in configuration
    print_message "$BLUE" "Changing OpenConnect port to $new_port..."
    sed -i "s/^tcp-port = .*/tcp-port = $new_port/" /etc/ocserv/ocserv.conf
    sed -i "s/^udp-port = .*/udp-port = $new_port/" /etc/ocserv/ocserv.conf
    
    # Restart OpenConnect service
    systemctl restart ocserv
    sleep 2
    
    # Check if service started successfully
    if [ "$(check_service_status "ocserv")" = "ACTIVE" ]; then
        print_message "$GREEN" "OpenConnect port successfully changed to $new_port!"
        print_message "$YELLOW" "Connection Information:"
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
        print_message "$YELLOW" "  Server: $SERVER_IP:$new_port"
    else
        print_message "$RED" "Failed to restart OpenConnect service with new port."
        print_message "$YELLOW" "Rolling back to previous port settings..."
        sed -i "s/^tcp-port = .*/tcp-port = $current_tcp_port/" /etc/ocserv/ocserv.conf
        sed -i "s/^udp-port = .*/udp-port = $current_udp_port/" /etc/ocserv/ocserv.conf
        systemctl restart ocserv
    fi
}

# Function to backup VPN settings and users
backup_vpn_settings() {
    print_message "$BLUE" "Backing up VPN settings and users..."
    echo ""
    
    # Check for available disk space (need at least 10MB free)
    free_space=$(df -m /root | awk 'NR==2 {print $4}')
    if [ "$free_space" -lt 10 ]; then
        print_message "$RED" "Not enough disk space available! Need at least 10MB."
        print_message "$YELLOW" "Available space: ${free_space}MB"
        return 1
    fi
    
    # Create backup directory if it doesn't exist
    mkdir -p /root/vpn_backups
    
    # Generate timestamp for backup file
    timestamp=$(date +"%Y%m%d_%H%M%S")
    backup_file="/root/vpn_backups/vpn_backup_$timestamp.tar.gz"
    
    # Create temporary directory for backup files
    temp_dir="/tmp/vpn_backup_temp"
    mkdir -p "$temp_dir"
    
    # Export users and settings to single-line files for easy restoration
    # PPTP users export
    print_message "$YELLOW" "Exporting PPTP users..."
    if [ -f "/etc/ppp/chap-secrets" ]; then
        cp "/etc/ppp/chap-secrets" "$temp_dir/pptp_users.txt"
    fi
    
    # PPTP user expiry export
    if [ -f "/etc/ppp/user-expiry" ]; then
        cp "/etc/ppp/user-expiry" "$temp_dir/pptp_expiry.txt"
    fi
    
    # OpenConnect users export (convert to single line format)
    print_message "$YELLOW" "Exporting OpenConnect users..."
    if [ -f "/etc/ocserv/ocpasswd" ]; then
        cp "/etc/ocserv/ocpasswd" "$temp_dir/ocserv_users.txt"
    fi
    
    # OpenConnect user expiry export
    if [ -f "/etc/ocserv/user-expiry" ]; then
        cp "/etc/ocserv/user-expiry" "$temp_dir/ocserv_expiry.txt"
    fi
    
    # Export configuration files
    print_message "$YELLOW" "Exporting configuration files..."
    
    # PPTP config files
    if [ -f "/etc/pptpd.conf" ]; then
        cp "/etc/pptpd.conf" "$temp_dir/pptpd.conf"
    fi
    
    if [ -f "/etc/ppp/pptpd-options" ]; then
        cp "/etc/ppp/pptpd-options" "$temp_dir/pptpd-options"
    fi
    
    # OpenConnect config
    if [ -f "/etc/ocserv/ocserv.conf" ]; then
        cp "/etc/ocserv/ocserv.conf" "$temp_dir/ocserv.conf"
        
        # Extract port settings to a separate file for easy reference
        grep -E "^(tcp|udp)-port =" "/etc/ocserv/ocserv.conf" > "$temp_dir/ocserv_ports.txt"
    fi
    
    # Export certificates
    if [ -d "/etc/ocserv/ssl" ]; then
        mkdir -p "$temp_dir/ssl"
        cp -r /etc/ocserv/ssl/* "$temp_dir/ssl/"
    fi
    
    # Export firewall rules
    print_message "$YELLOW" "Exporting firewall rules..."
    iptables-save > "$temp_dir/iptables_rules.txt"
    
    # Export system settings
    print_message "$YELLOW" "Exporting system settings..."
    if [ -f "/etc/sysctl.conf" ]; then
        grep "ip_forward" "/etc/sysctl.conf" > "$temp_dir/ip_forward_setting.txt"
    fi
    
    # Create single-line summary file with important information
    print_message "$YELLOW" "Creating backup summary..."
    
    # Count users
    pptp_users=$(grep -v "#" "$temp_dir/pptp_users.txt" 2>/dev/null | wc -l)
    ocserv_users=$(grep -v "#" "$temp_dir/ocserv_users.txt" 2>/dev/null | wc -l)
    
    # Get ports
    tcp_port=$(grep "tcp-port" "$temp_dir/ocserv_ports.txt" 2>/dev/null | awk '{print $3}')
    udp_port=$(grep "udp-port" "$temp_dir/ocserv_ports.txt" 2>/dev/null | awk '{print $3}')
    
    # Create summary
    cat > "$temp_dir/backup_summary.txt" << EOF
Backup date: $(date)
PPTP users: $pptp_users
OpenConnect users: $ocserv_users
OpenConnect TCP port: $tcp_port
OpenConnect UDP port: $udp_port
System: $(uname -a)
EOF
    
    # Ask if user wants to encrypt the backup
    echo -n "Do you want to encrypt this backup file? (y/N): "
    read -r encrypt_backup
    
    # Compress all files into a single tarball
    print_message "$YELLOW" "Compressing backup files..."
    
    if [[ "$encrypt_backup" =~ ^[Yy]$ ]]; then
        # Check if openssl is installed
        if ! command -v openssl &> /dev/null; then
            print_message "$YELLOW" "OpenSSL not found. Installing..."
            apt-get update -y && apt-get install -y openssl
        fi
        
        print_message "$YELLOW" "Backup will be encrypted with a password."
        print_message "$RED" "WARNING: If you lose this password, you cannot restore your backup!"
        echo -n "Enter encryption password: "
        read -r -s enc_password
        echo ""
        
        # Create normal tarball first, then encrypt it
        temp_tar="/tmp/vpn_backup_temp.tar.gz"
        tar -czf "$temp_tar" -C "$temp_dir" .
        
        # Encrypt the tarball
        openssl enc -aes-256-cbc -salt -in "$temp_tar" -out "$backup_file" -k "$enc_password"
        
        # Add indication that file is encrypted
        echo "encrypted" > "$temp_dir/encryption_status.txt"
        
        # Clean up temporary tarball
        rm -f "$temp_tar"
        
        print_message "$GREEN" "Backup encrypted successfully!"
    else
        tar -czf "$backup_file" -C "$temp_dir" .
    fi
    
    # Verify backup was created successfully
    if [ ! -f "$backup_file" ] || [ ! -s "$backup_file" ]; then
        print_message "$RED" "Backup creation failed! File is missing or empty."
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Clean up temporary directory
    rm -rf "$temp_dir"
    
    print_message "$GREEN" "Backup completed successfully!"
    print_message "$YELLOW" "Backup saved to: $backup_file"
    
    # Create a copy in the current directory for easy download
    current_dir_backup="./vpn_backup_$timestamp.tar.gz"
    cp "$backup_file" "$current_dir_backup"
    print_message "$YELLOW" "A copy is also available at: $current_dir_backup"
    
    # Show single-line backup string that can be copied
    print_message "$BLUE" "Single-line backup string (can be used for manual restoration):"
    echo ""
    echo "$(cat "$backup_file" | base64 -w 0)"
    echo ""
    print_message "$YELLOW" "Copy the above string to save your backup in text format."
}

# Function to restore VPN settings from backup
restore_vpn_settings() {
    check_root
    print_message "$BLUE" "\n=== بازیابی تنظیمات VPN ===\n"
    echo ""
    print_message "$YELLOW" "Please select restore method:"
    print_message "$GREEN" "1) Restore from backup file"
    print_message "$GREEN" "2) Restore from single-line backup string"
    print_message "$GREEN" "0) Back to main menu"
    echo ""
    echo -n "Enter your choice: "
    read -r restore_choice
    
    case $restore_choice in
        1)
            # List available backups
            echo ""
            print_message "$YELLOW" "Available backup files:"
            ls -l /root/vpn_backups/*.tar.gz 2>/dev/null || echo "No backups found in /root/vpn_backups/"
            ls -l ./vpn_backup_*.tar.gz 2>/dev/null || echo "No backups found in current directory"
            echo ""
            
            echo -n "Enter full path to the backup file: "
            read -r backup_file
            
            # Check if file exists
            if [ ! -f "$backup_file" ]; then
                print_message "$RED" "Backup file not found: $backup_file"
                return
            fi
            
            # Perform restoration
            perform_restore "$backup_file"
            ;;
        2)
            echo ""
            print_message "$YELLOW" "Paste the single-line backup string below:"
            echo -n "> "
            read -r backup_string
            
            # Create a unique temporary directory
            TMP_DIR=$(mktemp -d)
            if [ $? -ne 0 ]; then
                print_message "$RED" "Could not create temp directory"
                return 1
            fi
            
            # Use a more reliable approach to handle the backup string
            BACKUP_FILE="$TMP_DIR/backup.b64"
            DECODED_FILE="$TMP_DIR/backup.tar.gz"
            
            # Remove any problematic characters that might be added by copy-paste
            # and save directly to a file (avoids issues with echo)
            printf "%s" "$backup_string" | tr -d '\r\n ' > "$BACKUP_FILE"
            
            # Try to determine if this is an encrypted backup
            if grep -q "^U2Fs" "$BACKUP_FILE" 2>/dev/null; then
                print_message "$YELLOW" "This appears to be an encrypted backup."
                
                # For encrypted backups, we need a password
                echo -n "Enter decryption password: "
                read -s decrypt_password
                echo
                
                # Create a Python script to handle the decoding and decryption
                # This avoids shell issues with special characters
                cat > "$TMP_DIR/decrypt.py" << 'EOF'
#!/usr/bin/env python3
import sys
import base64
import os

try:
    # Read from stdin
    data = sys.stdin.read().strip()
    # Decode base64
    decoded = base64.b64decode(data)
    # Write to the output file
    with open(sys.argv[1], 'wb') as f:
        f.write(decoded)
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Error: {str(e)}\n")
    sys.exit(1)
EOF
                chmod +x "$TMP_DIR/decrypt.py"
                
                # Use the Python script to decode base64
                TMP_ENC="$TMP_DIR/backup.enc"
                if ! cat "$BACKUP_FILE" | python3 "$TMP_DIR/decrypt.py" "$TMP_ENC" 2>/dev/null; then
                    print_message "$RED" "Could not decode base64 data."
                    rm -rf "$TMP_DIR"
                    read -p "Press Enter to return to menu..."
                    return 1
                fi
                
                # Now decrypt with OpenSSL
                if ! openssl enc -aes-256-cbc -d -in "$TMP_ENC" -out "$DECODED_FILE" -k "$decrypt_password" 2>/dev/null; then
                    print_message "$RED" "Decryption failed. Wrong password or corrupt file."
                    rm -rf "$TMP_DIR"
                    read -p "Press Enter to return to menu..."
                    return 1
                fi
            else
                # For non-encrypted backups, just decode base64
                # Use Python for more reliable base64 decoding
                cat > "$TMP_DIR/decode.py" << 'EOF'
#!/usr/bin/env python3
import sys
import base64

try:
    # Read from stdin
    data = sys.stdin.read().strip()
    # Decode base64
    decoded = base64.b64decode(data)
    # Write to the output file
    with open(sys.argv[1], 'wb') as f:
        f.write(decoded)
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"Error: {str(e)}\n")
    sys.exit(1)
EOF
                chmod +x "$TMP_DIR/decode.py"
                
                if ! cat "$BACKUP_FILE" | python3 "$TMP_DIR/decode.py" "$DECODED_FILE" 2>/dev/null; then
                    print_message "$RED" "Base64 decoding failed. Invalid input."
                    rm -rf "$TMP_DIR"
                    read -p "Press Enter to return to menu..."
                    return 1
                fi
            fi
            
            # Verify we have a valid backup file
            if [ ! -s "$DECODED_FILE" ]; then
                print_message "$RED" "Resulting backup file is empty."
                rm -rf "$TMP_DIR"
                read -p "Press Enter to return to menu..."
                return 1
            fi
            
            # Verify it's a tar.gz file
            if ! (file "$DECODED_FILE" | grep -q "gzip compressed data"); then
                print_message "$RED" "Invalid backup format. Not a gzip file."
                rm -rf "$TMP_DIR"
                read -p "Press Enter to return to menu..."
                return 1
            fi
            
            # If we get here, we have a valid backup. Restore it.
            print_message "$GREEN" "Valid backup file detected. Starting restoration..."
            perform_restore "$DECODED_FILE"
            
            # Clean up temp files
            rm -rf "$TMP_DIR"
            read -p "Press Enter to return to menu..."
            ;;
        0)
            return
            ;;
        *)
            print_message "$RED" "Invalid option!"
            ;;
    esac
}

# Helper function to perform actual restoration
perform_restore() {
    backup_file=$1
    
    # Create temporary directory for extraction
    temp_dir="/tmp/vpn_restore_temp"
    mkdir -p "$temp_dir"
    
    # Check if backup file exists and is not empty
    if [ ! -f "$backup_file" ] || [ ! -s "$backup_file" ]; then
        print_message "$RED" "Invalid backup file: File is missing or empty."
        return 1
    fi
    
    # Check if this is an encrypted backup
    if ! tar -tzf "$backup_file" > /dev/null 2>&1; then
        print_message "$YELLOW" "This appears to be an encrypted backup."
        echo -n "Enter decryption password: "
        read -r -s dec_password
        echo ""
        
        # Decrypt the backup to a temporary file
        temp_decrypted="/tmp/vpn_restore_decrypted.tar.gz"
        if ! openssl enc -aes-256-cbc -d -in "$backup_file" -out "$temp_decrypted" -k "$dec_password" 2>/dev/null; then
            print_message "$RED" "Decryption failed. Wrong password or corrupt file."
            rm -f "$temp_dir" "$temp_decrypted"
            return 1
        fi
        
        # Use the decrypted file instead
        backup_file="$temp_decrypted"
        print_message "$GREEN" "Backup decrypted successfully!"
    fi
    
    # Extract backup
    print_message "$YELLOW" "Extracting backup..."
    if ! tar -xzf "$backup_file" -C "$temp_dir" 2>/dev/null; then
        print_message "$RED" "Failed to extract backup. File may be corrupted."
        rm -rf "$temp_dir"
        if [ -f "/tmp/vpn_restore_decrypted.tar.gz" ]; then
            rm -f "/tmp/vpn_restore_decrypted.tar.gz"
        fi
        return 1
    fi
    print_message "$GREEN" "Backup extracted successfully!"
    
    # Clean up decrypted file if it exists
    if [ -f "/tmp/vpn_restore_decrypted.tar.gz" ]; then
        rm -f "/tmp/vpn_restore_decrypted.tar.gz"
    fi
    
    # Show backup summary if available
    if [ -f "$temp_dir/backup_summary.txt" ]; then
        print_message "$BLUE" "Backup summary:"
        cat "$temp_dir/backup_summary.txt"
        echo ""
    fi
    
    # Ask what to restore
    print_message "$YELLOW" "What would you like to restore?"
    print_message "$GREEN" "1) Everything (configurations, users, and settings)"
    print_message "$GREEN" "2) Only user accounts"
    print_message "$GREEN" "3) Only configuration files"
    print_message "$GREEN" "0) Cancel restoration"
    echo -n "Enter your choice: "
    read -r restore_type
    
    case $restore_type in
        0)
            print_message "$YELLOW" "Restoration canceled."
            rm -rf "$temp_dir"
            return
            ;;
        1|2|3)
            # Valid choice, continue
            ;;
        *)
            print_message "$RED" "Invalid option! Defaulting to full restoration."
            restore_type=1
            ;;
    esac
    
    # Confirm restoration
    echo -n "Do you want to proceed with restoration? This will overwrite current settings [y/N]: "
    read -r confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_message "$YELLOW" "Restoration canceled."
        rm -rf "$temp_dir"
        return
    fi
    
    # Stop services before restoration
    print_message "$YELLOW" "Stopping VPN services..."
    systemctl stop pptpd ocserv
    
    # Restore based on chosen option
    if [ "$restore_type" = "1" ] || [ "$restore_type" = "3" ]; then
        # Restore PPTP configuration
        if [ -f "$temp_dir/pptpd.conf" ]; then
            print_message "$YELLOW" "Restoring PPTP configuration..."
            cp "$temp_dir/pptpd.conf" "/etc/pptpd.conf"
        fi
        
        if [ -f "$temp_dir/pptpd-options" ]; then
            cp "$temp_dir/pptpd-options" "/etc/ppp/pptpd-options"
        fi
        
        # Restore OpenConnect configuration
        if [ -f "$temp_dir/ocserv.conf" ]; then
            print_message "$YELLOW" "Restoring OpenConnect configuration..."
            cp "$temp_dir/ocserv.conf" "/etc/ocserv/ocserv.conf"
        fi
        
        # Restore certificates
        if [ -d "$temp_dir/ssl" ]; then
            print_message "$YELLOW" "Restoring certificates..."
            mkdir -p "/etc/ocserv/ssl"
            cp -r "$temp_dir/ssl"/* "/etc/ocserv/ssl/"
            chmod 600 "/etc/ocserv/ssl/server-key.pem"
            chmod 644 "/etc/ocserv/ssl/server-cert.pem"
        fi
        
        # Restore firewall rules
        if [ -f "$temp_dir/iptables_rules.txt" ]; then
            print_message "$YELLOW" "Restoring firewall rules..."
            iptables-restore < "$temp_dir/iptables_rules.txt"
        fi
        
        # Restore system settings
        if [ -f "$temp_dir/ip_forward_setting.txt" ]; then
            print_message "$YELLOW" "Ensuring IP forwarding is enabled..."
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
            cat "$temp_dir/ip_forward_setting.txt" >> /etc/sysctl.conf
            echo 1 > /proc/sys/net/ipv4/ip_forward
        fi
    fi
    
    if [ "$restore_type" = "1" ] || [ "$restore_type" = "2" ]; then
        # Restore PPTP users
        if [ -f "$temp_dir/pptp_users.txt" ]; then
            print_message "$YELLOW" "Restoring PPTP users..."
            cp "$temp_dir/pptp_users.txt" "/etc/ppp/chap-secrets"
        fi
        
        # Restore PPTP user expiry
        if [ -f "$temp_dir/pptp_expiry.txt" ]; then
            cp "$temp_dir/pptp_expiry.txt" "/etc/ppp/user-expiry"
        fi
        
        # Restore OpenConnect users
        if [ -f "$temp_dir/ocserv_users.txt" ]; then
            print_message "$YELLOW" "Restoring OpenConnect users..."
            cp "$temp_dir/ocserv_users.txt" "/etc/ocserv/ocpasswd"
        fi
        
        # Restore OpenConnect user expiry
        if [ -f "$temp_dir/ocserv_expiry.txt" ]; then
            cp "$temp_dir/ocserv_expiry.txt" "/etc/ocserv/user-expiry"
        fi
    fi
    
    # Start services
    print_message "$YELLOW" "Starting VPN services..."
    systemctl start pptpd
    systemctl enable pptpd
    systemctl start ocserv
    systemctl enable ocserv
    
    # Check if services started properly
    sleep 2
    pptp_status=$(systemctl is-active pptpd)
    ocserv_status=$(systemctl is-active ocserv)
    
    # Clean up
    rm -rf "$temp_dir"
    
    # Show results
    print_message "$GREEN" "VPN settings restored successfully!"
    print_message "$YELLOW" "PPTP service status: $pptp_status"
    print_message "$YELLOW" "OpenConnect service status: $ocserv_status"
    
    if [ "$pptp_status" != "active" ] || [ "$ocserv_status" != "active" ]; then
        print_message "$RED" "Warning: One or more services failed to start properly."
        print_message "$YELLOW" "Please use option 5 (Debug and Fix Issues) from the main menu."
    else
        print_message "$GREEN" "All services are running correctly!"
    fi
}

# Function to monitor online VPN users
monitor_online_users() {
    check_root
    clear
    print_message "$BLUE" "\n🔍 ONLINE VPN USERS MONITOR 🔍\n"
    
    # Keep monitoring until user quits
    local continue_monitoring=true
    trap 'continue_monitoring=false' INT
    
    print_message "$YELLOW" "Press Ctrl+C to return to menu\n"
    
    while $continue_monitoring; do
        clear
        print_message "$BLUE" "\n🔍 ONLINE VPN USERS MONITOR 🔍  (Auto-refresh every 10 seconds)\n"
        echo "Last update: $(date +"%Y-%m-%d %H:%M:%S")\n"
        
        # PPTP Online Users
        print_message "$YELLOW" "📡 PPTP Online Users:"
        echo "---------------------------------------------------"
        if [ -f "/var/log/syslog" ]; then
            # Extract PPTP connected users from logs
            connected_users=$(grep "pppd" /var/log/syslog | grep "user" | grep -i "connect" | tail -10 | awk -F"[][]" '{print $2}' | sort | uniq)
            
            if [ -z "$connected_users" ]; then
                echo "No online PPTP users found"
            else
                echo "Username        |  Connected Since"
                echo "---------------------------------------------------"
                echo "$connected_users" | while read -r line; do
                    if [ ! -z "$line" ]; then
                        # Try to find when they connected
                        connect_time=$(grep "$line" /var/log/syslog | grep -i "connect" | tail -1 | awk '{print $1, $2, $3}')
                        printf "%-15s | %s\n" "$line" "$connect_time"
                    fi
                done
            fi
        else
            echo "System logs not found"
        fi
        echo "---------------------------------------------------"
        
        echo
        
        # OpenConnect Online Users
        print_message "$YELLOW" "🌐 OpenConnect Online Users:"
        echo "---------------------------------------------------"
        
        if [ -f "/var/log/ocserv.log" ]; then
            # Print currently connected users from occtl
            if command -v occtl &> /dev/null; then
                occtl_output=$(occtl show users 2>/dev/null)
                
                if [ -z "$occtl_output" ] || echo "$occtl_output" | grep -q "no users are connected"; then
                    echo "No online OpenConnect users found"
                else
                    echo "Username        |  IP Address       |  Connected Since"
                    echo "---------------------------------------------------"
                    echo "$occtl_output" | grep -v "^id" | awk '{print $1, $2, $3, $4, $5}' | while read -r id username groupname state since rest; do
                        if [ "$state" = "online" ]; then
                            ip=$(occtl show user "$id" 2>/dev/null | grep "IP:" | awk '{print $2}')
                            printf "%-15s | %-16s | %s\n" "$username" "$ip" "$since"
                        fi
                    done
                fi
            else
                echo "occtl command not found"
            fi
        else
            echo "OpenConnect logs not found"
        fi
        echo "---------------------------------------------------"
        
        # Wait for 10 seconds before refreshing (unless user quits)
        for i in {10..1}; do
            if ! $continue_monitoring; then
                break
            fi
            echo -ne "\rRefreshing in $i seconds... Press Ctrl+C to exit"
            sleep 1
        done
    done
    
    # Reset trap
    trap - INT
    echo
    read -p "Press Enter to return to main menu..."
}

# Function to show network usage statistics
show_usage_stats() {
    check_root
    clear
    print_message "$BLUE" "\n📊 VPN USAGE STATISTICS 📊\n"
    
    # Check if required tools are installed
    if ! command -v vnstat &> /dev/null; then
        print_message "$YELLOW" "vnstat is not installed. Installing..."
        apt-get update && apt-get install -y vnstat
        systemctl enable vnstat && systemctl start vnstat
        print_message "$GREEN" "vnstat installed successfully."
        echo
    fi
    
    # Find the main network interface
    main_interface=$(ip route | grep default | awk '{print $5}')
    
    if [ -z "$main_interface" ]; then
        print_message "$RED" "Could not detect the main network interface."
        read -p "Press Enter to return to main menu..."
        return
    fi
    
    print_message "$YELLOW" "🖧 Main Network Interface: $main_interface\n"
    
    # Show daily traffic
    print_message "$GREEN" "📅 Daily Network Traffic:"
    echo "---------------------------------------------------"
    vnstat -d -i "$main_interface" | sed '1,/daily/d' | head -n 8
    echo "---------------------------------------------------"
    
    echo
    
    # Show monthly traffic
    print_message "$GREEN" "🗓️ Monthly Network Traffic:"
    echo "---------------------------------------------------"
    vnstat -m -i "$main_interface" | sed '1,/monthly/d' | head -n 8
    echo "---------------------------------------------------"
    
    echo
    
    # Show top processes using bandwidth if iftop is available
    if command -v iftop &> /dev/null; then
        print_message "$GREEN" "⚡ Current Network Usage (Press q to exit):"
        echo "---------------------------------------------------"
        echo "Starting iftop to monitor current network usage..."
        echo "Press 'q' to exit iftop and return to stats"
        echo "---------------------------------------------------"
        sleep 2
        iftop -n -N -P
    else
        print_message "$YELLOW" "iftop is not installed. Install it for real-time network monitoring."
        print_message "$YELLOW" "Run: apt-get install iftop"
    fi
    
    echo
    read -p "Press Enter to return to main menu..."
}

# Function to display main menu
show_menu() {
    while true; do
        clear
        # Display service status at the top
        display_status
        
        echo "=========================================================="
        print_message "$PURPLE" "     🚀 VPN SERVER MANAGEMENT - Multiple Protocols 🚀"
        echo "=========================================================="
        echo
        print_message "$YELLOW" "📋 Please select an option:"
        echo
        print_message "$GREEN" "1️⃣  Install and Configure Services"
        print_message "$GREEN" "2️⃣  User Management"
        print_message "$GREEN" "3️⃣  Monitoring and Statistics"
        print_message "$GREEN" "4️⃣  Debugging and Troubleshooting"
        print_message "$GREEN" "5️⃣  Backup and Restore"
        print_message "$GREEN" "6️⃣  Advanced Settings"
        print_message "$GREEN" "0️⃣  Exit"
        echo ""
        echo -n "Enter your choice: "
        read -r choice
        
        case $choice in
            1)
                # Installation submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     🔧 VPN INSTALLATION AND CONFIGURATION 🔧"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select a VPN service to install:"
                echo
                print_message "$GREEN" "1) Install All Services (OpenConnect, PPTP, WireGuard)"
                print_message "$GREEN" "2) Install OpenConnect VPN (AnyConnect Compatible)"
                print_message "$GREEN" "3) Install PPTP VPN"
                print_message "$GREEN" "4) Install WireGuard VPN"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r install_choice
                
                case $install_choice in
                    1)
                        check_root
                        install_packages
                        configure_pptp
                        configure_openconnect
                        install_wireguard
                        setup_expiry_cron
                        print_message "$GREEN" "All VPN services installed successfully!"
                        ;;
                    2)
                        check_root
                        install_packages
                        configure_openconnect
                        setup_expiry_cron
                        print_message "$GREEN" "OpenConnect VPN installed successfully!"
                        ;;
                    3)
                        check_root
                        install_packages
                        configure_pptp
                        setup_expiry_cron
                        print_message "$GREEN" "PPTP VPN installed successfully!"
                        ;;
                    4)
                        check_root
                        install_wireguard
                        print_message "$GREEN" "WireGuard VPN installed successfully!"
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            2)
                # User Management submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     👥 VPN USER MANAGEMENT 👥"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select an option:"
                echo
                print_message "$GREEN" "1) Create VPN User (Both PPTP & OpenConnect)"
                print_message "$GREEN" "2) Create WireGuard VPN User"
                print_message "$GREEN" "3) User Management (Add/Edit/Remove)"
                print_message "$GREEN" "4) Check Expired Users"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r user_choice
                
                case $user_choice in
                    1)
                        check_root
                        create_vpn_user
                        ;;
                    2)
                        check_root
                        create_wireguard_user
                        ;;
                    3)
                        check_root
                        manage_users
                        ;;
                    4)
                        check_root
                        check_expired_users
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            3)
                # Monitoring submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     📊 MONITORING AND STATISTICS 📊"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select an option:"
                echo
                print_message "$GREEN" "1) Monitor Online Users (Live)"
                print_message "$GREEN" "2) Network Usage Statistics"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r monitor_choice
                
                case $monitor_choice in
                    1)
                        check_root
                        monitor_online_users
                        ;;
                    2)
                        check_root
                        show_usage_stats
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            4)
                # Debugging submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     🔍 DEBUGGING AND TROUBLESHOOTING 🔍"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select an option:"
                echo
                print_message "$GREEN" "1) Basic VPN Diagnostics"
                print_message "$GREEN" "2) Advanced VPN Diagnostics & Performance Analysis"
                print_message "$GREEN" "3) OpenConnect Advanced Diagnostics & Fixes"
                print_message "$GREEN" "4) PPTP Troubleshooting"
                print_message "$GREEN" "5) WireGuard Troubleshooting"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r debug_choice
                
                case $debug_choice in
                    1)
                        check_root
                        debug_vpn_services
                        ;;
                    2)
                        check_root
                        advanced_vpn_diagnostics
                        ;;
                    3)
                        check_root
                        diagnose_openconnect_issues
                        ;;
                    4)
                        check_root
                        diagnose_pptp_issues
                        ;;
                    5)
                        check_root
                        diagnose_wireguard_issues
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            5)
                # Backup and Restore submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     💾 BACKUP AND RESTORE 💾"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select an option:"
                echo
                print_message "$GREEN" "1) Backup VPN Settings"
                print_message "$GREEN" "2) Restore VPN Settings"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r backup_choice
                
                case $backup_choice in
                    1)
                        check_root
                        backup_vpn_settings
                        ;;
                    2)
                        check_root
                        restore_vpn_settings
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            6)
                # Advanced Settings submenu
                clear
                echo "=========================================================="
                print_message "$PURPLE" "     ⚙️ ADVANCED SETTINGS ⚙️"
                echo "=========================================================="
                echo
                print_message "$YELLOW" "Select an option:"
                echo
                print_message "$GREEN" "1) Change OpenConnect Port"
                print_message "$GREEN" "2) Change WireGuard Port"
                print_message "$GREEN" "0) Return to Main Menu"
                echo
                echo -n "Enter your choice: "
                read -r advanced_choice
                
                case $advanced_choice in
                    1)
                        check_root
                        change_openconnect_port
                        ;;
                    2)
                        check_root
                        # This function will be added later
                        print_message "$YELLOW" "WireGuard port configuration will be available in the next update."
                        ;;
                    0)
                        continue
                        ;;
                    *)
                        print_message "$RED" "Invalid option!"
                        ;;
                esac
                ;;
            0)
                print_message "$YELLOW" "Exiting..."
                exit 0
                ;;
            *)
                print_message "$RED" "Invalid option!"
                ;;
        esac
        
        echo ""
        echo -n "Press Enter to return to menu..."
        read
    done
}

# Function to fix OpenConnect (ocserv) configuration issues
fix_ocserv_configuration() {
    print_message "$BLUE" "Checking and fixing OpenConnect (ocserv) configuration..."
    
    if [ ! -f "/etc/ocserv/ocserv.conf" ]; then
        print_message "$RED" "OpenConnect configuration file not found! Is ocserv installed?"
        return 1
    fi
    
    CONFIG_CHANGED=0
    
    # Check and fix the deprecated or problematic options
    if grep -q "deny-roaming" /etc/ocserv/ocserv.conf; then
        print_message "$YELLOW" "Removing deprecated 'deny-roaming' option..."
        sed -i '/deny-roaming/d' /etc/ocserv/ocserv.conf
        CONFIG_CHANGED=1
    fi
    
    if grep -q "pid-file" /etc/ocserv/ocserv.conf; then
        print_message "$YELLOW" "Removing unnecessary 'pid-file' option..."
        sed -i '/pid-file/d' /etc/ocserv/ocserv.conf
        CONFIG_CHANGED=1
    fi
    
    # Check for proper CA certificate configuration
    if grep -q "ca-cert.*server-cert" /etc/ocserv/ocserv.conf; then
        print_message "$YELLOW" "CA certificate is set to server certificate. This is not recommended."
        
        # Check if we should create proper CA
        if [ ! -f "/etc/ocserv/ssl/ca-cert.pem" ]; then
            print_message "$YELLOW" "Creating proper CA certificate..."
            
            # Create directory if it doesn't exist
            mkdir -p /etc/ocserv/ssl
            cd /etc/ocserv/ssl
            
            # Create CA certificate if it doesn't exist
            if [ ! -f "ca-key.pem" ]; then
                openssl genrsa -out ca-key.pem 4096
                openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -subj "/C=US/ST=State/L=City/O=VPN-CA/CN=VPN-Root-CA"
                chmod 600 ca-key.pem
                chmod 644 ca-cert.pem
            fi
            
            # Update the config file
            sed -i 's|ca-cert.*server-cert.pem|ca-cert = /etc/ocserv/ssl/ca-cert.pem|' /etc/ocserv/ocserv.conf
            CONFIG_CHANGED=1
        fi
    fi
    
    # Check socket-file configuration
    if grep -q "socket-file.*[0-9]" /etc/ocserv/ocserv.conf; then
        print_message "$YELLOW" "Fixing socket-file path to prevent random numbers..."
        sed -i 's|socket-file = .*|socket-file = /var/run/ocserv-socket|' /etc/ocserv/ocserv.conf
        CONFIG_CHANGED=1
    fi
    
    # Make sure runtime directory exists
    if [ ! -d "/var/run" ] || [ ! -w "/var/run" ]; then
        print_message "$YELLOW" "Creating and setting permissions for runtime directory..."
        mkdir -p /var/run
        chmod 755 /var/run
    fi
    
    # Create ocpasswd file if it doesn't exist
    if [ ! -f "/etc/ocserv/ocpasswd" ]; then
        print_message "$YELLOW" "Creating empty ocpasswd file..."
        touch /etc/ocserv/ocpasswd
        chmod 600 /etc/ocserv/ocpasswd
    fi
    
    # Create user-expiry file if it doesn't exist
    if [ ! -f "/etc/ocserv/user-expiry" ]; then
        print_message "$YELLOW" "Creating empty user-expiry file..."
        touch /etc/ocserv/user-expiry
        chmod 600 /etc/ocserv/user-expiry
    fi
    
    # If we made changes, restart the service
    if [ "$CONFIG_CHANGED" -eq 1 ]; then
        print_message "$GREEN" "Configuration fixed. Restarting OpenConnect service..."
        systemctl restart ocserv
        
        # Check if service starts successfully
        if systemctl is-active --quiet ocserv; then
            print_message "$GREEN" "✅ OpenConnect service restarted successfully!"
        else
            print_message "$RED" "❌ OpenConnect service failed to restart."
            print_message "$YELLOW" "Error details:"
            systemctl status ocserv
        fi
    else
        print_message "$GREEN" "✅ OpenConnect configuration appears to be correct."
    fi
}

# Function to debug and fix VPN issues
debug_vpn() {
    print_message "$PURPLE" "🔍 VPN Diagnostics and Troubleshooting"
    
    # Sub-menu for different debugging options
    while true; do
        clear
        echo "╭───────────────────────────────────────────────────╮"
        print_message "$PURPLE" "             🛠️ منوی عیب‌یابی VPN 🛠️             "
        echo "╰───────────────────────────────────────────────────╯"
        echo "┌───────────────────────────────────────────────────┐"
        print_message "$YELLOW" "  1) عیب‌یابی کامل و خودکار سرویس‌های VPN"
        print_message "$YELLOW" "  2) عیب‌یابی پیشرفته و رفع مشکلات OpenConnect"
        print_message "$YELLOW" "  3) بررسی و رفع مشکلات PPTP"
        print_message "$YELLOW" "  4) بررسی وضعیت شبکه و فایروال"
        print_message "$YELLOW" "  5) بازسازی پیکربندی و گواهی‌های OpenConnect"
        print_message "$YELLOW" "  6) بررسی لاگ‌های سیستم و خطاها"
        print_message "$YELLOW" "  0) بازگشت به منوی اصلی"
        echo "└───────────────────────────────────────────────────┘"
        
        read -p "$(echo -e "${BLUE}لطفاً گزینه مورد نظر را انتخاب کنید: ${NC}")" debug_option
        
        case $debug_option in
            1)
                # Basic checks
                print_message "$BLUE" "در حال انجام عیب‌یابی کامل سرویس‌های VPN..."
                
                # Check system requirements
                print_message "$BLUE" "بررسی نیازمندی‌های سیستم..."
                
                # Check kernel forwarding
                if grep -q "1" /proc/sys/net/ipv4/ip_forward; then
                    print_message "$GREEN" "✅ IP forwarding فعال است."
                else
                    print_message "$YELLOW" "⚠️ IP forwarding غیرفعال است. در حال فعال‌سازی..."
                    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/60-vpn-forward.conf
                    sysctl -p /etc/sysctl.d/60-vpn-forward.conf
                fi
                
                # Check iptables NAT rules
                if iptables -t nat -C POSTROUTING -s 192.168.10.0/24 -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)') -j MASQUERADE &>/dev/null || 
                   iptables -t nat -C POSTROUTING -s 192.168.0.0/24 -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)') -j MASQUERADE &>/dev/null; then
                    print_message "$GREEN" "✅ قوانین NAT به درستی پیکربندی شده‌اند."
                else
                    print_message "$YELLOW" "⚠️ قوانین NAT یافت نشد. در حال اضافه کردن..."
                    # Try to detect the main interface
                    MAIN_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
                    if [ -z "$MAIN_INTERFACE" ]; then
                        MAIN_INTERFACE="eth0"  # Fallback to eth0
                        print_message "$YELLOW" "اینترفیس اصلی شناسایی نشد، استفاده از eth0 به عنوان پیش‌فرض."
                    fi
                    
                    # Add NAT rules for both potential subnets
                    iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o $MAIN_INTERFACE -j MASQUERADE
                    iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o $MAIN_INTERFACE -j MASQUERADE
                    
                    # Save rules
                    if [ -d "/etc/iptables" ]; then
                        iptables-save > /etc/iptables/rules.v4
                    else
                        mkdir -p /etc/network/if-up.d/
                        cat > /etc/network/if-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
                        chmod +x /etc/network/if-up.d/iptables
                        iptables-save > /etc/iptables.rules
                    fi
                fi
                
                # Check PPTP service
                if systemctl is-active --quiet pptpd; then
                    print_message "$GREEN" "✅ سرویس PPTP در حال اجراست."
                else
                    print_message "$YELLOW" "⚠️ سرویس PPTP اجرا نمی‌شود. تلاش برای راه‌اندازی..."
                    systemctl start pptpd
                    
                    if systemctl is-active --quiet pptpd; then
                        print_message "$GREEN" "✅ سرویس PPTP با موفقیت راه‌اندازی شد."
                    else
                        print_message "$RED" "❌ راه‌اندازی سرویس PPTP ناموفق بود!"
                        print_message "$YELLOW" "جزئیات خطا:"
                        systemctl status pptpd
                    fi
                fi
                
                # Check OpenConnect service and configuration
                if systemctl is-active --quiet ocserv; then
                    print_message "$GREEN" "✅ سرویس OpenConnect در حال اجراست."
                    
                    # Check for warnings in the logs
                    if journalctl -u ocserv | grep -q "warning"; then
                        print_message "$YELLOW" "⚠️ هشدارهایی در لاگ OpenConnect یافت شد. در حال رفع پیکربندی..."
                        fix_ocserv_configuration
                    else
                        print_message "$GREEN" "✅ هیچ هشداری در لاگ‌های OpenConnect یافت نشد."
                    fi
                else
                    print_message "$YELLOW" "⚠️ سرویس OpenConnect اجرا نمی‌شود. در حال بررسی عمیق‌تر..."
                    diagnose_openconnect_issues
                fi
                
                # Check server connectivity
                print_message "$BLUE" "بررسی اتصال سرور..."
                
                # Check if ports are open
                if command -v netstat &>/dev/null; then
                    print_message "$YELLOW" "بررسی پورت‌های باز..."
                    netstat -tuln | grep -E '(443|4443|1723)'
                elif command -v ss &>/dev/null; then
                    print_message "$YELLOW" "بررسی پورت‌های باز..."
                    ss -tuln | grep -E '(443|4443|1723)'
                fi
                
                # Show useful statistics and information
                print_message "$BLUE" "اطلاعات سیستم:"
                print_message "$YELLOW" "IP سرور: $(curl -s ifconfig.me || hostname -I | awk '{print $1}')"
                OC_PORT=$(grep -oP 'tcp-port = \K\d+' /etc/ocserv/ocserv.conf || echo "443")
                print_message "$YELLOW" "پورت OpenConnect: $OC_PORT"
                print_message "$YELLOW" "پورت PPTP: 1723"
                
                print_message "$GREEN" "✅ عیب‌یابی کامل شد. اگر مشکلی یافت شد، به صورت خودکار رفع شده است."
                print_message "$YELLOW" "برای عیب‌یابی دستی اتصال:"
                print_message "$YELLOW" "- لاگ‌های OpenConnect: journalctl -u ocserv"
                print_message "$YELLOW" "- لاگ‌های PPTP: journalctl -u pptpd"
                ;;
            2)
                # OpenConnect advanced diagnostics
                diagnose_openconnect_issues
                ;;
            3)
                # PPTP diagnostics
                print_message "$BLUE" "در حال عیب‌یابی و رفع مشکلات PPTP..."
                
                # Check PPTP installation
                if ! command -v pptpd >/dev/null 2>&1; then
                    print_message "$RED" "❌ سرویس PPTP نصب نشده است!"
                    print_message "$YELLOW" "در حال نصب PPTP..."
                    apt-get update && apt-get install -y pptpd ppp
                    
                    if ! command -v pptpd >/dev/null 2>&1; then
                        print_message "$RED" "❌ نصب PPTP ناموفق بود!"
                        read -p "فشار دهید Enter را برای ادامه..." continue_key
                        break
                    fi
                    print_message "$GREEN" "✅ PPTP با موفقیت نصب شد."
                fi
                
                # Check PPTP configuration
                print_message "$YELLOW" "بررسی پیکربندی PPTP..."
                if [ ! -f "/etc/pptpd.conf" ]; then
                    print_message "$RED" "❌ فایل پیکربندی PPTP وجود ندارد!"
                    print_message "$YELLOW" "در حال ایجاد فایل پیکربندی..."
                    cat > /etc/pptpd.conf << EOF
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.0.1
remoteip 192.168.0.100-200
EOF
                    print_message "$GREEN" "✅ فایل پیکربندی PPTP ایجاد شد."
                fi
                
                # Check PPTP options
                if [ ! -f "/etc/ppp/pptpd-options" ]; then
                    print_message "$RED" "❌ فایل گزینه‌های PPTP وجود ندارد!"
                    print_message "$YELLOW" "در حال ایجاد فایل گزینه‌ها..."
                    cat > /etc/ppp/pptpd-options << EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
lock
nobsdcomp 
novj
novjccomp
nologfd
debug
EOF
                    print_message "$GREEN" "✅ فایل گزینه‌های PPTP ایجاد شد."
                fi
                
                # Check chap-secrets file
                if [ ! -f "/etc/ppp/chap-secrets" ]; then
                    print_message "$RED" "❌ فایل کاربران PPTP وجود ندارد!"
                    print_message "$YELLOW" "در حال ایجاد فایل کاربران..."
                    touch /etc/ppp/chap-secrets
                    chmod 600 /etc/ppp/chap-secrets
                    print_message "$GREEN" "✅ فایل کاربران PPTP ایجاد شد."
                fi
                
                # Check PPTP service
                print_message "$YELLOW" "بررسی وضعیت سرویس PPTP..."
                if systemctl is-active --quiet pptpd; then
                    print_message "$GREEN" "✅ سرویس PPTP در حال اجراست."
                else
                    print_message "$RED" "❌ سرویس PPTP اجرا نمی‌شود!"
                    print_message "$YELLOW" "در حال راه‌اندازی مجدد سرویس PPTP..."
                    systemctl restart pptpd
                    
                    if systemctl is-active --quiet pptpd; then
                        print_message "$GREEN" "✅ سرویس PPTP با موفقیت راه‌اندازی شد."
                    else
                        print_message "$RED" "❌ راه‌اندازی سرویس PPTP ناموفق بود!"
                        print_message "$YELLOW" "لاگ‌های سرویس:"
                        systemctl status pptpd
                    fi
                fi
                
                # Check if port is open
                print_message "$YELLOW" "بررسی وضعیت پورت PPTP..."
                if netstat -tuln | grep -q ":1723"; then
                    print_message "$GREEN" "✅ پورت PPTP (1723) باز است و در حال گوش دادن است."
                else
                    print_message "$RED" "❌ پورت PPTP (1723) باز نیست!"
                    print_message "$YELLOW" "بررسی وضعیت فایروال..."
                    
                    # Check if UFW is enabled
                    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
                        print_message "$YELLOW" "UFW فعال است. در حال باز کردن پورت PPTP..."
                        ufw allow 1723/tcp
                        ufw allow gre
                        print_message "$GREEN" "✅ پورت PPTP در UFW باز شد."
                    fi
                    
                    # Restart service
                    systemctl restart pptpd
                fi
                
                print_message "$GREEN" "✅ عیب‌یابی PPTP به پایان رسید."
                SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
                print_message "$GREEN" "اطلاعات اتصال PPTP:"
                print_message "$YELLOW" "سرور: $SERVER_IP"
                print_message "$YELLOW" "پورت: 1723"
                print_message "$YELLOW" "پروتکل: PPTP"
                ;;
            4)
                # Network and firewall checks
                print_message "$BLUE" "در حال بررسی وضعیت شبکه و فایروال..."
                
                # Check internet connectivity
                print_message "$YELLOW" "بررسی اتصال به اینترنت..."
                if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
                    print_message "$GREEN" "✅ اتصال به اینترنت برقرار است."
                else
                    print_message "$RED" "❌ اتصال به اینترنت برقرار نیست!"
                    print_message "$YELLOW" "مشکلات احتمالی: تنظیمات DNS، فایروال، یا مشکل در اتصال به اینترنت"
                fi
                
                # Check network interfaces
                print_message "$YELLOW" "بررسی رابط‌های شبکه..."
                ip a
                
                # Check routing table
                print_message "$YELLOW" "بررسی جدول مسیریابی (routing)..."
                ip route
                
                # Check firewall status
                print_message "$YELLOW" "بررسی وضعیت فایروال..."
                
                # Check UFW if installed
                if command -v ufw >/dev/null 2>&1; then
                    print_message "$YELLOW" "وضعیت UFW:"
                    ufw status
                fi
                
                # Check iptables rules
                print_message "$YELLOW" "قوانین iptables:"
                iptables -L -v
                print_message "$YELLOW" "قوانین NAT iptables:"
                iptables -t nat -L -v
                
                # Check open ports
                print_message "$YELLOW" "پورت‌های باز:"
                if command -v netstat >/dev/null 2>&1; then
                    netstat -tuln
                elif command -v ss >/dev/null 2>&1; then
                    ss -tuln
                fi
                
                print_message "$GREEN" "✅ بررسی وضعیت شبکه و فایروال به پایان رسید."
                print_message "$YELLOW" "در صورت نیاز به باز کردن پورت‌های VPN، از دستورات زیر استفاده کنید:"
                print_message "$YELLOW" "- برای OpenConnect: ufw allow 443/tcp ufw allow 443/udp"
                print_message "$YELLOW" "- برای PPTP: ufw allow 1723/tcp ufw allow gre"
                ;;
            5)
                # Rebuild OpenConnect configuration and certificates
                print_message "$BLUE" "در حال بازسازی پیکربندی و گواهی‌های OpenConnect..."
                
                # Backup existing configuration
                if [ -f "/etc/ocserv/ocserv.conf" ]; then
                    cp /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.bak.$(date +%Y%m%d%H%M%S)
                    print_message "$GREEN" "✅ از فایل پیکربندی فعلی پشتیبان تهیه شد."
                fi
                
                # Recreate certificates
                print_message "$YELLOW" "ایجاد مجدد گواهی‌ها..."
                
                # Create directory if needed
                mkdir -p /etc/ocserv/ssl
                cd /etc/ocserv/ssl || {
                    print_message "$RED" "خطا در دسترسی به دایرکتوری گواهی‌ها."
                    return 1
                }
                
                # Remove old certificates
                rm -f ca-key.pem ca-cert.pem server-key.pem server-cert.pem server-req.pem
                
                # Generate CA key and certificate
                print_message "$YELLOW" "ایجاد گواهی CA..."
                openssl genrsa -out ca-key.pem 4096
                openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -subj "/C=IR/ST=State/L=City/O=VPN-CA/CN=VPN-Root-CA"
                
                # Generate server key and certificate
                print_message "$YELLOW" "ایجاد گواهی سرور..."
                openssl genrsa -out server-key.pem 2048
                SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
                
                openssl req -new -key server-key.pem -out server-req.pem -subj "/C=IR/ST=State/L=City/O=VPN-Server/CN=$SERVER_IP"
                
                # Create openssl extension file for SAN
                cat > san.ext << EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = $(hostname)
IP.1 = $SERVER_IP
EOF
                
                # Sign certificate
                openssl x509 -req -days 3650 -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -extfile san.ext -out server-cert.pem
                
                # Verify certificate
                openssl verify -CAfile ca-cert.pem server-cert.pem
                
                # Set permissions
                chmod 600 ca-key.pem server-key.pem
                chmod 644 ca-cert.pem server-cert.pem
                
                print_message "$GREEN" "✅ گواهی‌ها با موفقیت ایجاد شدند."
                
                # Create optimized config
                print_message "$YELLOW" "ایجاد فایل پیکربندی بهینه..."
                cat > /etc/ocserv/ocserv.conf << EOF
# پیکربندی بهینه OpenConnect Server (ocserv)
# ایجاد شده توسط اسکریپت راه‌اندازی VPN

# احراز هویت کاربر
auth = "plain[passwd=/etc/ocserv/ocpasswd]"

# تنظیمات شبکه
tcp-port = 4443
udp-port = 4443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket

# تنظیمات TLS/SSL
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca-cert.pem
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"
cert-user-oid = 0.9.2342.19200300.100.1.1
compression = true

# امنیت و جداسازی
isolate-workers = true
max-clients = 128
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
cookie-validate = true
server-drain-ms = 100

# تنظیمات اتصال
mtu = 1400
switch-to-tcp-timeout = 25
try-mtu-discovery = true
rekey-time = 172800
rekey-method = ssl
use-occtl = true
device = vpns
predictable-ips = true
output-buffer = 1000

# DNS و مسیریابی
default-domain = vpn.local
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
route = default
no-route = 192.168.10.0/255.255.255.0
ping-leases = true

# سازگاری
cisco-client-compat = true
dtls-legacy = true
user-profile = profile.xml

# لاگ و دیباگ
syslog = true
log-level = 1
EOF
                
                # Create ocpasswd file if it doesn't exist
                if [ ! -f "/etc/ocserv/ocpasswd" ]; then
                    touch /etc/ocserv/ocpasswd
                    chmod 600 /etc/ocserv/ocpasswd
                    print_message "$GREEN" "✅ فایل کاربران OpenConnect ایجاد شد."
                fi
                
                # Restart service
                print_message "$YELLOW" "در حال راه‌اندازی مجدد سرویس OpenConnect..."
                systemctl restart ocserv
                
                if systemctl is-active --quiet ocserv; then
                    print_message "$GREEN" "✅ سرویس OpenConnect با موفقیت راه‌اندازی شد."
                else
                    print_message "$RED" "❌ راه‌اندازی سرویس OpenConnect ناموفق بود!"
                    print_message "$YELLOW" "لاگ‌های سرویس:"
                    journalctl -u ocserv --no-pager -n 20
                fi
                
                print_message "$GREEN" "✅ بازسازی پیکربندی و گواهی‌های OpenConnect به پایان رسید."
                ;;
            6)
                # Check system logs
                print_message "$BLUE" "در حال بررسی لاگ‌های سیستم و خطاها..."
                
                # Check OpenConnect logs
                print_message "$YELLOW" "لاگ‌های اخیر OpenConnect:"
                journalctl -u ocserv --no-pager -n 50
                
                # Check PPTP logs
                print_message "$YELLOW" "لاگ‌های اخیر PPTP:"
                journalctl -u pptpd --no-pager -n 20
                
                # Check system logs for VPN related entries
                print_message "$YELLOW" "لاگ‌های سیستم مرتبط با VPN:"
                grep -i "vpn\|ppp\|ocserv\|pptpd" /var/log/syslog 2>/dev/null | tail -n 30
                
                # Check authentication logs
                print_message "$YELLOW" "لاگ‌های احراز هویت:"
                grep -i "vpn\|ppp\|ocserv\|pptpd" /var/log/auth.log 2>/dev/null | tail -n 30
                
                print_message "$GREEN" "✅ بررسی لاگ‌ها به پایان رسید."
                ;;
            0)
                return 0
                ;;
            *)
                print_message "$RED" "گزینه نامعتبر!"
                ;;
        esac
        
        read -p "$(echo -e "${BLUE}فشار دهید Enter را برای ادامه...${NC}")" continue_key
    done
}

# Function to diagnose OpenConnect issues
diagnose_openconnect_issues() {
    print_message "$BLUE" "Diagnosing OpenConnect VPN issues..."
    
    # Check if ocserv is installed
    if ! command -v ocserv >/dev/null 2>&1; then
        print_message "$RED" "OpenConnect server (ocserv) is not installed!"
        read -p "Do you want to install OpenConnect server now? (y/n): " install_oc
        if [[ "$install_oc" =~ ^[Yy]$ ]]; then
            install_packages
            configure_openconnect
            return
        else
            return 1
        fi
    fi
    
    # Check configuration file
    print_message "$YELLOW" "Checking OpenConnect configuration..."
    if [ ! -f "/etc/ocserv/ocserv.conf" ]; then
        print_message "$RED" "Configuration file not found!"
        read -p "Do you want to create a new configuration file? (y/n): " create_conf
        if [[ "$create_conf" =~ ^[Yy]$ ]]; then
            configure_openconnect
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "Configuration file exists."
    fi
    
    # Check certificates
    print_message "$YELLOW" "Checking OpenConnect certificates..."
    local cert_issues=0
    
    # Check CA certificate
    if [ ! -f "/etc/ocserv/ssl/ca-cert.pem" ]; then
        print_message "$RED" "CA certificate not found!"
        cert_issues=$((cert_issues + 1))
    else
        print_message "$GREEN" "Certificate file exists: /etc/ocserv/ssl/ca-cert.pem"
    fi
    
    # Check server certificate
    if [ ! -f "/etc/ocserv/ssl/server-cert.pem" ]; then
        print_message "$RED" "Server certificate not found!"
        cert_issues=$((cert_issues + 1))
    else
        print_message "$GREEN" "Certificate file exists: /etc/ocserv/ssl/server-cert.pem"
    fi
    
    # Check server key
    if [ ! -f "/etc/ocserv/ssl/server-key.pem" ]; then
        print_message "$RED" "Server key not found!"
        cert_issues=$((cert_issues + 1))
    else
        print_message "$GREEN" "Certificate file exists: /etc/ocserv/ssl/server-key.pem"
    fi
    
    # Check OpenConnect service
    print_message "$YELLOW" "Checking OpenConnect service status..."
    if systemctl is-active --quiet ocserv; then
        print_message "$GREEN" "OpenConnect service is running."
    else
        print_message "$YELLOW" "OpenConnect service is not running!"
        print_message "$YELLOW" "Attempting to diagnose the issue..."
        
        print_message "$YELLOW" "OpenConnect service log:"
        journalctl -u ocserv --no-pager -n 20
        
        # Fix common issues
        print_message "$YELLOW" "Checking for common configuration issues..."
        
        # Check for problematic options
        if grep -q "cookie-validate" /etc/ocserv/ocserv.conf; then
            print_message "$YELLOW" "Removing problematic 'cookie-validate' option..."
            sed -i '/cookie-validate/d' /etc/ocserv/ocserv.conf
        fi
        
        if grep -q "syslog" /etc/ocserv/ocserv.conf; then
            print_message "$YELLOW" "Removing problematic 'syslog' option..."
            sed -i '/syslog/d' /etc/ocserv/ocserv.conf
        fi
        
        # Check for user-profile
        if grep -q "user-profile = profile.xml" /etc/ocserv/ocserv.conf; then
            print_message "$YELLOW" "Removing reference to missing profile.xml..."
            sed -i '/user-profile = profile.xml/d' /etc/ocserv/ocserv.conf
        fi
        
        # Restart the service
        print_message "$YELLOW" "Restarting OpenConnect service..."
        systemctl restart ocserv
        
        if systemctl is-active --quiet ocserv; then
            print_message "$GREEN" "OpenConnect service started successfully after fixes."
        else
            print_message "$RED" "OpenConnect service still failing to start."
            print_message "$YELLOW" "Please fix the issues above and then run 'systemctl restart ocserv'."
        fi
    fi
    
    read -p "Press Enter to continue..."
    return 0
}

# Function to diagnose and troubleshoot WireGuard VPN
diagnose_wireguard_issues() {
    print_message "$BLUE" "🔍 WIREGUARD VPN DIAGNOSTICS 🔍"
    
    # Check if WireGuard is installed
    if ! command -v wg &> /dev/null; then
        print_message "$RED" "WireGuard is not installed!"
        read -p "Do you want to install WireGuard now? (y/n): " install_wg
        if [[ "$install_wg" =~ ^[Yy]$ ]]; then
            install_wireguard
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "WireGuard is installed."
    fi
    
    # Check WireGuard configuration
    print_message "$YELLOW" "Checking WireGuard configuration..."
    WG_DIR="/etc/wireguard"
    if [ ! -d "$WG_DIR" ]; then
        print_message "$RED" "WireGuard configuration directory not found!"
        return 1
    fi
    
    if [ ! -f "$WG_DIR/wg0.conf" ]; then
        print_message "$RED" "WireGuard configuration file not found!"
        read -p "Do you want to create a new configuration? (y/n): " create_conf
        if [[ "$create_conf" =~ ^[Yy]$ ]]; then
            install_wireguard
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "WireGuard configuration file exists."
    fi
    
    # Check WireGuard keys
    print_message "$YELLOW" "Checking WireGuard keys..."
    if [ ! -f "$WG_DIR/server_private.key" ] || [ ! -f "$WG_DIR/server_public.key" ]; then
        print_message "$RED" "WireGuard server keys not found!"
        print_message "$YELLOW" "Generating new WireGuard keys..."
        wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
        chmod 600 "$WG_DIR/server_private.key"
        chmod 644 "$WG_DIR/server_public.key"
        print_message "$GREEN" "WireGuard keys generated successfully."
    else
        print_message "$GREEN" "WireGuard keys exist."
    fi
    
    # Check WireGuard service status
    print_message "$YELLOW" "Checking WireGuard service status..."
    if systemctl is-active --quiet wg-quick@wg0; then
        print_message "$GREEN" "WireGuard service is running."
    else
        print_message "$YELLOW" "WireGuard service is not running!"
        print_message "$YELLOW" "Attempting to start WireGuard service..."
        systemctl start wg-quick@wg0
        
        if systemctl is-active --quiet wg-quick@wg0; then
            print_message "$GREEN" "WireGuard service started successfully."
        else
            print_message "$RED" "WireGuard service failed to start."
            print_message "$YELLOW" "WireGuard service log:"
            journalctl -u wg-quick@wg0 --no-pager -n 20
            
            # Check common issues
            print_message "$YELLOW" "Checking for common configuration issues..."
            
            # Check if server private key is correctly set in wg0.conf
            if ! grep -q "PrivateKey" "$WG_DIR/wg0.conf"; then
                print_message "$RED" "PrivateKey not found in WireGuard configuration."
                SERVER_PRIVATE_KEY=$(cat "$WG_DIR/server_private.key")
                print_message "$YELLOW" "Adding server private key to configuration..."
                sed -i "s|\[Interface\]|\[Interface\]\nPrivateKey = $SERVER_PRIVATE_KEY|" "$WG_DIR/wg0.conf"
            fi
            
            # Ensure IP forwarding is enabled
            if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -ne 1 ]; then
                print_message "$RED" "IP forwarding is not enabled."
                print_message "$YELLOW" "Enabling IP forwarding..."
                echo 1 > /proc/sys/net/ipv4/ip_forward
                echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
                sysctl -p /etc/sysctl.d/99-wireguard.conf
            fi
            
            # Restart WireGuard service
            print_message "$YELLOW" "Restarting WireGuard service..."
            systemctl restart wg-quick@wg0
            
            if systemctl is-active --quiet wg-quick@wg0; then
                print_message "$GREEN" "WireGuard service started successfully after fixes."
            else
                print_message "$RED" "WireGuard service still failing to start."
                print_message "$YELLOW" "Please check the system logs for more details."
            fi
        fi
    fi
    
    # Check WireGuard interface
    print_message "$YELLOW" "Checking WireGuard interface status..."
    if ip link show wg0 &> /dev/null; then
        print_message "$GREEN" "WireGuard interface exists."
        wg show
    else
        print_message "$RED" "WireGuard interface does not exist!"
    fi
    
    # Check for active connections
    print_message "$YELLOW" "Checking for active connections..."
    CONNECTIONS=$(wg show wg0 | grep -c "peer:")
    if [ "$CONNECTIONS" -gt 0 ]; then
        print_message "$GREEN" "WireGuard has $CONNECTIONS active peer(s)."
        wg show wg0
    else
        print_message "$YELLOW" "No active WireGuard connections."
    fi
    
    # Display WireGuard server info
    print_message "$BLUE" "WireGuard Server Information:"
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    SERVER_PORT=$(grep "ListenPort" "$WG_DIR/wg0.conf" | awk '{print $3}')
    SERVER_PUBLIC_KEY=$(cat "$WG_DIR/server_public.key")
    
    print_message "$YELLOW" "Server IP: $SERVER_IP"
    print_message "$YELLOW" "Server Port: $SERVER_PORT"
    print_message "$YELLOW" "Server Public Key: $SERVER_PUBLIC_KEY"
    
    read -p "Press Enter to continue..."
    return 0
}

# Function to diagnose and troubleshoot PPTP VPN
diagnose_pptp_issues() {
    print_message "$BLUE" "🔍 PPTP VPN DIAGNOSTICS 🔍"
    
    # Check if PPTP is installed
    if ! command -v pptpd &> /dev/null; then
        print_message "$RED" "PPTP server is not installed!"
        read -p "Do you want to install PPTP server now? (y/n): " install_pptp
        if [[ "$install_pptp" =~ ^[Yy]$ ]]; then
            configure_pptp
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "PPTP server is installed."
    fi
    
    # Check PPTP configuration files
    print_message "$YELLOW" "Checking PPTP configuration..."
    if [ ! -f "/etc/pptpd.conf" ]; then
        print_message "$RED" "PPTP configuration file not found!"
        read -p "Do you want to create a new configuration? (y/n): " create_conf
        if [[ "$create_conf" =~ ^[Yy]$ ]]; then
            configure_pptp
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "PPTP configuration file exists."
    fi
    
    # Check PPP options file
    if [ ! -f "/etc/ppp/pptpd-options" ]; then
        print_message "$RED" "PPTP options file not found!"
        read -p "Do you want to create a new options file? (y/n): " create_opts
        if [[ "$create_opts" =~ ^[Yy]$ ]]; then
            configure_pptp
            return
        else
            return 1
        fi
    else
        print_message "$GREEN" "PPTP options file exists."
    fi
    
    # Check PPTP users
    print_message "$YELLOW" "Checking PPTP users..."
    if [ ! -f "/etc/ppp/chap-secrets" ]; then
        print_message "$RED" "PPTP user file not found!"
        touch /etc/ppp/chap-secrets
        print_message "$GREEN" "Created empty PPTP user file."
    else
        PPTP_USERS=$(grep -c "pptpd" /etc/ppp/chap-secrets)
        if [ "$PPTP_USERS" -gt 0 ]; then
            print_message "$GREEN" "Found $PPTP_USERS PPTP user(s)."
            grep "pptpd" /etc/ppp/chap-secrets
        else
            print_message "$YELLOW" "No PPTP users found."
        fi
    fi
    
    # Check PPTP service status
    print_message "$YELLOW" "Checking PPTP service status..."
    if systemctl is-active --quiet pptpd; then
        print_message "$GREEN" "PPTP service is running."
    else
        print_message "$RED" "PPTP service is not running!"
        print_message "$YELLOW" "Attempting to start PPTP service..."
        systemctl start pptpd
        
        if systemctl is-active --quiet pptpd; then
            print_message "$GREEN" "PPTP service started successfully."
        else
            print_message "$RED" "PPTP service failed to start."
            print_message "$YELLOW" "PPTP service log:"
            journalctl -u pptpd --no-pager -n 20
            
            # Check common issues
            print_message "$YELLOW" "Checking for common configuration issues..."
            
            # Check if localip and remoteip are set
            if ! grep -q "localip" /etc/pptpd.conf || ! grep -q "remoteip" /etc/pptpd.conf; then
                print_message "$RED" "Missing IP configuration in pptpd.conf."
                print_message "$YELLOW" "Adding IP configuration..."
                
                if ! grep -q "localip" /etc/pptpd.conf; then
                    echo "localip 192.168.0.1" >> /etc/pptpd.conf
                fi
                
                if ! grep -q "remoteip" /etc/pptpd.conf; then
                    echo "remoteip 192.168.0.200-238,192.168.0.245" >> /etc/pptpd.conf
                fi
            fi
            
            # Ensure IP forwarding is enabled
            if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -ne 1 ]; then
                print_message "$RED" "IP forwarding is not enabled."
                print_message "$YELLOW" "Enabling IP forwarding..."
                echo 1 > /proc/sys/net/ipv4/ip_forward
                echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-pptp.conf
                sysctl -p /etc/sysctl.d/99-pptp.conf
            fi
            
            # Check DNS settings
            if ! grep -q "ms-dns" /etc/ppp/pptpd-options; then
                print_message "$RED" "DNS settings not found in pptpd-options."
                print_message "$YELLOW" "Adding DNS settings..."
                echo "ms-dns 8.8.8.8" >> /etc/ppp/pptpd-options
                echo "ms-dns 8.8.4.4" >> /etc/ppp/pptpd-options
            fi
            
            # Restart PPTP service
            print_message "$YELLOW" "Restarting PPTP service..."
            systemctl restart pptpd
            
            if systemctl is-active --quiet pptpd; then
                print_message "$GREEN" "PPTP service started successfully after fixes."
            else
                print_message "$RED" "PPTP service still failing to start."
                print_message "$YELLOW" "Please check the system logs for more details."
            fi
        fi
    fi
    
    # Check if port is open
    print_message "$YELLOW" "Checking PPTP port (1723)..."
    if netstat -tuln | grep -q ":1723"; then
        print_message "$GREEN" "PPTP port is open and listening."
    else
        print_message "$RED" "PPTP port is not listening!"
        print_message "$YELLOW" "This may indicate a configuration issue."
    fi
    
    # Check active connections
    print_message "$YELLOW" "Checking for active connections..."
    ACTIVE_CONNECTIONS=$(netstat -anp | grep pptpd | grep -c ESTABLISHED)
    if [ "$ACTIVE_CONNECTIONS" -gt 0 ]; then
        print_message "$GREEN" "PPTP has $ACTIVE_CONNECTIONS active connection(s)."
        netstat -anp | grep pptpd | grep ESTABLISHED
    else
        print_message "$YELLOW" "No active PPTP connections."
    fi
    
    # Check NAT rules
    print_message "$YELLOW" "Checking NAT rules for PPTP..."
    if iptables -t nat -C POSTROUTING -s 192.168.0.0/24 -j MASQUERADE &>/dev/null; then
        print_message "$GREEN" "NAT rules for PPTP are properly configured."
    else
        print_message "$RED" "NAT rules for PPTP are missing!"
        print_message "$YELLOW" "Adding NAT rules..."
        
        # Try to detect the main interface
        MAIN_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)')
        if [ -z "$MAIN_INTERFACE" ]; then
            MAIN_INTERFACE="eth0"  # Fallback to eth0
        fi
        
        iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o $MAIN_INTERFACE -j MASQUERADE
        print_message "$GREEN" "NAT rules added for PPTP."
        
        # Make iptables rules persistent
        if command -v iptables-save >/dev/null 2>&1; then
            if [ -d "/etc/iptables" ]; then
                iptables-save > /etc/iptables/rules.v4
            else
                iptables-save > /etc/iptables.rules
            fi
            print_message "$GREEN" "Firewall rules saved for persistence."
        fi
    fi
    
    # Display PPTP server info
    print_message "$BLUE" "PPTP Server Information:"
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    print_message "$YELLOW" "Server IP: $SERVER_IP"
    print_message "$YELLOW" "Server Port: 1723"
    print_message "$YELLOW" "Protocol: PPTP"
    
    read -p "Press Enter to continue..."
    return 0
}

# Function for advanced VPN diagnostics
advanced_vpn_diagnostics() {
    print_message "$BLUE" "🔬 ADVANCED VPN DIAGNOSTICS AND PERFORMANCE ANALYSIS 🔬"
    
    # Create diagnostics directory
    DIAG_DIR="/var/log/vpn_diagnostics"
    mkdir -p "$DIAG_DIR"
    
    # Generate timestamp for this diagnostic session
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    LOG_FILE="$DIAG_DIR/vpn_diag_$TIMESTAMP.log"
    
    print_message "$YELLOW" "Creating comprehensive diagnostic log at: $LOG_FILE"
    echo "VPN DIAGNOSTIC SESSION - $(date)" > "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
    
    # System Information
    print_message "$YELLOW" "Gathering system information..."
    echo "SYSTEM INFORMATION:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    echo "Hostname: $(hostname)" >> "$LOG_FILE"
    echo "Kernel: $(uname -r)" >> "$LOG_FILE"
    echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d \")" >> "$LOG_FILE"
    echo "CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')" >> "$LOG_FILE"
    echo "Memory: $(free -h | grep Mem | awk '{print $2}')" >> "$LOG_FILE"
    echo "Disk Usage: $(df -h / | grep -v Filesystem | awk '{print $5}')" >> "$LOG_FILE"
    echo "Uptime: $(uptime -p)" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    # Network Information
    print_message "$YELLOW" "Analyzing network configuration..."
    echo "NETWORK INFORMATION:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    echo "IP Addresses:" >> "$LOG_FILE"
    ip -4 addr show | grep inet >> "$LOG_FILE"
    echo "Default Routes:" >> "$LOG_FILE"
    ip route | grep default >> "$LOG_FILE"
    echo "DNS Configuration:" >> "$LOG_FILE"
    cat /etc/resolv.conf >> "$LOG_FILE"
    echo "IP Forwarding Status:" >> "$LOG_FILE"
    cat /proc/sys/net/ipv4/ip_forward >> "$LOG_FILE"
    echo "NAT Rules:" >> "$LOG_FILE"
    iptables -t nat -L -v >> "$LOG_FILE"
    echo "Filter Rules:" >> "$LOG_FILE"
    iptables -L -v >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    # SEPARATE DIAGNOSTICS FOR EACH SERVICE
    print_message "$BLUE" "Running separate diagnostics for each VPN service..."
    
    # OpenConnect Diagnostics
    print_message "$YELLOW" "Analyzing OpenConnect VPN..."
    echo "OPENCONNECT DIAGNOSTICS:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    if command -v ocserv &> /dev/null; then
        echo "OpenConnect server is installed." >> "$LOG_FILE"
        
        echo "Configuration validation:" >> "$LOG_FILE"
        if [ -f "/etc/ocserv/ocserv.conf" ]; then
            echo "✓ Configuration file exists" >> "$LOG_FILE"
            
            # Extract key configuration parameters
            echo "TCP port: $(grep -oP 'tcp-port = \K\d+' /etc/ocserv/ocserv.conf || echo 'not specified')" >> "$LOG_FILE"
            echo "UDP port: $(grep -oP 'udp-port = \K\d+' /etc/ocserv/ocserv.conf || echo 'not specified')" >> "$LOG_FILE"
            echo "Auth method: $(grep -oP 'auth = \K.*' /etc/ocserv/ocserv.conf || echo 'not specified')" >> "$LOG_FILE"
            
            # Check for problematic settings
            if grep -q "cookie-validate" /etc/ocserv/ocserv.conf; then
                echo "⚠️ WARNING: cookie-validate option may cause issues" >> "$LOG_FILE"
            fi
            
            if grep -q "profile.xml" /etc/ocserv/ocserv.conf; then
                echo "⚠️ WARNING: profile.xml reference found but file might not exist" >> "$LOG_FILE"
            fi
        else
            echo "✗ Configuration file missing!" >> "$LOG_FILE"
        fi
        
        echo "Service status:" >> "$LOG_FILE"
        if systemctl is-active --quiet ocserv; then
            echo "✓ Service is running" >> "$LOG_FILE"
        else
            echo "✗ Service is NOT running" >> "$LOG_FILE"
        fi
        
        echo "Port check:" >> "$LOG_FILE"
        OC_PORT=$(grep -oP 'tcp-port = \K\d+' /etc/ocserv/ocserv.conf || echo "443")
        if netstat -tuln | grep -q ":$OC_PORT"; then
            echo "✓ Port $OC_PORT is listening" >> "$LOG_FILE"
        else
            echo "✗ Port $OC_PORT is NOT listening" >> "$LOG_FILE"
        fi
        
        echo "Recent logs:" >> "$LOG_FILE"
        journalctl -u ocserv --no-pager -n 20 >> "$LOG_FILE"
    else
        echo "OpenConnect server is NOT installed." >> "$LOG_FILE"
    fi
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    # PPTP Diagnostics
    print_message "$YELLOW" "Analyzing PPTP VPN..."
    echo "PPTP DIAGNOSTICS:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    if command -v pptpd &> /dev/null; then
        echo "PPTP server is installed." >> "$LOG_FILE"
        
        echo "Configuration validation:" >> "$LOG_FILE"
        if [ -f "/etc/pptpd.conf" ]; then
            echo "✓ Configuration file exists" >> "$LOG_FILE"
            echo "Local IP: $(grep -oP 'localip \K.*' /etc/pptpd.conf || echo 'not specified')" >> "$LOG_FILE"
            echo "Remote IP range: $(grep -oP 'remoteip \K.*' /etc/pptpd.conf || echo 'not specified')" >> "$LOG_FILE"
        else
            echo "✗ Configuration file missing!" >> "$LOG_FILE"
        fi
        
        if [ -f "/etc/ppp/pptpd-options" ]; then
            echo "✓ Options file exists" >> "$LOG_FILE"
            echo "DNS settings: $(grep 'ms-dns' /etc/ppp/pptpd-options || echo 'DNS not configured')" >> "$LOG_FILE"
        else
            echo "✗ Options file missing!" >> "$LOG_FILE"
        fi
        
        echo "Service status:" >> "$LOG_FILE"
        if systemctl is-active --quiet pptpd; then
            echo "✓ Service is running" >> "$LOG_FILE"
        else
            echo "✗ Service is NOT running" >> "$LOG_FILE"
        fi
        
        echo "Port check:" >> "$LOG_FILE"
        if netstat -tuln | grep -q ":1723"; then
            echo "✓ Port 1723 is listening" >> "$LOG_FILE"
        else
            echo "✗ Port 1723 is NOT listening" >> "$LOG_FILE"
        fi
        
        echo "Users configured:" >> "$LOG_FILE"
        if [ -f "/etc/ppp/chap-secrets" ]; then
            grep pptpd /etc/ppp/chap-secrets >> "$LOG_FILE" || echo "No PPTP users found" >> "$LOG_FILE"
        else
            echo "✗ User file missing!" >> "$LOG_FILE"
        fi
        
        echo "Recent logs:" >> "$LOG_FILE"
        journalctl -u pptpd --no-pager -n 20 >> "$LOG_FILE"
    else
        echo "PPTP server is NOT installed." >> "$LOG_FILE"
    fi
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    # WireGuard Diagnostics
    print_message "$YELLOW" "Analyzing WireGuard VPN..."
    echo "WIREGUARD DIAGNOSTICS:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    if command -v wg &> /dev/null; then
        echo "WireGuard is installed." >> "$LOG_FILE"
        
        echo "Configuration validation:" >> "$LOG_FILE"
        if [ -f "/etc/wireguard/wg0.conf" ]; then
            echo "✓ Configuration file exists" >> "$LOG_FILE"
            echo "Listen port: $(grep -oP 'ListenPort = \K\d+' /etc/wireguard/wg0.conf || echo 'not specified')" >> "$LOG_FILE"
            echo "Address: $(grep -oP 'Address = \K.*' /etc/wireguard/wg0.conf || echo 'not specified')" >> "$LOG_FILE"
        else
            echo "✗ Configuration file missing!" >> "$LOG_FILE"
        fi
        
        echo "Service status:" >> "$LOG_FILE"
        if systemctl is-active --quiet wg-quick@wg0; then
            echo "✓ Service is running" >> "$LOG_FILE"
        else
            echo "✗ Service is NOT running" >> "$LOG_FILE"
        fi
        
        echo "Interface status:" >> "$LOG_FILE"
        if ip link show wg0 &> /dev/null; then
            echo "✓ Interface wg0 exists" >> "$LOG_FILE"
            wg show >> "$LOG_FILE"
        else
            echo "✗ Interface wg0 does NOT exist" >> "$LOG_FILE"
        fi
        
        echo "Recent logs:" >> "$LOG_FILE"
        journalctl -u wg-quick@wg0 --no-pager -n 20 >> "$LOG_FILE"
    else
        echo "WireGuard is NOT installed." >> "$LOG_FILE"
    fi
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    # Check for critical issues
    print_message "$YELLOW" "Analyzing for critical issues..."
    echo "CRITICAL ISSUES SUMMARY:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    
    CRITICAL_ISSUES=0
    
    # Check IP forwarding
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
        echo "⚠️ CRITICAL: IP forwarding is disabled!" >> "$LOG_FILE"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for NAT rules
    if ! iptables -t nat -L | grep -q MASQUERADE; then
        echo "⚠️ CRITICAL: NAT rules are missing!" >> "$LOG_FILE"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
    
    # Check for port conflicts
    OC_PORT=$(grep -oP 'tcp-port = \K\d+' /etc/ocserv/ocserv.conf 2>/dev/null || echo "443")
    WG_PORT=$(grep -oP 'ListenPort = \K\d+' /etc/wireguard/wg0.conf 2>/dev/null || echo "51820")
    
    if netstat -tuln | grep -q ":$OC_PORT" && systemctl is-active --quiet ocserv; then
        if netstat -tuln | grep ":$OC_PORT" | grep -qv ocserv; then
            echo "⚠️ CRITICAL: Port conflict detected for OpenConnect port $OC_PORT!" >> "$LOG_FILE"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        fi
    fi
    
    if netstat -tuln | grep -q ":1723" && systemctl is-active --quiet pptpd; then
        if netstat -tuln | grep ":1723" | grep -qv pptpd; then
            echo "⚠️ CRITICAL: Port conflict detected for PPTP port 1723!" >> "$LOG_FILE"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        fi
    fi
    
    if netstat -tuln | grep -q ":$WG_PORT" && systemctl is-active --quiet wg-quick@wg0; then
        if netstat -tuln | grep ":$WG_PORT" | grep -qv wg; then
            echo "⚠️ CRITICAL: Port conflict detected for WireGuard port $WG_PORT!" >> "$LOG_FILE"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        fi
    fi
    
    echo "-----------------------------------------" >> "$LOG_FILE"
    if [ $CRITICAL_ISSUES -eq 0 ]; then
        echo "✅ No critical issues detected" >> "$LOG_FILE"
    else
        echo "⚠️ $CRITICAL_ISSUES critical issues detected!" >> "$LOG_FILE"
    fi
    
    # Server information
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo "SERVER INFORMATION:" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    echo "Server IP: $SERVER_IP" >> "$LOG_FILE"
    echo "OpenConnect port: $OC_PORT" >> "$LOG_FILE"
    echo "PPTP port: 1723" >> "$LOG_FILE"
    echo "WireGuard port: $WG_PORT" >> "$LOG_FILE"
    echo "-----------------------------------------" >> "$LOG_FILE"
    echo "End of diagnostic report - $(date)" >> "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
    
    # Display summary to the user
    print_message "$GREEN" "✅ Comprehensive diagnostics completed!"
    print_message "$YELLOW" "Detailed report saved to: $LOG_FILE"
    
    if [ $CRITICAL_ISSUES -eq 0 ]; then
        print_message "$GREEN" "No critical issues detected."
    else
        print_message "$RED" "$CRITICAL_ISSUES critical issues detected!"
        print_message "$YELLOW" "Please check the log file for details."
    fi
    
    # Ask if user wants to view log
    print_message "$BLUE" "Would you like to view the diagnostic log? [y/N]"
    read -r view_log
    
    if [[ "$view_log" =~ ^[Yy]$ ]]; then
        if command -v less &> /dev/null; then
            less "$LOG_FILE"
        else
            more "$LOG_FILE" || cat "$LOG_FILE"
        fi
    fi
    
    read -p "Press Enter to return to the menu..."
}

# Function to install and configure WireGuard VPN
install_wireguard() {
    print_message "$BLUE" "Installing and configuring WireGuard VPN..."
    
    # Check if WireGuard is already installed
    if command -v wg &> /dev/null; then
        print_message "$GREEN" "WireGuard is already installed."
    else
        print_message "$YELLOW" "WireGuard not found. Installing..."
        apt-get update
        apt-get install -y wireguard wireguard-tools
        
        # Check if installation was successful
        if ! command -v wg &> /dev/null; then
            print_message "$RED" "Failed to install WireGuard. Please check your system and try again."
            return 1
        fi
        print_message "$GREEN" "WireGuard installed successfully."
    fi
    
    # Create WireGuard directory if it doesn't exist
    WG_DIR="/etc/wireguard"
    if [ ! -d "$WG_DIR" ]; then
        mkdir -p "$WG_DIR"
        chmod 700 "$WG_DIR"
    fi
    
    # Generate server private and public keys if they don't exist
    if [ ! -f "$WG_DIR/server_private.key" ]; then
        print_message "$YELLOW" "Generating WireGuard server keys..."
        wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
        chmod 600 "$WG_DIR/server_private.key"
        chmod 644 "$WG_DIR/server_public.key"
    fi
    
    SERVER_PRIVATE_KEY=$(cat "$WG_DIR/server_private.key")
    
    # Create basic WireGuard configuration
    print_message "$YELLOW" "Creating basic WireGuard configuration..."
    cat > "$WG_DIR/wg0.conf" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.10.10.1/24
ListenPort = 51820
SaveConfig = true

# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -t nat -A POSTROUTING -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)') -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)') -j MASQUERADE
EOF
    
    # Set proper permissions
    chmod 600 "$WG_DIR/wg0.conf"
    
    # Create client directory
    mkdir -p "$WG_DIR/clients"
    
    # Enable and start the WireGuard service
    print_message "$YELLOW" "Enabling and starting WireGuard service..."
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Display server information
    print_message "$GREEN" "WireGuard VPN has been configured successfully!"
    
    return 0
}

# Check if running as root and display the main menu
check_root
show_menu
