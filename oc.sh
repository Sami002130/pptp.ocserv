#!/bin/bash
# OCServ Auto Installer & Manager with Quota
# Run as root

set -e

# ---------- Functions ----------

function install_ocserv() {
    echo "===== Installing OCServ and dependencies ====="
    apt update
    apt install -y ocserv gnutls-bin net-tools iptables-persistent certbot

    read -p "Enter your VPN domain (e.g., vpn.example.com): " DOMAIN
    read -p "Enter VPN TCP/UDP port (default 443): " PORT
    PORT=${PORT:-443}
    read -p "Enter VPN admin username: " VPNUSER
    read -s -p "Enter VPN admin password: " VPNPASS
    echo ""

    # Obtain SSL
    certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN

    CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

    # DH params
    echo "Generating DH params..."
    certtool --generate-dh-params --outfile /etc/ocserv/dh2048.pem
    chmod 600 /etc/ocserv/dh2048.pem

    # Configure ocserv with secure settings
    echo "Writing ocserv configuration..."
    cat > /etc/ocserv/ocserv.conf <<EOL
### Port settings
tcp-port = $PORT
udp-port = $PORT

### TLS Certificates
server-cert = $CERT_PATH
server-key = $KEY_PATH

### TLS security
tls-priorities = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:+VERS-TLS1.3:-CIPHER-ALL:+AES-256-GCM:+AES-128-GCM:+CHACHA20-POLY1305"

### Authentication
auth = "plain[/etc/ocserv/ocpasswd]"

### Brute-force protection
rate-limit-ms = 1000
auth-timeout = 40

### Socket for systemd
socket-file = /var/run/ocserv-socket

### Virtual device
device = vpns0

### IP range for clients
ipv4-network = 192.168.100.0
ipv4-netmask = 255.255.255.0

### DNS servers for clients (secure)
dns = 1.1.1.1
dns = 9.9.9.9

### Maximum clients
max-clients = 50
max-same-clients = 1

### Tunneling & MTU
tunnel-all-dns = true
try-mtu-discovery = true
mtu = 1400

### Keepalive and dead peer detection
keepalive = 60
dpd = 90
mobile-dpd = 180

### Logging
log-level = 3

### Compression
compression = true

### Misc
no-route = false
dh-params = /etc/ocserv/dh2048.pem
EOL

    # Create admin user
    ocpasswd -c /etc/ocserv/ocpasswd $VPNUSER <<< $VPNPASS

    # Enable NAT
    sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    IFACE=$(ip route | grep default | awk '{print $5}')
    iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
    netfilter-persistent save

    # Start ocserv
    systemctl daemon-reload
    systemctl enable ocserv
    systemctl restart ocserv

    echo "===== OCServ Installation Complete ====="
    echo "Connect with OpenConnect / AnyConnect to: https://$DOMAIN:$PORT"
    echo "Username: $VPNUSER"
}

# ---------- User Management ----------
function add_user() {
    read -p "Enter new VPN username: " VPNUSER
    read -s -p "Enter VPN password: " VPNPASS
    echo ""
    read -p "Enter traffic limit in GB: " GBLIMIT
    MBLIMIT=$((GBLIMIT*1024))

    # Add user
    ocpasswd -c /etc/ocserv/ocpasswd $VPNUSER <<< $VPNPASS

    # Save quota
    mkdir -p /etc/ocserv
    touch /etc/ocserv/users_quota.txt
    # Format: username:limitMB:usedMB
    echo "$VPNUSER:$MBLIMIT:0" >> /etc/ocserv/users_quota.txt

    echo "User $VPNUSER added with $GBLIMIT GB limit."
}

function list_users() {
    echo "Existing VPN users:"
    cut -d: -f1 /etc/ocserv/ocpasswd
}

function enforce_single_client() {
    # Ensure max-same-clients = 1
    sed -i 's/^max-same-clients.*/max-same-clients = 1/' /etc/ocserv/ocserv.conf
    systemctl restart ocserv
    echo "All users are now limited to a single connection."
}

# ---------- Quota Checker (to be run via cron) ----------
function quota_check() {
    LOG_FILE="/var/log/ocserv/ocserv.log"
    QUOTA_FILE="/etc/ocserv/users_quota.txt"

    while IFS=: read -r user limit used; do
        if [ "$used" -ge "$limit" ]; then
            echo "Disconnecting $user: quota exceeded"
            pkill -f "ocserv.*$user"
        fi
    done < $QUOTA_FILE
}

# ---------- Main ----------
if systemctl is-active --quiet ocserv; then
    echo "OCServ is running. Management mode:"
    while true; do
        echo "1) Add user with traffic limit"
        echo "2) List users"
        echo "3) Enforce single connection"
        echo "4) Exit"
        read -p "Choose an option: " CHOICE
        case $CHOICE in
            1) add_user ;;
            2) list_users ;;
            3) enforce_single_client ;;
            4) exit 0 ;;
            *) echo "Invalid option" ;;
        esac
    done
else
    echo "OCServ not running. Installing..."
    install_ocserv
fi
