#!/bin/bash
#
# dnsttEx server setup script
# Supports Fedora, Rocky, CentOS, Debian, Ubuntu
# Repo: https://github.com/AliRezaBeigy/dnsttEx
# Usage: curl -sSL <SCRIPT_URL> | sudo bash
#
set -e

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (use: sudo bash)"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_URL="https://raw.githubusercontent.com/AliRezaBeigy/dnsttEx/main/scripts/dnsttEx-deploy.sh"
RELEASE_BASE="https://github.com/AliRezaBeigy/dnsttEx/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dnsttEx"
SYSTEMD_DIR="/etc/systemd/system"
DNSTT_PORT="53"
DNSTT_USER="dnsttEx"
SERVICE_NAME="dnsttEx-server"
CONFIG_FILE="${CONFIG_DIR}/dnsttEx-server.conf"
SCRIPT_INSTALL_PATH="/usr/local/bin/dnsttEx-deploy"
UPDATE_AVAILABLE=false

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
print_question() { echo -ne "${BLUE}[?]${NC} $1"; }

# Install or update this script when run via curl
install_script() {
    print_status "Installing/updating dnsttEx-deploy script..."
    local tmp="/tmp/dnsttEx-deploy-new.sh"
    if ! curl -sSL "$SCRIPT_URL" -o "$tmp"; then
        print_error "Failed to download script from $SCRIPT_URL"
    fi
    chmod +x "$tmp"
    if [[ -f "$SCRIPT_INSTALL_PATH" ]]; then
        local current_checksum new_checksum
        current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
        new_checksum=$(sha256sum "$tmp" | cut -d' ' -f1)
        if [[ "$current_checksum" == "$new_checksum" ]]; then
            print_status "Script is already up to date"
            rm -f "$tmp"
            return 0
        fi
        print_status "Updating existing script..."
    fi
    cp "$tmp" "$SCRIPT_INSTALL_PATH"
    rm -f "$tmp"
    print_status "Script installed to $SCRIPT_INSTALL_PATH"
}

update_script() {
    print_status "Checking for script updates..."
    local tmp="/tmp/dnsttEx-deploy-latest.sh"
    if ! curl -sSL "$SCRIPT_URL" -o "$tmp"; then
        print_error "Failed to download latest version"
    fi
    chmod +x "$tmp"
    local current_checksum latest_checksum
    current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
    latest_checksum=$(sha256sum "$tmp" | cut -d' ' -f1)
    if [[ "$current_checksum" == "$latest_checksum" ]]; then
        print_status "You are already running the latest version"
        rm -f "$tmp"
        return 0
    fi
    print_status "New version available! Updating..."
    cp "$tmp" "$SCRIPT_INSTALL_PATH"
    rm -f "$tmp"
    print_status "Script updated. Restarting with new version..."
    exec "$SCRIPT_INSTALL_PATH" "$@"
}

show_menu() {
    echo ""
    print_status "dnsttEx Server Management"
    print_status "========================="
    if [[ "$UPDATE_AVAILABLE" == true ]]; then
        echo -e "${YELLOW}[UPDATE AVAILABLE]${NC} A new version of this script is available!"
        echo -e "${YELLOW}                  ${NC} Use option 2 to update."
        echo ""
    fi
    echo "1) Install/Reconfigure dnsttEx server"
    echo "2) Update dnsttEx-deploy script"
    echo "3) Check service status"
    echo "4) View service logs"
    echo "5) Show configuration info"
    echo "6) Uninstall dnsttEx server"
    echo "0) Exit"
    echo ""
    print_question "Please select an option (0-6): "
}

handle_menu() {
    while true; do
        show_menu
        read -r choice
        case $choice in
            1) print_status "Starting dnsttEx server installation/reconfiguration..."; return 0 ;;
            2) update_script ;;
            3)
                if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
                    print_status "$SERVICE_NAME is running"
                    systemctl status "$SERVICE_NAME" --no-pager -l
                else
                    print_warning "$SERVICE_NAME is not running"
                    systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null || true
                fi
                ;;
            4)
                print_status "Showing $SERVICE_NAME logs (Press Ctrl+C to exit)..."
                journalctl -u "$SERVICE_NAME" -f
                ;;
            5) show_configuration_info ;;
            6) uninstall_server ;;
            0) print_status "Goodbye!"; exit 0 ;;
            *) print_error "Invalid choice. Please enter 0-6." ;;
        esac
        if [[ "$choice" != "4" ]]; then
            echo ""
            print_question "Press Enter to continue..."
            read -r
        fi
    done
}

check_for_updates() {
    if [[ "$0" == "$SCRIPT_INSTALL_PATH" ]] && [[ -f "$SCRIPT_INSTALL_PATH" ]]; then
        print_status "Checking for script updates..."
        local tmp="/tmp/dnsttEx-deploy-latest.sh"
        if curl -sSL "$SCRIPT_URL" -o "$tmp" 2>/dev/null; then
            local current_checksum latest_checksum
            current_checksum=$(sha256sum "$SCRIPT_INSTALL_PATH" | cut -d' ' -f1)
            latest_checksum=$(sha256sum "$tmp" | cut -d' ' -f1)
            rm -f "$tmp"
            if [[ "$current_checksum" != "$latest_checksum" ]]; then
                UPDATE_AVAILABLE=true
                print_warning "New version available! Use menu option 2 to update."
            else
                print_status "Script is up to date"
            fi
        else
            print_warning "Could not check for updates (network issue)"
        fi
    fi
}

load_existing_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        . "$CONFIG_FILE"
        return 0
    fi
    return 1
}

save_config() {
    print_status "Saving configuration..."
    cat > "$CONFIG_FILE" << EOF
# dnsttEx server config - $(date)
NS_SUBDOMAIN="$NS_SUBDOMAIN"
MTU_VALUE="$MTU_VALUE"
TUNNEL_MODE="$TUNNEL_MODE"
PRIVATE_KEY_FILE="$PRIVATE_KEY_FILE"
PUBLIC_KEY_FILE="$PUBLIC_KEY_FILE"
EOF
    chmod 640 "$CONFIG_FILE"
    chown root:"$DNSTT_USER" "$CONFIG_FILE"
}

show_configuration_info() {
    print_status "Current Configuration"
    print_status "====================="
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_warning "No configuration found. Install/configure first (option 1)."
        return 0
    fi
    if ! load_existing_config; then
        print_error "Failed to load $CONFIG_FILE"
    fi
    local service_status
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        service_status="${GREEN}Running${NC}"
    else
        service_status="${RED}Stopped${NC}"
    fi
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  Nameserver subdomain: ${YELLOW}$NS_SUBDOMAIN${NC}"
    echo -e "  MTU: ${YELLOW}$MTU_VALUE${NC}"
    echo -e "  Tunnel mode: ${YELLOW}$TUNNEL_MODE${NC}"
    echo -e "  User: ${YELLOW}$DNSTT_USER${NC}"
    echo -e "  Listen port: ${YELLOW}$DNSTT_PORT${NC} (UDP)"
    echo -e "  Service status: $service_status"
    echo ""
    if [[ -f "$PUBLIC_KEY_FILE" ]]; then
        echo -e "${BLUE}Public key:${NC}"
        echo -e "${YELLOW}$(cat "$PUBLIC_KEY_FILE")${NC}"
        echo ""
    fi
    echo -e "${BLUE}Commands:${NC}"
    echo -e "  Menu:       ${YELLOW}dnsttEx-deploy${NC}"
    echo -e "  Start:      ${YELLOW}systemctl start $SERVICE_NAME${NC}"
    echo -e "  Stop:       ${YELLOW}systemctl stop $SERVICE_NAME${NC}"
    echo -e "  Status:     ${YELLOW}systemctl status $SERVICE_NAME${NC}"
    echo -e "  Logs:       ${YELLOW}journalctl -u $SERVICE_NAME -f${NC}"
    if [[ "$TUNNEL_MODE" == "socks" ]]; then
        echo ""
        echo -e "${BLUE}SOCKS proxy:${NC} 127.0.0.1:1080"
        echo -e "  ${YELLOW}systemctl status danted${NC}  ${YELLOW}journalctl -u danted -f${NC}"
    fi
    echo ""
}

remove_iptables_rules() {
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    iface="${iface:-eth0}"
    print_status "Removing iptables rules..."
    # Remove current port rule
    while iptables -C INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT
    done
    # Remove legacy redirect and port 5300 rules from older installations
    for old_port in 5300 "$DNSTT_PORT"; do
        while iptables -C INPUT -p udp --dport "$old_port" -j ACCEPT 2>/dev/null; do
            iptables -D INPUT -p udp --dport "$old_port" -j ACCEPT
        done
        while iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$old_port" 2>/dev/null; do
            iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$old_port"
        done
    done
    if command -v ip6tables &>/dev/null && [[ -f /proc/net/if_inet6 ]]; then
        for old_port in 5300 "$DNSTT_PORT"; do
            while ip6tables -C INPUT -p udp --dport "$old_port" -j ACCEPT 2>/dev/null; do
                ip6tables -D INPUT -p udp --dport "$old_port" -j ACCEPT
            done
            while ip6tables -t nat -C PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$old_port" 2>/dev/null; do
                ip6tables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports "$old_port"
            done
        done
    fi
    save_iptables_rules
}

remove_firewall_rules() {
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_status "Removing firewalld rules..."
        firewall-cmd --permanent --remove-port="${DNSTT_PORT}/udp" 2>/dev/null
        firewall-cmd --permanent --remove-port=53/udp 2>/dev/null
        firewall-cmd --permanent --remove-port=5300/udp 2>/dev/null
        firewall-cmd --reload 2>/dev/null
    fi
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        print_status "Removing ufw rules..."
        ufw delete allow "${DNSTT_PORT}/udp" 2>/dev/null
        ufw delete allow 53/udp 2>/dev/null
        ufw delete allow 5300/udp 2>/dev/null
    fi
}

uninstall_server() {
    print_warning "This will stop the dnsttEx server and remove binaries, config, and the system user."
    print_question "Continue? [y/N]: "
    read -r confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && print_status "Uninstall cancelled." && return 0

    detect_os
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Stopping $SERVICE_NAME..."
        systemctl stop "$SERVICE_NAME"
    fi
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Disabling $SERVICE_NAME..."
        systemctl disable "$SERVICE_NAME" 2>/dev/null
    fi
    local svc="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    if [[ -f "$svc" ]]; then
        print_status "Removing systemd service..."
        rm -f "$svc"
        systemctl daemon-reload
    fi

    remove_firewall_rules
    remove_iptables_rules

    if [[ -f "${INSTALL_DIR}/dnsttEx-server" ]]; then
        print_status "Removing dnsttEx-server binary..."
        rm -f "${INSTALL_DIR}/dnsttEx-server"
    fi
    if [[ -d "$CONFIG_DIR" ]]; then
        print_status "Removing config directory $CONFIG_DIR..."
        rm -rf "$CONFIG_DIR"
    fi
    if id "$DNSTT_USER" &>/dev/null; then
        print_status "Removing user $DNSTT_USER..."
        userdel "$DNSTT_USER" 2>/dev/null || true
    fi

    print_status "dnsttEx server uninstalled."
    print_question "Also remove this deploy script from $SCRIPT_INSTALL_PATH? [y/N]: "
    read -r rm_script
    if [[ "$rm_script" == "y" || "$rm_script" == "Y" ]]; then
        rm -f "$SCRIPT_INSTALL_PATH"
        print_status "Script removed. Goodbye!"
        exit 0
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS="$NAME"
    else
        print_error "Cannot detect OS"
    fi
    if command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
    elif command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
    else
        print_error "Unsupported package manager"
    fi
    print_status "Detected: $OS ($PKG_MANAGER)"
}

detect_arch() {
    local m
    m=$(uname -m)
    case "$m" in
        x86_64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv6l) ARCH="arm" ;;
        i386|i686) ARCH="386" ;;
        *) print_error "Unsupported architecture: $m" ;;
    esac
    [[ "$(uname -s)" == "Linux" ]] || print_error "Linux only"
    ASSET_SUFFIX="linux-${ARCH}"
    print_status "Architecture: $ARCH"
}

check_required_tools() {
    print_status "Checking required tools..."
    local missing=()
    for tool in curl iptables; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        print_status "Installing: ${missing[*]}"
        case "$PKG_MANAGER" in
            dnf|yum)
                $PKG_MANAGER install -y curl iptables iptables-services 2>/dev/null || $PKG_MANAGER install -y curl iptables
                ;;
            apt)
                apt-get update -qq && apt-get install -y curl iptables
                ;;
            *) print_error "Unsupported package manager"
        esac
    fi
    command -v iptables &>/dev/null || print_error "iptables not available"
}

get_user_input() {
    local existing_domain="" existing_mtu="" existing_mode=""
    if load_existing_config; then
        existing_domain="$NS_SUBDOMAIN"
        existing_mtu="$MTU_VALUE"
        existing_mode="$TUNNEL_MODE"
        print_status "Found existing config: $existing_domain"
    fi
    echo ""
    while true; do
        if [[ -n "$existing_domain" ]]; then
            print_question "Nameserver subdomain (current: $existing_domain): "
        else
            print_question "Nameserver subdomain (e.g. t.example.com): "
        fi
        read -r NS_SUBDOMAIN
        [[ -z "$NS_SUBDOMAIN" && -n "$existing_domain" ]] && NS_SUBDOMAIN="$existing_domain"
        [[ -n "$NS_SUBDOMAIN" ]] && break
        print_error "Subdomain is required"
    done
    print_question "MTU (current: ${existing_mtu:-1232}): "
    read -r MTU_VALUE
    MTU_VALUE="${MTU_VALUE:-$existing_mtu}"
    MTU_VALUE="${MTU_VALUE:-1232}"
    echo "Tunnel mode: 1) SOCKS proxy  2) SSH"
    while true; do
        if [[ -n "$existing_mode" ]]; then
            local n; [[ "$existing_mode" == "socks" ]] && n=1 || n=2
            print_question "Choice (current: $n - $existing_mode): "
        else
            print_question "Choice (1 or 2): "
        fi
        read -r choice
        if [[ -z "$choice" && -n "$existing_mode" ]]; then
            TUNNEL_MODE="$existing_mode"
            break
        fi
        case $choice in
            1) TUNNEL_MODE="socks"; break ;;
            2) TUNNEL_MODE="ssh"; break ;;
            *) print_error "Enter 1 or 2" ;;
        esac
    done
    print_status "Config: domain=$NS_SUBDOMAIN MTU=$MTU_VALUE mode=$TUNNEL_MODE"
}

download_server() {
    local bin_name="dnsttEx-server-${ASSET_SUFFIX}"
    local dest="${INSTALL_DIR}/dnsttEx-server"
    local tmp="/tmp/${bin_name}"
    local need_restart=false
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        need_restart=true
    fi

    print_status "Downloading dnsttEx-server from GitHub releases..."
    if ! curl -sSLf -o "$tmp" "${RELEASE_BASE}/${bin_name}"; then
        print_error "Download failed: ${RELEASE_BASE}/${bin_name}"
    fi
    chmod +x "$tmp"

    if [[ -f "$dest" ]]; then
        local current_checksum new_checksum
        current_checksum=$(sha256sum "$dest" | cut -d' ' -f1)
        new_checksum=$(sha256sum "$tmp" | cut -d' ' -f1)
        if [[ "$current_checksum" == "$new_checksum" ]]; then
            print_status "dnsttEx-server already up to date at $dest"
            rm -f "$tmp"
            return 0
        fi
        print_status "New version available. Updating binary..."
    else
        print_status "Installing dnsttEx-server..."
    fi

    mv "$tmp" "$dest"
    print_status "Installed $dest"

    if [[ "$need_restart" == true ]]; then
        print_status "Restarting $SERVICE_NAME to use new binary..."
        systemctl restart "$SERVICE_NAME"
    fi
}

create_user_and_dirs() {
    if ! id "$DNSTT_USER" &>/dev/null; then
        useradd -r -s /bin/false -d /nonexistent -c "dnsttEx service" "$DNSTT_USER"
        print_status "Created user $DNSTT_USER"
    else
        print_status "User $DNSTT_USER exists"
    fi
    mkdir -p "$CONFIG_DIR"
    chown -R "${DNSTT_USER}:${DNSTT_USER}" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
}

generate_keys() {
    local key_prefix
    key_prefix=$(echo "$NS_SUBDOMAIN" | tr '.' '_')
    PRIVATE_KEY_FILE="${CONFIG_DIR}/${key_prefix}_server.key"
    PUBLIC_KEY_FILE="${CONFIG_DIR}/${key_prefix}_server.pub"
    if [[ -f "$PRIVATE_KEY_FILE" && -f "$PUBLIC_KEY_FILE" ]]; then
        print_status "Using existing keys for $NS_SUBDOMAIN"
        chown "${DNSTT_USER}:${DNSTT_USER}" "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"
        chmod 600 "$PRIVATE_KEY_FILE"
        chmod 644 "$PUBLIC_KEY_FILE"
    else
        print_status "Generating keys..."
        "${INSTALL_DIR}/dnsttEx-server" -gen-key -privkey-file "$PRIVATE_KEY_FILE" -pubkey-file "$PUBLIC_KEY_FILE"
        chown "${DNSTT_USER}:${DNSTT_USER}" "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"
        chmod 600 "$PRIVATE_KEY_FILE"
        chmod 644 "$PUBLIC_KEY_FILE"
    fi
    print_status "Public key:"
    cat "$PUBLIC_KEY_FILE"
}

save_iptables_rules() {
    print_status "Saving iptables rules..."
    case $PKG_MANAGER in
        dnf|yum)
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null && print_status "Saved to /etc/sysconfig/iptables" || print_warning "Could not save iptables"
                if command -v ip6tables-save &>/dev/null && [[ -f /proc/net/if_inet6 ]]; then
                    ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
                fi
            fi
            ;;
        apt)
            if command -v iptables-save &>/dev/null; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null && print_status "Saved to /etc/iptables/rules.v4" || print_warning "Could not save iptables"
                if command -v ip6tables-save &>/dev/null && [[ -f /proc/net/if_inet6 ]]; then
                    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
                fi
            fi
            ;;
    esac
}

configure_iptables() {
    print_status "Configuring iptables (allow UDP port $DNSTT_PORT inbound)..."
    iptables -C INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT
    if command -v ip6tables &>/dev/null && [[ -f /proc/net/if_inet6 ]]; then
        ip6tables -C INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || \
            ip6tables -I INPUT -p udp --dport "$DNSTT_PORT" -j ACCEPT 2>/dev/null || true
    fi
    # Clean up legacy PREROUTING redirect rules from older installations
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    iface="${iface:-eth0}"
    while iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null; do
        iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports 5300
        print_status "Removed legacy iptables PREROUTING redirect (53→5300)"
    done
    save_iptables_rules
}

configure_firewall() {
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_status "Configuring firewalld..."
        firewall-cmd --permanent --add-port="${DNSTT_PORT}/udp" 2>/dev/null
        firewall-cmd --permanent --add-port=53/udp 2>/dev/null
        firewall-cmd --reload 2>/dev/null
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        print_status "Configuring ufw..."
        ufw allow "${DNSTT_PORT}/udp" 2>/dev/null
        ufw allow 53/udp 2>/dev/null
    fi
    configure_iptables
}

detect_ssh_port() {
    local port
    port=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1)
    echo "${port:-22}"
}

setup_dante() {
    print_status "Setting up Dante SOCKS proxy..."
    case $PKG_MANAGER in
        dnf|yum) $PKG_MANAGER install -y dante-server ;;
        apt)     apt-get install -y dante-server ;;
        *)       print_error "Cannot install dante-server"
    esac
    local ext_iface
    ext_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    ext_iface="${ext_iface:-eth0}"
    cat > /etc/danted.conf << 'DANTE_EOF'
logoutput: syslog
user.privileged: root
user.unprivileged: nobody
internal: 127.0.0.1 port = 1080
external: EXT_IFACE
socksmethod: none
client pass { from: 127.0.0.0/8 to: 0.0.0.0/0 }
socks pass { from: 127.0.0.0/8 to: 0.0.0.0/0 command: bind connect udpassociate }
DANTE_EOF
    sed -i "s/EXT_IFACE/$ext_iface/" /etc/danted.conf
    systemctl enable danted 2>/dev/null
    systemctl restart danted 2>/dev/null
    print_status "Dante SOCKS listening on 127.0.0.1:1080"
}

free_port_53() {
    # systemd-resolved's stub listener can occupy 127.0.0.53:53 or 127.0.0.1:53.
    # The main listener on 0.0.0.0:53 / :::53 is what blocks us.
    # Disable the stub listener so dnstt-server can bind to :53.
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        local stub_status
        stub_status=$(resolvectl status 2>/dev/null | grep -i "DNSStubListener" || true)
        # Check if anything is actually bound to *:53 or 0.0.0.0:53
        if ss -ulnp 2>/dev/null | grep -qE '(0\.0\.0\.0|:::|\*):53 '; then
            print_status "Disabling systemd-resolved stub listener to free port 53..."
            mkdir -p /etc/systemd/resolved.conf.d
            cat > /etc/systemd/resolved.conf.d/no-stub.conf << 'STUBEOF'
[Resolve]
DNSStubListener=no
STUBEOF
            systemctl restart systemd-resolved
            # Point /etc/resolv.conf to a real upstream so the server can still resolve DNS
            if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q stub-resolv; then
                print_status "Updating /etc/resolv.conf to use upstream DNS..."
                rm -f /etc/resolv.conf
                echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
            fi
        fi
    fi
    # Stop bind9/named if running on port 53
    for svc_name in named bind9; do
        if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
            if ss -ulnp 2>/dev/null | grep -E '(0\.0\.0\.0|:::|\*):53 ' | grep -q "$svc_name"; then
                print_status "Stopping $svc_name which is using port 53..."
                systemctl stop "$svc_name"
                systemctl disable "$svc_name"
            fi
        fi
    done
}

create_systemd_service() {
    local target_port
    if [[ "$TUNNEL_MODE" == "ssh" ]]; then
        target_port=$(detect_ssh_port)
        print_status "SSH mode: forwarding to 127.0.0.1:$target_port"
    else
        target_port="1080"
        print_status "SOCKS mode: forwarding to 127.0.0.1:1080"
    fi
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_status "Stopping $SERVICE_NAME for reconfiguration..."
        systemctl stop "$SERVICE_NAME"
    fi
    free_port_53
    local svc="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    print_status "Creating systemd service..."
    cat > "$svc" << EOF
[Unit]
Description=dnsttEx DNS Tunnel Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$DNSTT_USER
Group=$DNSTT_USER
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=${INSTALL_DIR}/dnsttEx-server -udp :${DNSTT_PORT} -privkey-file ${PRIVATE_KEY_FILE} -mtu ${MTU_VALUE} ${NS_SUBDOMAIN} 127.0.0.1:${target_port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    # Verify the service is actually listening on port 53
    sleep 1
    if ss -ulnp 2>/dev/null | grep -qE ":${DNSTT_PORT}\b"; then
        print_status "$SERVICE_NAME is listening on UDP port $DNSTT_PORT"
    else
        print_warning "$SERVICE_NAME may not be listening on port $DNSTT_PORT — check: journalctl -u $SERVICE_NAME"
    fi
}

print_success_box() {
    echo ""
    echo -e "${GREEN}+============================================================================+${NC}"
    echo -e "${GREEN}|                    dnsttEx server setup complete                          |${NC}"
    echo -e "${GREEN}+============================================================================+${NC}"
    echo ""
    echo -e "  Subdomain:  ${YELLOW}$NS_SUBDOMAIN${NC}"
    echo -e "  MTU:        ${YELLOW}$MTU_VALUE${NC}"
    echo -e "  Tunnel:     ${YELLOW}$TUNNEL_MODE${NC}"
    echo -e "  Public key: ${YELLOW}$(cat "$PUBLIC_KEY_FILE")${NC}"
    echo ""
    echo "  Commands:  dnsttEx-deploy  |  systemctl status $SERVICE_NAME  |  journalctl -u $SERVICE_NAME -f"
    if [[ "$TUNNEL_MODE" == "socks" ]]; then
        echo ""
        echo "  SOCKS proxy: 127.0.0.1:1080  (systemctl status danted)"
    fi
    echo ""
    echo -e "${GREEN}+============================================================================+${NC}"
    echo ""
}

main() {
    if [[ "$0" != "$SCRIPT_INSTALL_PATH" ]] && [[ "$0" != *"dnsttEx-deploy"* ]]; then
        install_script
        exec "$SCRIPT_INSTALL_PATH" "$@"
    fi
    check_for_updates
    handle_menu
    detect_os
    detect_arch
    check_required_tools
    get_user_input
    download_server
    create_user_and_dirs
    generate_keys
    save_config
    configure_firewall
    if [[ "$TUNNEL_MODE" == "socks" ]]; then
        setup_dante
    else
        if systemctl is-active --quiet danted 2>/dev/null; then
            systemctl stop danted 2>/dev/null
            systemctl disable danted 2>/dev/null
        fi
    fi
    create_systemd_service
    print_success_box
}

main "$@"
