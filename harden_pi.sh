#!/usr/bin/env bash

# vibed by Gemini Pro 3.0
# Hardening Script v2.4 (Raspberry Pi Flex Edition + Fixes)
# Optimized for Debian/Ubuntu/Raspberry Pi OS
set -eo pipefail

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Log Functions ---
log_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; }

# --- Global Variables ---
SSH_PORT=""
SSH_KEY_PATH=""
SKIP_KEY_IMPORT="false"
SUDO_USER_NAME=""
USER_HOME_DIR=""

REQUIRED_PKGS=(ufw fail2ban clamav clamav-daemon chkrootkit rkhunter openssh-server)

# --- 0. The Flex Module ---

check_hardware() {
    # Check if running on a Raspberry Pi via Device Tree
    if grep -q "Raspberry Pi" /sys/firmware/devicetree/base/model 2>/dev/null; then
        MODEL=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
        # Get RAM in GB
        RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        RAM_GB=$((RAM_KB / 1024 / 1024))
        
        clear
        echo -e "${PURPLE}${BOLD}"
        echo "   _  __     __                    __   "
        echo "  | |/ /__  / /____ _______  ___  / /   "
        echo "  |   / _ \/ __/ _ \_  / _ \/ _ \/ /    "
        echo " /   /  __/ /_/  __/ //  __/  __/ /___  "
        echo "/_/|_\___/\__/\___//__\___/\___/_____/  "
        echo -e "${NC}"
        echo -e "${CYAN}>>> HARDWARE DETECTED: ${MODEL}${NC}"
        echo -e "${CYAN}>>> MEMORY CAPACITY:   ${RAM_GB}GB (Absolute Unit)${NC}"
        echo -e "${GREEN}>>> STATUS:            Ready to Harden${NC}"
        echo ""
        sleep 2
    else
        log_info "Standard Linux Host Detected."
    fi
}

# --- 1. System Checks ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./harden_pi.sh'"
        exit 1
    fi
    
    SUDO_USER_NAME="${SUDO_USER:-$(who am i | awk '{print $1}')}"
    if [[ -z "$SUDO_USER_NAME" || "$SUDO_USER_NAME" == "root" ]]; then
        log_warn "Could not determine sudo user. Assuming current user is the target."
        read -p "Enter the username to harden (e.g. pi): " SUDO_USER_NAME
    fi
    
    USER_HOME_DIR=$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)
    log_info "Target User: $SUDO_USER_NAME (Home: $USER_HOME_DIR)"
}

ensure_dependencies() {
    log_info "--- Phase 1: Dependency Verification ---"
    log_info "Updating package lists..."
    apt-get update -y > /dev/null

    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            log_warn "Package '$pkg' is missing. Installing..."
            apt-get install -y "$pkg"
        else
            log_success "Package '$pkg' is already installed."
        fi
    done
}

# --- 2. User Inputs ---

get_user_inputs() {
    log_info "--- Phase 2: User Configuration ---"
    
    # Get SSH Port
    while true; do
        read -p "Enter a custom SSH port (1025-65535): " SSH_PORT
        if [[ "$SSH_PORT" -gt 1024 && "$SSH_PORT" -lt 65535 ]]; then
            break
        else
            log_error "Invalid port. Must be between 1025 and 65535."
        fi
    done
    
    # OPTIONAL SSH Key Import (Fixed logic)
    echo ""
    log_warn "If you have already manually set up your authorized_keys, you can skip this step."
    read -p "Do you want to import a public key file now? (y/n): " IMPORT_CHOICE
    
    if [[ "$IMPORT_CHOICE" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter path to public SSH key (e.g., /home/$SUDO_USER_NAME/id.pub): " INPUT_PATH
            SSH_KEY_PATH="${INPUT_PATH/#\~/$USER_HOME_DIR}"

            if [[ -f "$SSH_KEY_PATH" ]]; then
                break
            else
                log_error "File not found at: $SSH_KEY_PATH"
            fi
        done
    else
        SKIP_KEY_IMPORT="true"
        log_info "Skipping SSH key import (preserving existing authorized_keys)."
    fi
}

# --- 3. Hardening Functions ---

setup_linger() {
    log_info "Enabling linger for $SUDO_USER_NAME..."
    loginctl enable-linger "$SUDO_USER_NAME"
}

setup_firewall() {
    log_info "Configuring UFW..."
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw deny 22/tcp
    ufw allow "$SSH_PORT/tcp"
    
    # FIX: Use --force instead of piping 'yes' to avoid crash
    ufw --force enable
    
    log_success "Firewall active. Port $SSH_PORT allowed."
}

secure_ssh() {
    log_info "Hardening SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    
    set_ssh_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^\s*#?\s*$param" "$ssh_config"; then
            sed -i "s/^\s*#\?\s*$param.*/$param $value/" "$ssh_config"
        else
            echo "$param $value" >> "$ssh_config"
        fi
    }

    set_ssh_param "Port" "$SSH_PORT"
    set_ssh_param "PermitRootLogin" "no"
    set_ssh_param "PasswordAuthentication" "no"
    set_ssh_param "KbdInteractiveAuthentication" "no"
    set_ssh_param "PubkeyAuthentication" "yes"
    
    local ssh_dir="$USER_HOME_DIR/.ssh"
    local auth_key_file="$ssh_dir/authorized_keys"
    
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    
    # Only import if user requested
    if [[ "$SKIP_KEY_IMPORT" == "false" ]]; then
        cat "$SSH_KEY_PATH" >> "$auth_key_file"
        log_success "Key imported."
    fi
    
    # Ensure permissions are correct
    if [[ -f "$auth_key_file" ]]; then
        chmod 600 "$auth_key_file"
    fi
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$ssh_dir"
    
    systemctl restart ssh
    log_success "SSH hardened."
}

setup_clamav() {
    log_info "Configuring ClamAV (16GB RAM detected? Running Full Suite)..."
    systemctl enable --now clamav-freshclam.service
    
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=Run ClamAV scan on home directory
[Service]
Type=oneshot
ExecStart=/usr/bin/clamscan -r --infected %h
EOL

    tee "$user_service_dir/clamscan-home.timer" > /dev/null << EOL
[Unit]
Description=Run daily ClamAV scan
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL

    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$user_service_dir"

    sudo -u "$SUDO_USER_NAME" systemctl --user daemon-reload
    sudo -u "$SUDO_USER_NAME" systemctl --user enable --now clamscan-home.timer
    log_success "ClamAV user timer enabled."
}

setup_chkrootkit() {
    log_info "Scheduling chkrootkit..."
    tee "/etc/systemd/system/chkrootkit.service" > /dev/null << EOL
[Unit]
Description=Run chkrootkit scan
[Service]
Type=oneshot
ExecStart=/usr/sbin/chkrootkit
SuccessExitStatus=1
EOL
    tee "/etc/systemd/system/chkrootkit.timer" > /dev/null << EOL
[Unit]
Description=Run daily chkrootkit scan
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL
    systemctl daemon-reload
    systemctl enable --now chkrootkit.timer
    log_success "chkrootkit scheduled."
}

setup_rkhunter() {
    log_info "Configuring rkhunter..."
    local conf="/etc/rkhunter.conf"
    local default="/etc/default/rkhunter"
    
    # FIX: Comment out disable flag
    sed -i 's/^DISABLE_WEB_CMD=.*/#&/' "$conf"
    # FIX: Remove quotes for wget command
    sed -i "s|^WEB_CMD=.*|WEB_CMD=/usr/bin/wget|" "$conf"

    sed -i "s/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/" "$conf"
    sed -i "s/^MIRRORS_MODE=.*/MIRRORS_MODE=0/" "$conf"
    
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' "$default"
    sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' "$default"

    log_info "Updating rkhunter signatures..."
    rkhunter --update > /dev/null || log_warn "rkhunter update failed (check network)"
    rkhunter --propupd > /dev/null || log_warn "rkhunter propupd failed"
    log_success "rkhunter configured."
}

setup_fail2ban() {
    log_info "Configuring fail2ban..."
    local jail_local="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_local" ]]; then cp /etc/fail2ban/jail.conf "$jail_local"; fi
    
    sed -i "/^\[sshd\]/,/^\[/ s/enabled = .*/enabled = true/" "$jail_local"
    sed -i "/^\[sshd\]/,/^\[/ s/port .*=.*/port = $SSH_PORT/" "$jail_local"
    
    systemctl restart fail2ban
    log_success "fail2ban active on port $SSH_PORT."
}

setup_kernel_hardening() {
    log_info "Applying kernel hardening..."
    local sysctl_conf="/etc/sysctl.d/99-hardening.conf"
    
    tee "$sysctl_conf" > /dev/null << EOL
# --- Kernel Hardening ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.core.bpf_jit_harden = 2
# --- TCP/IP Stack Hardening ---
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOL
    sysctl -p "$sysctl_conf"
    log_success "Kernel parameters applied."
}

# --- Main Execution ---

main() {
    check_root
    check_hardware
    ensure_dependencies
    get_user_inputs
    
    log_info "--- Starting Configuration ---"
    setup_linger
    setup_firewall
    secure_ssh
    setup_clamav
    setup_chkrootkit
    setup_rkhunter
    setup_fail2ban
    setup_kernel_hardening
    
    log_info "-------------------------------------"
    log_success "Hardening Complete. PLEASE REBOOT."
    log_warn "REMINDER: Set up 2FA manually using 'google-authenticator' after reboot."
    log_info "-------------------------------------"
}

main