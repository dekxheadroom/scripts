#!/usr/bin/env bash

# This script is vibed by Gemini Pro 3.0; 
# prompted for re-design to validate environment first before asking for user inputs
# Hardening Script v2.0
# Logic: Check Root -> Install Dependencies -> Get User Input -> Apply Hardening
set -eo pipefail

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Log Functions ---
log_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; }

# --- Global Variables ---
SSH_PORT=""
SSH_KEY_PATH=""
SUDO_USER_NAME=""
USER_HOME_DIR=""

# List of required packages
REQUIRED_PKGS=(ufw fail2ban clamav clamav-daemon chkrootkit rkhunter openssh-server)

# --- 1. System Checks & Dependency Management ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./harden.sh'"
        exit 1
    fi
    
    # Get the real user who invoked sudo
    SUDO_USER_NAME="${SUDO_USER:-$(who am i | awk '{print $1}')}"
    if [[ -z "$SUDO_USER_NAME" || "$SUDO_USER_NAME" == "root" ]]; then
        log_error "Run this with 'sudo' from a regular user account, not directly as root."
        exit 1
    fi
    
    USER_HOME_DIR=$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)
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
    log_success "All dependencies are in place."
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
    
    # Get SSH Public Key
    while true; do
        read -p "Enter path to admin's public SSH key (e.g., $USER_HOME_DIR/.ssh/id_rsa.pub): " SSH_KEY_PATH
        if [[ -f "$SSH_KEY_PATH" ]]; then
            break
        else
            log_error "File not found at: $SSH_KEY_PATH"
        fi
    done
}

# --- 3. Hardening Functions ---

setup_linger() {
    log_info "Enabling linger for $SUDO_USER_NAME..."
    loginctl enable-linger "$SUDO_USER_NAME"
}

setup_firewall() {
    if ! command -v ufw &> /dev/null; then log_error "UFW not found. Skipping."; return; fi

    log_info "Configuring UFW..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # Deny standard SSH, Allow Custom SSH
    ufw deny 22/tcp
    ufw allow "$SSH_PORT/tcp"
    
    yes | ufw enable
    log_success "Firewall active. Port $SSH_PORT allowed."
}

secure_ssh() {
    log_info "Hardening SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    
    # Helper function to set config robustly
    set_ssh_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^#?$param" "$ssh_config"; then
            sed -i "s/^#?$param .*/$param $value/" "$ssh_config"
        else
            echo "$param $value" >> "$ssh_config"
        fi
    }

    set_ssh_param "Port" "$SSH_PORT"
    set_ssh_param "PermitRootLogin" "no"
    set_ssh_param "PasswordAuthentication" "no"
    set_ssh_param "KbdInteractiveAuthentication" "no"
    
    # Setup Authorized Keys
    local auth_key_file="$USER_HOME_DIR/.ssh/authorized_keys"
    mkdir -p "$USER_HOME_DIR/.ssh"
    chmod 700 "$USER_HOME_DIR/.ssh"
    cat "$SSH_KEY_PATH" >> "$auth_key_file"
    chmod 600 "$auth_key_file"
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$USER_HOME_DIR/.ssh"
    
    systemctl restart ssh
    log_success "SSH hardened."
}

setup_clamav() {
    if ! command -v clamscan &> /dev/null; then log_error "ClamAV not found. Skipping."; return; fi

    log_info "Configuring ClamAV..."
    systemctl enable --now clamav-freshclam.service
    
    # Create User Service
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    # Using 'tee' without sudo because we are root
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=Run ClamAV scan on home directory
[Service]
Type=oneshot
ExecStart=/usr/bin/clamscan -r --infected --log=%h/clamscan_report.log %h
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

    # Execute systemctl as the user
    sudo -u "$SUDO_USER_NAME" systemctl --user daemon-reload
    sudo -u "$SUDO_USER_NAME" systemctl --user enable --now clamscan-home.timer
    log_success "ClamAV user timer enabled."
}

setup_chkrootkit() {
    if ! command -v chkrootkit &> /dev/null; then log_error "chkrootkit not found. Skipping."; return; fi
    
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
    if ! command -v rkhunter &> /dev/null; then log_error "rkhunter not found. Skipping."; return; fi
    
    log_info "Configuring rkhunter..."
    local conf="/etc/rkhunter.conf"
    local default="/etc/default/rkhunter"
    
    sed -i "s|^WEB_CMD=.*|WEB_CMD=\"/usr/bin/wget\"|" "$conf"
    sed -i "s/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/" "$conf"
    sed -i "s/^MIRRORS_MODE=.*/MIRRORS_MODE=0/" "$conf"
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' "$default"
    sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' "$default"

    rkhunter --update > /dev/null
    rkhunter --propupd > /dev/null
    log_success "rkhunter baseline created."
}

setup_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then log_error "fail2ban not found. Skipping."; return; fi

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
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOL
    sysctl -p "$sysctl_conf"
    log_success "Kernel parameters applied."
}

# --- Main Execution ---

main() {
    clear
    log_info "=== Linux Host Hardening v2.0 ==="
    
    check_root
    
    # 1. Ensure tools are present BEFORE asking questions
    ensure_dependencies
    
    # 2. Now safe to ask questions
    get_user_inputs
    
    log_info "--- Starting Configuration ---"
    
    # 3. Apply Hardening
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
}

main