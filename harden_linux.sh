#!/usr/bin/env bash

# vibed by Gemini 3 Pro
# Hardening Script v3.2
# Changelog:
# v3.4.2: removed conditional statement for notify-send. alert will be sent if XARG process any errors. XARG does not pass on clamav's positive detection
# v3.4.1: corrected bug in setup_clamAV() - removed `%h` after `--infected`
# v3.4: Optimised setup_clamAV() for clamscan daemon to scan files only
# v3.3: Modified setup_clamAV() to run `clamdscan` instead of `clamscan` 
# v3.2: Added ClamAV Desktop Notifications (libnotify/mako) & Dependencies
# v3.1: Added Enhanced SSH hardening (Strict Ciphers, X11 Block, Banners, Timeouts)
# v3.0: Added VM Isolation Module
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
SKIP_KEY_IMPORT="false"
ISOLATE_VM="false"
VM_SUBNET=""
SUDO_USER_NAME=""
USER_HOME_DIR=""

# Added libnotify-bin (notify-send) and mako-notifier (for Wayland/Sway) for alerts
REQUIRED_PKGS=(ufw fail2ban clamav clamav-daemon chkrootkit rkhunter openssh-server libnotify-bin mako-notifier)

# --- 1. System Checks ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./harden_linux.sh'"
        exit 1
    fi
    
    SUDO_USER_NAME="${SUDO_USER:-$(who am i | awk '{print $1}')}"
    if [[ -z "$SUDO_USER_NAME" || "$SUDO_USER_NAME" == "root" ]]; then
        log_warn "Could not determine sudo user. Assuming current user is the target."
        read -p "Enter the username to harden (e.g. ubuntu): " SUDO_USER_NAME
    fi
    
    USER_HOME_DIR=$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)
    log_info "Target User: $SUDO_USER_NAME (Home: $USER_HOME_DIR)"
}

ensure_dependencies() {
    log_info "--- Phase 1: Dependency Verification ---"
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
    
    # SSH Key Import
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
        log_info "Skipping SSH key import."
    fi

    # VM ISOLATION
    echo ""
    log_warn "Virtual Machine Isolation Check: Do you need to isolate Guest VMs from this Host?"
    read -p "Configure VM Isolation Rule? (y/n): " ISO_CHOICE
    
    if [[ "$ISO_CHOICE" =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter the VM Subnet (CIDR format, e.g., 192.168.146.0/24): " VM_SUBNET
            if [[ "$VM_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                ISOLATE_VM="true"
                break
            else
                log_error "Invalid format. Please use CIDR (e.g., 192.168.146.0/24)"
            fi
        done
    else
        ISOLATE_VM="false"
        log_info "Skipping VM isolation."
    fi
}

# --- 3. Hardening Functions ---

setup_linger() {
    log_info "Enabling linger for $SUDO_USER_NAME..."
    loginctl enable-linger "$SUDO_USER_NAME"
}

setup_firewall() {
    log_info "Configuring UFW..."
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    
    # Basic SSH Rules
    ufw deny 22/tcp
    ufw allow "$SSH_PORT/tcp"
    
    # VM Isolation (One-Way Mirror)
    if [[ "$ISOLATE_VM" == "true" ]]; then
        log_info "Applying One-Way Mirror isolation for subnet: $VM_SUBNET"
        ufw insert 1 deny from "$VM_SUBNET" to any
    fi
    
    ufw --force enable
    log_success "Firewall active. Port $SSH_PORT allowed."
}

secure_ssh() {
    log_info "Hardening SSH configuration (Hunter Class)..."
    local ssh_config="/etc/ssh/sshd_config"
    
    setup_banner
    
    # Helper to safely set config
    set_ssh_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^\s*#?\s*$param" "$ssh_config"; then
            sed -i "s|^\s*#\?\s*$param.*|$param $value|" "$ssh_config"
        else
            echo "$param $value" >> "$ssh_config"
        fi
    }

    # 1. Basics & Port
    set_ssh_param "Port" "$SSH_PORT"
    set_ssh_param "Protocol" "2"
    set_ssh_param "Banner" "/etc/issue.net"

    # 2. Authentication Lockdown
    set_ssh_param "PermitRootLogin" "no"
    set_ssh_param "PasswordAuthentication" "no"
    set_ssh_param "PermitEmptyPasswords" "no"
    set_ssh_param "KbdInteractiveAuthentication" "no"
    set_ssh_param "KerberosAuthentication" "no"
    set_ssh_param "GSSAPIAuthentication" "no"
    set_ssh_param "PubkeyAuthentication" "yes"

    # 3. Surface Area Reduction
    set_ssh_param "X11Forwarding" "no"
    set_ssh_param "AllowAgentForwarding" "no"
    set_ssh_param "AllowTcpForwarding" "no"
    set_ssh_param "PrintLastLog" "yes"

    # 4. Anti-Brute Force / Timeouts
    set_ssh_param "ClientAliveInterval" "300"
    set_ssh_param "ClientAliveCountMax" "0"
    set_ssh_param "MaxAuthTries" "3"
    set_ssh_param "MaxSessions" "2"
    set_ssh_param "LoginGraceTime" "30"

    # 5. Crypto-Shield (Explicit Ciphers)
    # Removing old entries first to ensure no conflicts
    sed -i '/^Ciphers/d' "$ssh_config"
    sed -i '/^KexAlgorithms/d' "$ssh_config"
    sed -i '/^MACs/d' "$ssh_config"

    echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> "$ssh_config"
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$ssh_config"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> "$ssh_config"

    # Authorized Keys Setup
    local ssh_dir="$USER_HOME_DIR/.ssh"
    local auth_key_file="$ssh_dir/authorized_keys"
    
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    
    if [[ "$SKIP_KEY_IMPORT" == "false" ]]; then
        cat "$SSH_KEY_PATH" >> "$auth_key_file"
        log_success "Key imported."
    fi
    
    if [[ -f "$auth_key_file" ]]; then
        chmod 600 "$auth_key_file"
    fi
    
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$ssh_dir"
    
    # Syntax Check
    if sshd -t; then
        systemctl restart ssh
        log_success "SSH hardened and restarted."
    else
        log_error "SSH Config syntax error! Reverting changes might be necessary."
        exit 1
    fi
}

setup_banner() {
    log_info "Setting up Legal Banner..."
    echo "AUTHORIZED ACCESS ONLY. ALL ACTIVITIES MONITORED." > /etc/issue.net
}

setup_clamav() {
    log_info "Configuring ClamAV daemon & Alerts..."
    #Ensure daemon is running for clamdscan
    systemctl enable --now clamav-daemon.service
    systemctl enable --now clamav-freshclam.service

    #wait for db to load
    log_info "Waiting 15sec for ClamAV daemon to initialise..."
    sleep 15
    
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    # optimised to scan only file types 
    # 1. 'find' gets all regular files (skips sockets/pipes).
    # 2. 'xargs' feeds them to clamdscan in batches (efficient).
    # 3. '||' catches exit code 1 (Virus Found) to trigger the alert.
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=Run ClamAV daemon scan on home directory

[Service]
#Logic: find files only. run scan. if exit code is 1 (virus found), trigger notification
Type=oneshot
ExecStart=/bin/bash -c 'find %h -type f -print0 | xargs -0 -r /usr/bin/clamdscan --fdpass --multiscan --infected || notify-send "SECURITY ALERT" "Malware detected in %h" --urgency=critical --icon=security-high'

[Install]
WantedBy=default.target
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
    log_success "ClamAV (daemon mode) user timer enabled with Desktop Notifications."
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
    
    sed -i 's/^DISABLE_WEB_CMD=.*/#&/' "$conf"
    sed -i "s|^WEB_CMD=.*|WEB_CMD=/usr/bin/wget|" "$conf"
    sed -i "s/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/" "$conf"
    sed -i "s/^MIRRORS_MODE=.*/MIRRORS_MODE=0/" "$conf"
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' "$default"
    sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' "$default"

    log_info "Updating rkhunter signatures..."
    rkhunter --update > /dev/null || log_warn "rkhunter update failed (check network later)"
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
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.core.bpf_jit_harden = 2
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
    log_info "=== Linux Host Hardening v3.2 ==="
    
    check_root
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
}

main