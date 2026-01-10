#!/usr/bin/env bash

# vibed by Gemini Pro 3.0
# Hardening Script v3.5 (RAVAGE Edition)
# Changelog:
# v3.5: Removed swaylock and swayidle because of conflict with 2FA login
# v3.4: Removed deprecated 'Protocol 2' SSH directive; Fixed DBUS session logic for Wayland/LabWC notifications; Hardened Sudoers regex to prevent mangling on re-runs; Added wlopm to dependencies for display power management
# v3.3.2: removed conditional statement for notify-send. alert will be sent if XARG process any errors. XARG does not pass on clamav's positive detection
# v3.3.1: corrected bug in setup_clamAV() - removed `%h` after `--infected`
# v3.3 Optimised setup_clamAV() for clamscan daemon to scan files only
# v3.2: Modified setup_clamAV() to run `clamdscan` instead of `clamscan`, Added Desktop Notifications (libnotify/mako) & Dependencies 
# v3.1: Integrated Enhanced Hardening (Strict Ciphers, No X11, Timeouts)
# v3.0: Optimized for Raspberry Pi OS (Bookworm/Wayland)

set -eo pipefail

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

# Removed swayidle and swaylock. Kept wlopm for power management
REQUIRED_PKGS=(ufw fail2ban clamav clamav-daemon chkrootkit rkhunter openssh-server libnotify-bin mako-notifier wlopm)

# --- 0. The Flex Module ---
check_hardware() {
    if grep -q "Raspberry Pi" /sys/firmware/devicetree/base/model 2>/dev/null; then
        MODEL=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
        RAM_KB=$(grep MemTotal /proc/proc/meminfo | awk '{print $2}' 2>/dev/null || echo 0)
        RAM_GB=$((RAM_KB / 1024 / 1024))
        
        clear
        echo -e "${BOLD}"
        echo -e "${GREEN}    .~~.   .~~.  ${NC}"
        echo -e "${GREEN}  '. \ ' ' / .' ${NC}"
        echo -e "${RED}    .~ .~~~..~.  ${NC}"
        echo -e "${RED}  : .~.'~'.~. : ${NC}"
        echo -e "${RED} ~ (   ) (   ) ~${NC}"
        echo -e "${RED}( : '~'.~.'~' : )${NC}"
        echo -e "${RED} ~ .~ (   ) ~. ~${NC}"
        echo -e "${RED}  (  : '~' :  ) ${NC}"
        echo -e "${RED}    '~ .~~~. ~'  ${NC}"
        echo -e "${RED}        '~'      ${NC}"
        echo -e "${NC}"
        echo -e "${CYAN}>>> HARDWARE DETECTED: ${MODEL}${NC}"
        echo -e "${CYAN}>>> MEMORY CAPACITY:   ${RAM_GB}GB (Absolute Unit)${NC}"
        echo -e "${GREEN}>>> STATUS:             Ready to Harden${NC}"
        echo ""
        sleep 2
    fi
}

# --- 1. System Checks ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./harden_pi.sh'"
        exit 1
    fi
    SUDO_USER_NAME="${SUDO_USER:-$(who am i | awk '{print $1}')}"
    USER_HOME_DIR=$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)
}

ensure_dependencies() {
    log_info "--- Phase 1: Dependency Verification ---"
    apt-get update -y > /dev/null
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! dpkg -s "$pkg" &> /dev/null; then
            apt-get install -y "$pkg"
        else
            log_success "Package '$pkg' verified."
        fi
    done
}

# --- 2. User Inputs ---
get_user_inputs() {
    log_info "--- Phase 2: User Configuration ---"
    while true; do
        read -p "Enter a custom SSH port (1025-65535): " SSH_PORT
        if [[ "$SSH_PORT" -gt 1024 && "$SSH_PORT" -lt 65535 ]]; then break;
        else log_error "Invalid port range."; fi
    done
    read -p "Import public key file? (y/n): " IMPORT_CHOICE
    if [[ "$IMPORT_CHOICE" =~ ^[Yy]$ ]]; then
        read -p "Enter path to public SSH key: " INPUT_PATH
        SSH_KEY_PATH="${INPUT_PATH/#\~/$USER_HOME_DIR}"
    else
        SKIP_KEY_IMPORT="true"
    fi
}

# --- 3. Hardening Functions ---
setup_linger() {
    loginctl enable-linger "$SUDO_USER_NAME"
}

setup_firewall() {
    log_info "Configuring UFW..."
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw deny 22/tcp
    ufw allow "$SSH_PORT/tcp"
    ufw --force enable
}

secure_ssh() {
    log_info "Hardening SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    set_ssh_param() {
        local param="$1"
        local value="$2"
        if grep -qE "^\s*#?\s*$param" "$ssh_config"; then
            sed -i "s|^\s*#\?\s*$param.*|$param $value|" "$ssh_config"
        else
            echo "$param $value" >> "$ssh_config"
        fi
    }
    set_ssh_param "Port" "$SSH_PORT"
    set_ssh_param "PermitRootLogin" "no"
    set_ssh_param "PasswordAuthentication" "no"
    set_ssh_param "X11Forwarding" "no"
    
    sed -i '/^Ciphers/d' "$ssh_config"
    sed -i '/^KexAlgorithms/d' "$ssh_config"
    sed -i '/^MACs/d' "$ssh_config"

    echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> "$ssh_config"
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> "$ssh_config"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> "$ssh_config"
    
    local ssh_dir="$USER_HOME_DIR/.ssh"
    local auth_key_file="$ssh_dir/authorized_keys"
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    if [[ "$SKIP_KEY_IMPORT" == "false" ]]; then
        cat "$SSH_KEY_PATH" >> "$auth_key_file"
    fi
    if [[ -f "$auth_key_file" ]]; then chmod 600 "$auth_key_file"; fi
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$ssh_dir"
    systemctl restart ssh
}

configure_sudo_password() {
    local sudoers_file="/etc/sudoers.d/010_pi-nopasswd"
    if [[ -f "$sudoers_file" ]]; then
        sed -i 's/NOPASSWD[:[:space:]]*//g' "$sudoers_file"
    fi
}

configure_display_wayland() {
    log_info "Configuring Wayland (LabWC) Boot and Display Power..."
    if command -v raspi-config >/dev/null; then raspi-config nonint do_boot_behaviour B3; fi
    
    local labwc_config_dir="$USER_HOME_DIR/.config/labwc"
    local autostart_file="$labwc_config_dir/autostart"
    mkdir -p "$labwc_config_dir"
    touch "$autostart_file"
    
    # Lockscreen removed. Only power management remains
    if ! grep -q "wlopm" "$autostart_file"; then
        echo -e "\n# Display Power Management (Off after 600s)" >> "$autostart_file"
        echo "wlopm --set-timeout 600 &" >> "$autostart_file"
        log_success "Display power management configured."
    fi
}

setup_clamav() {
    log_info "Setting up ClamAV..."
    systemctl enable --now clamav-daemon.service > /dev/null
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=ClamAV scan on home directory
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'find %h -type f -print0 | xargs -0 -r /usr/bin/clamdscan --fdpass --infected || { export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus; /usr/bin/notify-send "SECURITY ALERT" "Malware detected in %h" --urgency=critical; }'
EOL

    tee "$user_service_dir/clamscan-home.timer" > /dev/null << EOL
[Unit]
Description=Daily ClamAV timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$user_service_dir"
    sudo -u "$SUDO_USER_NAME" systemctl --user daemon-reload
    sudo -u "$SUDO_USER_NAME" systemctl --user enable --now clamscan-home.timer
}

setup_chkrootkit() {
    tee "/etc/systemd/system/chkrootkit.timer" > /dev/null << EOL
[Unit]
Description=Daily chkrootkit timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL
    systemctl enable --now chkrootkit.timer
}

setup_rkhunter() {
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
    rkhunter --update > /dev/null || true
    rkhunter --propupd > /dev/null || true
}

setup_fail2ban() {
    local jail_local="/etc/fail2ban/jail.local"
    cp /etc/fail2ban/jail.conf "$jail_local"
    sed -i "/^\[sshd\]/,/^\[/ s/enabled = .*/enabled = true/" "$jail_local"
    sed -i "/^\[sshd\]/,/^\[/ s/port .*=.*/port = $SSH_PORT/" "$jail_local"
    systemctl restart fail2ban
}

setup_kernel_hardening() {
    local sysctl_conf="/etc/sysctl.d/99-hardening.conf"
    tee "$sysctl_conf" > /dev/null << EOL
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
EOL
    sysctl -p "$sysctl_conf" > /dev/null
}

main() {
    check_root
    check_hardware
    ensure_dependencies
    get_user_inputs
    setup_linger
    setup_firewall
    secure_ssh
    configure_sudo_password
    configure_display_wayland
    setup_clamav
    setup_chkrootkit
    setup_rkhunter
    setup_fail2ban
    setup_kernel_hardening
    log_success "Hardening Complete. PLEASE REBOOT."
}

main