#!/usr/bin/env bash

# vibed by Gemini Pro 3.0
# Hardening Script v3.6 (RAVAGE Edition)
# Changelog:
# v3.6.1: modified configure_display_wayland() to boot to GUI login
# v3.6: Maintained flattened sudo for SSH session stability
# v3.5.2: improved logging for setting up of clamav
# v3.5.1: fixed path: /proc/meminfo and Use systemd-run or explicit XDG_RUNTIME_DIR for SSH sessions
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
REQUIRED_PKGS=(ufw fail2ban clamav clamav-daemon chkrootkit rkhunter openssh-server libnotify-bin mako-notifier wlopm)

# --- 0. The Flex Module ---
check_hardware() {
    if grep -q "Raspberry Pi" /sys/firmware/devicetree/base/model 2>/dev/null; then
        MODEL=$(tr -d '\0' < /sys/firmware/devicetree/base/model)
        #fixed path: /proc/meminfo
        RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
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
        sleep 1
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

# --- 2. Interactive Phase ---
get_user_inputs() {
    log_info "--- Phase 1: Tactical Configuration ---"
    while true; do
        read -p "Enter custom SSH port (1025-65535): " SSH_PORT
        if [[ "$SSH_PORT" -gt 1024 && "$SSH_PORT" -lt 65535 ]]; then break;
        else log_error "Invalid port selection."; fi
    done
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
    log_info "Hardening SSH Gates (Iron Gate Protocol)..."
    local config="/etc/ssh/sshd_config"
    
    # Helper for parameter consistency
    set_param() {
        local key="$1"
        local val="$2"
        if grep -qE "^\s*#?\s*$key" "$config"; then
            sed -i "s|^\s*#\?\s*$key.*|$key $val|" "$config"
        else
            echo "$key $val" >> "$config"
        fi
    }

    # 1. Port & Protocol
    set_param "Port" "$SSH_PORT"

    # 2. Authentication Lockdown
    set_param "PasswordAuthentication" "no"
    set_param "PermitRootLogin" "no"
    set_param "PermitEmptyPasswords" "no"
    set_param "KbdInteractiveAuthentication" "no"
    set_param "KerberosAuthentication" "no"
    set_param "GSSAPIAuthentication" "no"
    set_param "PubkeyAuthentication" "yes"

    # 3. Surface Area Reduction
    set_param "X11Forwarding" "no"
    set_param "AllowAgentForwarding" "no"
    set_param "AllowTcpForwarding" "no"
    set_param "PrintLastLog" "yes"

    # 4. Anti-Brute Force / Timeouts
    set_param "ClientAliveInterval" "300"
    set_param "ClientAliveCountMax" "0"
    set_param "MaxAuthTries" "3"
    set_param "MaxSessions" "2"
    set_param "LoginGraceTime" "30"

    # 5. Crypto Shield (Explicit Ciphers)
    sed -i '/^Ciphers/d' "$config"
    sed -i '/^KexAlgorithms/d' "$config"
    sed -i '/^MACs/d' "$config"

    echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> "$config"
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> "$config"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" >> "$config"
    
    if sshd -t; then systemctl restart ssh; log_success "Iron Gate Active.";
    else log_error "SSH Config Error!"; exit 1; fi
}

configure_sudo_password() {
    local sudoers_file="/etc/sudoers.d/010_pi-nopasswd"
    if [[ -f "$sudoers_file" ]]; then
        sed -i 's/NOPASSWD[:[:space:]]*//g' "$sudoers_file"
    fi
}

configure_display_wayland() {
    log_info "Configuring Wayland (LabWC) Boot and Display Power..."
    
    # 
    # Change B3 (Console Autologin) to B4 (Desktop Autologin) 
    # OR B2 (Desktop Login Screen - Recommended for your 2FA setup)
    if command -v raspi-config >/dev/null; then 
        raspi-config nonint do_boot_behaviour B2
        log_success "Boot behavior set to Graphical Login Screen (B2)."
    fi
    
    local labwc_config_dir="$USER_HOME_DIR/.config/labwc"
    local autostart_file="$labwc_config_dir/autostart"
    mkdir -p "$labwc_config_dir"
    
    #
    if ! grep -q "wlopm" "$autostart_file" 2>/dev/null; then
        echo -e "\n# Display Power Management (Off after 600s)" >> "$autostart_file"
        echo "wlopm --set-timeout 600 &" >> "$autostart_file"
        log_success "Display power management configured."
    fi
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$labwc_config_dir"
}

setup_clamav() {
    log_info "Deploying ClamAV Watchman..."
    systemctl enable --now clamav-daemon.service > /dev/null
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=Daily Home Scan
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'find %h -type f -print0 | xargs -0 -r /usr/bin/clamdscan --fdpass --infected || { export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus; /usr/bin/notify-send "MALWARE ALERT" "Infection in %h" --urgency=critical; }'
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
    local uid=$(id -u "$SUDO_USER_NAME")
    
    sudo -u "$SUDO_USER_NAME" XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus systemctl --user daemon-reload || true
    sudo -u "$SUDO_USER_NAME" XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus systemctl --user enable --now clamscan-home.timer || true
}

setup_chkrootkit() {
    log_info "Scheduling Rootkit Checks..."
    tee "/etc/systemd/system/chkrootkit.timer" > /dev/null << EOL
[Unit]
Description=Daily chkrootkit
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL
    systemctl daemon-reload && systemctl enable --now chkrootkit.timer > /dev/null
}

setup_rkhunter() {
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
    rkhunter --update > /dev/null || true
    rkhunter --propupd > /dev/null || true
}

setup_fail2ban() {
    log_info "Arming Fail2Ban..."
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i "/^\[sshd\]/,/^\[/ s/enabled = .*/enabled = true/" /etc/fail2ban/jail.local
    sed -i "/^\[sshd\]/,/^\[/ s/port .*=.*/port = $SSH_PORT/" /etc/fail2ban/jail.local
    systemctl restart fail2ban
}

setup_kernel_hardening() {
    log_info "Casting the Heavenly Net (Kernel)..."
    tee "/etc/sysctl.d/99-hardening.conf" > /dev/null << EOL
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
EOL
    sysctl -p "/etc/sysctl.d/99-hardening.conf" > /dev/null
}

main() {
    check_root
    check_hardware
    ensure_dependencies
    get_user_inputs
    log_info "--- Starting Configuration ---"
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
    log_info "-------------------------------------"
    log_success "Hardening Complete. PLEASE REBOOT."
}

main