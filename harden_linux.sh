#!/usr/bin/env bash

# This Script is written by Gemini 2.5 Pro  
# This script must be run with sudo, but by a regular user.
# It will exit immediately if any command fails.
set -eo pipefail

# --- Color Definitions ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Log Functions ---
log_info() {
    echo -e "${CYAN}[INFO] $1${NC}"
}
log_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}
log_warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}
log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# --- Global Variables ---
SSH_PORT=""
SSH_KEY_PATH=""
SUDO_USER_NAME=""
USER_HOME_DIR=""

# --- Helper Functions ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo ./harden.sh'"
        exit 1
    fi
    
    # Get the name of the user who invoked sudo
    SUDO_USER_NAME="${SUDO_USER:-$(who am i | awk '{print $1}')}"
    if [[ -z "$SUDO_USER_NAME" || "$SUDO_USER_NAME" == "root" ]]; then
        log_error "This script must be run with 'sudo' by a non-root user. Exiting."
        exit 1
    fi
    
    # Get that user's home directory
    USER_HOME_DIR=$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)
    if [[ ! -d "$USER_HOME_DIR" ]]; then
        log_error "Could not determine home directory for user '$SUDO_USER_NAME'. Exiting."
        exit 1
    fi
    
    log_info "Script running as root, but on behalf of user: $SUDO_USER_NAME"
}

get_user_inputs() {
    log_info "--- Gathering User Inputs ---"
    
    # Get SSH Port
    while true; do
        read -p "Enter a custom SSH port (e.g., 22222, 1025-65535): " SSH_PORT
        if [[ "$SSH_PORT" -gt 1024 && "$SSH_PORT" -lt 65535 ]]; then
            log_info "Using SSH port $SSH_PORT"
            break
        else
            log_error "Invalid port. Must be between 1025 and 65535."
        fi
    done
    
    # Get SSH Public Key
    while true; do
        read -p "Enter the FULL path to the admin's public SSH key to add (e.g., $USER_HOME_DIR/.ssh/id_admin.pub): " SSH_KEY_PATH
        if [[ -f "$SSH_KEY_PATH" ]]; then
            log_info "Using public key: $SSH_KEY_PATH"
            break
        else
            log_error "File not found. Please provide the full path."
        fi
    done
}

install_packages() {
    log_info "Updating package lists..."
    sudo apt-get update -y
    
    log_info "Installing core hardening packages..."
    # Corrected package names
    sudo apt-get install -y openssh-server ufw clamav clamav-daemon chkrootkit rkhunter fail2ban
    log_success "All packages installed."
}

# --- Hardening Functions ---

setup_linger() {
    log_info "Enabling linger for $SUDO_USER_NAME..."
    loginctl enable-linger "$SUDO_USER_NAME"
    log_success "Linger enabled."
}

setup_firewall() {
    log_info "Configuring UFW (Firewall)..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Deny the default SSH port just in case
    sudo ufw deny 22/tcp
    
    # Allow the new custom SSH port
    sudo ufw allow "$SSH_PORT/tcp"
    
    # Enable UFW without interactive prompt
    yes | sudo ufw enable
    
    log_success "Firewall enabled on port $SSH_PORT."
    sudo ufw status numbered
}

secure_ssh() {
    log_info "Hardening SSH configuration..."
    local ssh_config="/etc/ssh/sshd_config"
    
    # Set custom port
    sudo sed -i "s/^#?Port .*/Port $SSH_PORT/" "$ssh_config"
    
    # Disable root login
    sudo sed -i "s/^#?PermitRootLogin .*/PermitRootLogin no/" "$ssh_config"
    
    # Disable password auth
    sudo sed -i "s/^#?PasswordAuthentication .*/PasswordAuthentication no/" "$ssh_config"
    
    # Disable challenge-response auth
    sudo sed -i "s/^#?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/" "$ssh_config"
    
    log_info "Adding authorized key for $SUDO_USER_NAME..."
    local auth_key_file="$USER_HOME_DIR/.ssh/authorized_keys"
    
    mkdir -p "$USER_HOME_DIR/.ssh"
    chmod 700 "$USER_HOME_DIR/.ssh"
    cat "$SSH_KEY_PATH" >> "$auth_key_file"
    chmod 600 "$auth_key_file"
    
    # Set correct ownership
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$USER_HOME_DIR/.ssh"
    
    log_info "Enabling and restarting SSH service..."
    sudo systemctl enable ssh.service
    sudo systemctl restart ssh
    
    log_success "SSH server hardened and restarted on port $SSH_PORT."
}

setup_clamav() {
    log_info "Setting up ClamAV..."
    
    # Enable and start the definition updater (system service)
    log_info "Enabling freshclam daemon for auto-updates..."
    sudo systemctl enable --now clamav-freshclam.service
    
    # Create the user service files
    local user_service_dir="$USER_HOME_DIR/.config/systemd/user"
    mkdir -p "$user_service_dir"
    
    log_info "Creating ClamAV user service..."
    tee "$user_service_dir/clamscan-home.service" > /dev/null << EOL
[Unit]
Description=Run ClamAV scan on home directory
[Service]
Type=oneshot
ExecStart=/usr/bin/clamscan -r --infected %h
EOL

    log_info "Creating ClamAV user timer..."
    tee "$user_service_dir/clamscan-home.timer" > /dev/null << EOL
[Unit]
Description=Run daily ClamAV scan on home directory
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL

    # Set ownership for the new files
    chown -R "$SUDO_USER_NAME:$SUDO_USER_NAME" "$user_service_dir"

    log_info "Enabling ClamAV user timer for $SUDO_USER_NAME..."
    # Run systemctl --user commands as the actual user
    sudo -u "$SUDO_USER_NAME" systemctl --user daemon-reload
    sudo -u "$SUDO_USER_NAME" systemctl --user enable --now clamscan-home.timer
    
    log_success "ClamAV scan scheduled for user $SUDO_USER_NAME."
}

setup_chkrootkit() {
    log_info "Setting up chkrootkit..."
    
    log_info "Creating chkrootkit system service..."
    tee "/etc/systemd/system/chkrootkit.service" > /dev/null << EOL
[Unit]
Description=Run chkrootkit scan
[Service]
Type=oneshot
ExecStart=/usr/sbin/chkrootkit
SuccessExitStatus=1
EOL

    log_info "Creating chkrootkit system timer..."
    tee "/etc/systemd/system/chkrootkit.timer" > /dev/null << EOL
[Unit]
Description=Run daily chkrootkit scan
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOL
    
    log_info "Enabling chkrootkit system timer..."
    sudo systemctl daemon-reload
    sudo systemctl enable --now chkrootkit.timer
    
    log_success "chkrootkit scan scheduled."
}

setup_rkhunter() {
    log_info "Setting up rkhunter..."
    local rkhunter_conf="/etc/rkhunter.conf"
    local rkhunter_default="/etc/default/rkhunter"
    
    # Configure rkhunter.conf
    sudo sed -i "s|^WEB_CMD=.*|WEB_CMD=\"/usr/bin/wget\"|" "$rkhunter_conf"
    sudo sed -i 's/^DISABLE_WEB_CMD=.*/#&/' "$rkhunter_conf" # Comment out the disable line
    sudo sed -i "s/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/" "$rkhunter_conf"
    sudo sed -i "s/^MIRRORS_MODE=.*/MIRRORS_MODE=0/" "$rkhunter_conf"
    
    # Configure /etc/default/rkhunter
    sudo sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' "$rkhunter_default"
    sudo sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' "$rkhunter_default"

    log_info "Running initial rkhunter update and baseline..."
    sudo rkhunter --update
    sudo rkhunter --propupd
    
    log_success "rkhunter configured for daily cron jobs."
}

setup_fail2ban() {
    log_info "Setting up fail2ban..."
    local jail_local="/etc/fail2ban/jail.local"
    
    # Create jail.local if it doesn't exist
    if [[ ! -f "$jail_local" ]]; then
        sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi
    
    log_info "Configuring fail2ban for SSH on port $SSH_PORT..."
    # Use sed to find the [sshd] block and update its settings
    # This ensures we're editing the correct section
    sudo sed -i "/^\[sshd\]/,/^\[/ s/enabled = .*/enabled = true/" "$jail_local"
    sudo sed -i "/^\[sshd\]/,/^\[/ s/port    = .*/port    = $SSH_PORT/" "$jail_local"
    sudo sed -i "/^\[sshd\]/,/^\[/ s/maxretry = .*/maxretry = 3/" "$jail_local"
    sudo sed -i "/^\[sshd\]/,/^\[/ s/bantime  = .*/bantime  = 600s/" "$jail_local"

    sudo systemctl restart fail2ban
    
    log_success "fail2ban is now active and monitoring SSH."
}

setup_kernel_hardening() {
    log_info "Applying kernel hardening parameters..."
    local sysctl_conf="/etc/sysctl.d/99-hardening.conf" # 99 to override defaults

    tee "$sysctl_conf" > /dev/null << EOL
# --- Kernel Hardening ---
# Restricts access to kernel pointers, making exploits harder to write
kernel.kptr_restrict = 2
# Restricts dmesg (kernel log) access to privileged users
kernel.dmesg_restrict = 1
# Hardens the BPF JIT compiler
net.core.bpf_jit_harden = 2
# --- TCP/IP Stack Hardening ---
# Enable SYN cookies to protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
# Log "martian" packets (spoofed/malformed)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# Ignore ICMP redirects (MITM protection)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Don't send ICMP redirects (this isn't a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Ignore "bogus" ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOL

    log_info "Loading new kernel parameters..."
    # Corrected typo from your notes (sytemctl.d)
    sudo sysctl -p "$sysctl_conf"
    
    log_success "Kernel hardening applied."
}

# --- Main Script Execution ---

main() {
    clear
    log_info "=== Ubuntu Host Hardening Script ==="
    
    check_root
    get_user_inputs
    install_packages
    
    log_info "--- Starting Hardening Sequence ---"
    
    setup_linger
    setup_firewall
    secure_ssh
    setup_clamav
    setup_chkrootkit
    setup_rkhunter
    setup_fail2ban
    setup_kernel_hardening
    
    log_info "-------------------------------------"
    log_success "Hardening script complete!"
    log_warn "Step 7 (2FA/MFA) was NOT automated. It is too risky."
    log_warn "Please set up 2FA manually for user '$SUDO_USER_NAME' *now*."
    log_info "It is recommended to REBOOT the system to ensure all services start correctly."
    log_info "-------------------------------------"
}

# Run the main function
main