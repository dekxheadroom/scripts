#!/bin/bash

# A script to automate the installation of Oracle Database Attacking Tool (ODAT)
# and its dependencies, including the Oracle Instant Client.
# Run with: sudo bash install_odat.sh

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# Variables for Oracle Instant Client files. Update these if the version changes.
BASIC_ZIP="instantclient-basic-linux.x64-21.4.0.0.0dbru.zip"
SQLPLUS_ZIP="instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip"
BASE_URL="https://download.oracle.com/otn_software/linux/instantclient/214000"
ORACLE_HOME="/opt/oracle/instantclient_21_4"
ODAT_DIR="/opt/odat"

# --- Main Installation ---
echo "[+] Starting ODAT and Oracle Instant Client installation..."

# Step 1: Update package lists and install system dependencies
echo "[+] Updating system and installing required packages (git, unzip, python3-pip)..."
sudo apt-get update -y
sudo apt-get install -y wget unzip git python3-pip build-essential libgmp-dev python3-scapy

# Step 2: Download Oracle Instant Client packages
echo "[+] Downloading Oracle Instant Client packages..."
wget "${BASE_URL}/${BASIC_ZIP}"
wget "${BASE_URL}/${SQLPLUS_ZIP}"

# Step 3: Create Oracle directory and unzip packages
echo "[+] Setting up Oracle Instant Client in /opt/oracle..."
sudo mkdir -p /opt/oracle
sudo unzip -o -d /opt/oracle "${BASIC_ZIP}"
sudo unzip -o -d /opt/oracle "${SQLPLUS_ZIP}"

# Step 4: Configure environment variables for all users
echo "[+] Configuring system-wide environment variables..."
sudo tee /etc/profile.d/oracle_instant_client.sh > /dev/null <<EOF
export LD_LIBRARY_PATH=${ORACLE_HOME}:\$LD_LIBRARY_PATH
export PATH=${ORACLE_HOME}:\$PATH
EOF

# Step 5: Clean up downloaded zip files
echo "[+] Cleaning up downloaded archives..."
rm "${BASIC_ZIP}" "${SQLPLUS_ZIP}"

# Step 6: Clone ODAT repository and install its dependencies
echo "[+] Cloning ODAT from GitHub and installing Python dependencies..."
# --- FIX: Remove the old directory if it exists ---
if [ -d "${ODAT_DIR}" ]; then
    echo "[-] Found existing ODAT directory. Removing it before cloning."
    rm -rf "${ODAT_DIR}"
fi

sudo git clone https://github.com/quentinhardy/odat.git "${ODAT_DIR}"

#echo "[+] Initializing ODAT submodules..."
# Use an absolute path to be explicit
(cd "${ODAT_DIR}" && sudo git submodule init && sudo git submodule update)

echo "[+] Installing Python dependencies..."
sudo pip3 install cx_Oracle python-libnmap colorlog termcolor passlib pycryptodome
sudo pip3 install pyyaml
sudo pip3 install "requests[socks]"

echo ""
echo "--- Installation Complete! ---"
echo "To apply the new environment variables, please log out and log back in, or run:"
echo "source /etc/profile.d/oracle_instant_client.sh"
