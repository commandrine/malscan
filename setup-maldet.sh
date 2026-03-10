#!/bin/bash
# install_maldet_clamav_v6.sh

# --- Configuration Variables ---
LMD_INSTALL_DIR="/usr/local/maldetect"
LMD_CONFIG_FILE="${LMD_INSTALL_DIR}/conf.maldet"
IGNORE_FILE="${LMD_INSTALL_DIR}/ignore_paths"
# Default to /var/www and /tmp for speed, or use first argument
SCAN_PATH="${1:-/var/www/,/tmp/,/var/tmp/,/home/}"

# --- Helper Functions ---
check_exit() {
    if [ $? -ne 0 ]; then
        echo "ERROR: $1 failed. Exiting script."
        exit 1
    fi
}

echo "--- 1. System Update & ClamAV Preparation ---"
sudo apt update && sudo apt install -y clamav clamav-daemon build-essential wget
check_exit "Package installation"

# Ensure clamav user can read root-owned files/sockets
sudo usermod -a -G root clamav

# Update ClamAV Signatures
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam

# Start ClamAV Daemon
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
echo "ClamAV daemon (clamd) is active and updated."

---

echo "--- 2. Installing Linux Malware Detect (maldet) ---"
wget -q http://www.rfxn.com/downloads/maldetect-current.tar.gz
check_exit "Downloading maldetect"

tar -xzf maldetect-current.tar.gz
LMD_DIR=$(find . -maxdepth 1 -type d -name "maldetect-*" | head -n 1)

cd "$LMD_DIR" || exit
sudo ./install.sh
check_exit "maldet installation"
cd - > /dev/null
rm -rf maldetect-current.tar.gz "$LMD_DIR"

---

echo "--- 3. Advanced Configuration & Optimization ---"
if [ ! -f "$LMD_CONFIG_FILE" ]; then
    echo "ERROR: Configuration file missing."
    exit 1
fi

# Correcting the config keys (scan_clamscan is the correct key for LMD)
sudo sed -i 's/^scan_clamscan=.*/scan_clamscan="1"/' "$LMD_CONFIG_FILE"
sudo sed -i 's/^quarantine_hits=.*/quarantine_hits="1"/' "$LMD_CONFIG_FILE"
sudo sed -i 's/^quarantine_clean=.*/quarantine_clean="1"/' "$LMD_CONFIG_FILE"
sudo sed -i 's/^email_alert=.*/email_alert="1"/' "$LMD_CONFIG_FILE"
# Replace 'root' with your actual email if you want external alerts
sudo sed -i 's/^email_addr=.*/email_addr="root@localhost"/' "$LMD_CONFIG_FILE"

# Add exclusions to ignore_paths to prevent scanning virtual/temp files
{
    echo "/proc/*"
    echo "/sys/*"
    echo "/dev/shm/.org.chromium.*"
    echo "/var/lib/mysql/*"
} | sudo tee -a "$IGNORE_FILE" > /dev/null

# Update Maldet signatures
sudo maldet --update-sig

---

echo "--- 4. Initial Optimized Scan ---"
echo "Starting scan on ${SCAN_PATH}..."
echo "Priority set to background (nice 19) and idle I/O (ionice 3)."

# Run the scan using the ClamAV engine via Maldet
# Using 'nice' and 'ionice' ensures the server stays responsive for web traffic
sudo nice -n 19 ionice -c 3 maldet -a "${SCAN_PATH}"

echo ""
echo "--- Installation & Initial Scan Complete! ---"
echo "To view the latest report, run: sudo maldet --report"
