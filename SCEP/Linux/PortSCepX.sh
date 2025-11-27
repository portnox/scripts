#!/bin/bash

# PortScepX - Enhanced SCEP Certificate Enrollment and 802.1X Setup Script
# Version: 1.4.1
# Last Updated: March 28, 2025
#
# Description:
# This script automates the process of obtaining certificates via SCEP protocol
# and configuring 802.1X authentication for network interfaces.
#
# Author: Portnox Security
# License: MIT

# Enable exit on error
set -e

# Configuration file path
CONFIG_FILE="/etc/portnox/config.conf"

# Default values
DEFAULT_SCEP_URL="http://scep-eus.portnox.com/scep"
DEFAULT_SCEP_SECRET="SCEP Secret Challenge"
DEFAULT_EAP_METHOD="tls"
DEFAULT_USER_OR_DEVICE="device"
DEFAULT_ENROLLMENT_METHOD="direct"

# Log file location
LOG_FILE="/var/log/portnox_setup.log"

# Color codes - Only use if output is to a terminal
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BLUE='\033[0;34m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    MAGENTA='\033[0;35m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    BLUE=''
    YELLOW=''
    CYAN=''
    MAGENTA=''
    BOLD=''
    NC=''
fi

# Global variables
DRY_RUN=false
VERBOSE=false
CONN_NAME=""
CA_CERT_PATH="/var/portnox/ca.pem"
CERT_PATH=""
KEY_PATH=""
DIGICERT_PATH="/var/portnox/digicert_root_ca.crt"
ENROLLMENT_METHOD=""
NO_UPDATES=false

# Create a robust global temp directory
PORTNOX_TEMP_DIR="/var/tmp/portnox-$(date +%s)"

# Function to create and set up temp directory
setup_temp_dir() {
    # Create the main temp directory with appropriate permissions
    sudo mkdir -p "$PORTNOX_TEMP_DIR"
    sudo chmod 1777 "$PORTNOX_TEMP_DIR"
    
    # Create subdirectories for specific operations
    sudo mkdir -p "$PORTNOX_TEMP_DIR/apt" "$PORTNOX_TEMP_DIR/certs" "$PORTNOX_TEMP_DIR/downloads"
    sudo chmod 1777 "$PORTNOX_TEMP_DIR/apt" "$PORTNOX_TEMP_DIR/certs" "$PORTNOX_TEMP_DIR/downloads"
    
    # Export environment variables to use our custom temp directory
    export TMPDIR="$PORTNOX_TEMP_DIR"
    export TEMPDIR="$PORTNOX_TEMP_DIR"
    export TMP="$PORTNOX_TEMP_DIR"
    export APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
    
    log_info "Created custom temp directory: $PORTNOX_TEMP_DIR"
}

# Function to clean up temp directory
cleanup_temp_dir() {
    if [ -d "$PORTNOX_TEMP_DIR" ]; then
        log_info "Cleaning up temporary directory: $PORTNOX_TEMP_DIR"
        sudo rm -rf "$PORTNOX_TEMP_DIR"
    fi
}

# Function to log messages with timestamp and colors
log_message() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Log to file without colors
    echo "[$timestamp] $1" | sudo tee -a "$LOG_FILE" > /dev/null
    # Display with colors on terminal
    echo -e "${BOLD}[$timestamp]${NC} $1"
}

# Function to log success messages
log_success() {
    log_message "${GREEN}SUCCESS:${NC} $1"
}

# Function to log error messages
log_error() {
    log_message "${RED}ERROR:${NC} $1"
}

# Function to log warning messages
log_warning() {
    log_message "${YELLOW}WARNING:${NC} $1"
}

# Function to log information messages
log_info() {
    log_message "${BLUE}INFO:${NC} $1"
}

# Function to log verbose messages
log_verbose() {
    if [ "$VERBOSE" = true ]; then
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] VERBOSE: $1" | sudo tee -a "$LOG_FILE" > /dev/null
        echo -e "${CYAN}VERBOSE:${NC} $1"
    fi
}

# Function to clean up on error
cleanup() {
    log_error "Error occurred, cleaning up..."
    if [ -n "$CONN_NAME" ] && [ "$DRY_RUN" = false ]; then
        sudo nmcli connection delete "$CONN_NAME" 2>/dev/null || true
        log_warning "Removed connection: $CONN_NAME"
    fi
    cleanup_temp_dir
    exit 1
}

# Use ERR trap to call cleanup on error
trap 'cleanup' ERR

# Create log file
sudo mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
sudo touch "$LOG_FILE" 2>/dev/null || { echo "Cannot create log file $LOG_FILE. Check permissions."; exit 1; }
sudo chmod 644 "$LOG_FILE"

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log_verbose "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log_info "Configuration loaded from $CONFIG_FILE"
    else
        log_verbose "Configuration file not found, using defaults"
    fi
}

# Display header
display_header() {
    cat << "EOF"
  ______             _                          __   __
  | ___ \           | |                         \ \ / /
  | |_/ /___   _ __ | |_  ___   ___  ___  _ __   \ V / 
  |  __// _ \ | '__|| __|/ __| / __|/ _ \| '_ \  /   \ 
  | |  | (_) || |   | |_ \__ \| (__|  __/| |_) |/ /^\ \
  \_|   \___/ |_|    \__||___/ \___|\___|| .__/ \/   \/
                                         | |           
                                         |_|           
EOF
    echo -e "${GREEN}=== PortScepX - SCEP Certificate and 802.1X Setup ===${NC}"
}

# Advanced APT repair function
fix_apt_completely() {
    log_info "Performing comprehensive APT repair..."
    
    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
        log_warning "Not running as root, cannot perform APT repairs"
        return 1
    fi
    
    # Clean package cache
    log_info "Cleaning package cache..."
    sudo apt-get clean
    
    # Remove package lists
    log_info "Removing package lists..."
    sudo rm -rf /var/lib/apt/lists/*
    
    # Create a separate directory for APT operations
    local APT_TMP="$PORTNOX_TEMP_DIR/apt-repair"
    sudo mkdir -p "$APT_TMP"
    sudo chmod 1777 "$APT_TMP"
    
    # Fix any broken dependencies
    log_info "Fixing broken dependencies..."
    sudo apt --fix-broken install -y || log_warning "Could not fix broken packages"
    
    # Update package lists with multiple fallback methods
    log_info "Updating package lists with fixes..."
    
    # Try standard update first
    if ! sudo apt-get update; then
        log_warning "Standard update failed, trying with allow-insecure-repositories..."
        # Try with security bypass
        if ! sudo apt-get update --allow-insecure-repositories; then
            log_warning "Insecure update failed, trying with alternative sources..."
            # Create a minimal sources list for emergency update
            local CODENAME
            CODENAME=$(lsb_release -cs 2>/dev/null || echo "focal")
            local TEMP_SOURCES="$APT_TMP/sources.list"
            
            sudo tee "$TEMP_SOURCES" > /dev/null << EOF
deb [trusted=yes] http://archive.ubuntu.com/ubuntu $CODENAME main restricted
deb [trusted=yes] http://security.ubuntu.com/ubuntu $CODENAME-security main restricted
EOF
            
            # Try update with minimal sources
            if ! sudo apt-get -o "Dir::Etc::SourceList=$TEMP_SOURCES" update; then
                log_error "All APT update methods failed"
                return 1
            fi
        fi
    fi
    
    log_success "APT repositories repaired successfully"
    return 0
}

# Check dependency versions - now checks both sscep and certmonger regardless of method
check_dependency_versions() {
    echo -e "\n${MAGENTA}=== Checking Dependency Versions ===${NC}"
    
    # Check OpenSSL version
    if command -v openssl >/dev/null 2>&1; then
        OPENSSL_VERSION=$(openssl version)
        echo -e "${CYAN}OpenSSL:${NC} $OPENSSL_VERSION"
    else
        echo -e "${RED}OpenSSL:${NC} Not installed"
    fi
    
    # Check curl version
    if command -v curl >/dev/null 2>&1; then
        CURL_VERSION=$(curl --version | head -n 1)
        echo -e "${CYAN}curl:${NC} $CURL_VERSION"
    else
        echo -e "${RED}curl:${NC} Not installed"
    fi
    
    # Check NetworkManager version
    if command -v nmcli >/dev/null 2>&1; then
        NM_VERSION=$(nmcli --version)
        echo -e "${CYAN}NetworkManager:${NC} $NM_VERSION"
    else
        echo -e "${RED}NetworkManager:${NC} Not installed"
    fi
    
    # Check git version (needed for sscep installation)
    if command -v git >/dev/null 2>&1; then
        GIT_VERSION=$(git --version)
        echo -e "${CYAN}Git:${NC} $GIT_VERSION"
    else
        echo -e "${YELLOW}Git:${NC} Not installed"
    fi
    
    # Check build tools
    if command -v gcc >/dev/null 2>&1; then
        GCC_VERSION=$(gcc --version | head -n 1)
        echo -e "${CYAN}GCC:${NC} $GCC_VERSION"
    else
        echo -e "${YELLOW}GCC:${NC} Not installed"
    fi
    
    if command -v make >/dev/null 2>&1; then
        MAKE_VERSION=$(make --version | head -n 1)
        echo -e "${CYAN}Make:${NC} $MAKE_VERSION"
    else
        echo -e "${YELLOW}Make:${NC} Not installed"
    fi
    
    if command -v automake >/dev/null 2>&1; then
        AUTOMAKE_VERSION=$(automake --version | head -n 1)
        echo -e "${CYAN}Automake:${NC} $AUTOMAKE_VERSION"
    else
        echo -e "${YELLOW}Automake:${NC} Not installed"
    fi
    
    if command -v autoreconf >/dev/null 2>&1; then
        AUTOCONF_VERSION=$(autoreconf --version | head -n 1)
        echo -e "${CYAN}Autoconf:${NC} $AUTOCONF_VERSION"
    else
        echo -e "${YELLOW}Autoconf:${NC} Not installed"
    fi
    
    # Check sscep version
    if command -v sscep >/dev/null 2>&1; then
        SSCEP_VERSION=$(sscep --version 2>&1 | grep "version" | head -n 1 || echo "version unknown")
        echo -e "${CYAN}sscep:${NC} $SSCEP_VERSION"
    else
        echo -e "${YELLOW}sscep:${NC} Not installed"
    fi
    
    # Check certmonger version
    if command -v getcert >/dev/null 2>&1; then
        # Certmonger doesn't support a standard --version flag
        # Try to get version from package manager
        if command -v dpkg >/dev/null 2>&1; then
            CERTMONGER_VERSION=$(dpkg -l certmonger 2>/dev/null | grep certmonger | awk '{print $3}' || echo "installed (version unknown)")
        elif command -v rpm >/dev/null 2>&1; then
            CERTMONGER_VERSION=$(rpm -q certmonger --qf "%{VERSION}" 2>/dev/null || echo "installed (version unknown)")
        else
            # Check if service is running
            if systemctl is-active certmonger >/dev/null 2>&1; then
                CERTMONGER_VERSION="Service running (version unknown)"
            else
                CERTMONGER_VERSION="Installed (version unknown)"
            fi
        fi
        echo -e "${CYAN}certmonger:${NC} $CERTMONGER_VERSION"
    else
        echo -e "${YELLOW}certmonger:${NC} Not installed"
    fi
    
    echo -e "${MAGENTA}=====================================${NC}\n"
}

# Show detailed help
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Description:
  PortScepifier automates the process of obtaining certificates via SCEP protocol 
  and configuring 802.1X authentication for network interfaces. The script 
  supports two enrollment methods: direct (using OpenSSL and sscep) and 
  certmonger (using the certmonger service).

Options:
  -h, --help           Show this help message and exit
  -v, --verbose        Enable verbose output and detailed logging
  -d, --dry-run        Simulate without making changes
  -c, --config FILE    Use specific configuration file
  --direct             Use direct OpenSSL+sscep enrollment
  --certmonger         Use certmonger enrollment
  --clean              Clean up existing certificates and CAs before running
  --no-updates         Skip apt/yum update checks
  --fix-apt            Fix APT repository issues before running
  --list-certs         List all certificates and CAs
  --show-sscep-install Show SSCEP installation instructions

Certificate Enrollment Methods:
  - direct: Uses OpenSSL and sscep directly for enrollment (default)
  - certmonger: Uses certmonger service for certificate management

Troubleshooting Steps:
  1. Run with verbose flag: $0 -v
  2. Check logs at: /var/log/portnox_setup.log
  3. Run the troubleshooting option: $0 -> Menu option 4
  4. Run dependency check: $0 -> Menu option 5
  5. List certificates: $0 -> Menu option 8
  6. Show SSCEP installation steps: $0 -> Menu option 9

Common Issues:
  - Temp directory permissions: Ensure /var/tmp is writable by the current user
  - Certificate rejection: Verify SCEP URL and secret are correct
  - Network issues: Ensure network connectivity to the SCEP server
  - Package installation: If apt/yum fails, use --fix-apt or --no-updates flags

For more information and examples, use the "--advanced-help" option.
EOF
}

# Function to list all certificates and CAs
list_certificates_and_cas() {
    echo -e "\n${MAGENTA}=== Listing Certificates and CAs ===${NC}"
    
    # Check for CA certificates
    echo -e "${CYAN}CA Certificates:${NC}"
    if [ -f "$CA_CERT_PATH" ]; then
        echo -e "  ${GREEN}✓${NC} SCEP CA Certificate: $CA_CERT_PATH"
        if [ "$VERBOSE" = true ]; then
            echo -e "    Details:"
            sudo openssl x509 -in "$CA_CERT_PATH" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
        fi
    else
        echo -e "  ${RED}✗${NC} SCEP CA Certificate: Not found"
    fi
    
    if [ -f "$DIGICERT_PATH" ]; then
        echo -e "  ${GREEN}✓${NC} DigiCert Root CA: $DIGICERT_PATH"
        if [ "$VERBOSE" = true ]; then
            echo -e "    Details:"
            sudo openssl x509 -in "$DIGICERT_PATH" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
        fi
    else
        echo -e "  ${RED}✗${NC} DigiCert Root CA: Not found"
    fi
    
    # Check for client certificates
    echo -e "\n${CYAN}Client Certificates:${NC}"
    CERTS_COUNT=0
    
    if [ -d "/etc/certs" ]; then
        while read -r cert; do
            if [ -f "$cert" ]; then
                CERTS_COUNT=$((CERTS_COUNT + 1))
                echo -e "  ${GREEN}✓${NC} Certificate: $cert"
                
                # Check if corresponding private key exists
                KEY_FILE="${cert%.crt}.key"
                if [ -f "$KEY_FILE" ]; then
                    echo -e "    ${GREEN}✓${NC} Private key: $KEY_FILE"
                    
                    # Verify key matches certificate
                    CERT_MODULUS=$(sudo openssl x509 -in "$cert" -noout -modulus 2>/dev/null | cut -d= -f2)
                    KEY_MODULUS=$(sudo openssl rsa -in "$KEY_FILE" -noout -modulus 2>/dev/null | cut -d= -f2)
                    
                    if [ "$CERT_MODULUS" = "$KEY_MODULUS" ]; then
                        echo -e "    ${GREEN}✓${NC} Key matches certificate"
                    else
                        echo -e "    ${RED}✗${NC} Key does NOT match certificate"
                    fi
                else
                    echo -e "    ${RED}✗${NC} Private key not found"
                fi
                
                # Show certificate details
                if [ "$VERBOSE" = true ]; then
                    echo -e "    Details:"
                    sudo openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/    /'
                fi
            fi
        done < <(find /etc/certs -name "*.crt" 2>/dev/null || echo "")
    fi
    
    if [ $CERTS_COUNT -eq 0 ]; then
        echo -e "  ${RED}✗${NC} No client certificates found in /etc/certs/"
    fi
    
    # Check certmonger certificates if available
    if command -v getcert >/dev/null 2>&1; then
        echo -e "\n${CYAN}Certmonger Tracked Certificates:${NC}"
        CERTM_COUNT=0
        
        while read -r id; do
            if [ -n "$id" ]; then
                CERTM_COUNT=$((CERTM_COUNT + 1))
                echo -e "  ${GREEN}✓${NC} Certificate request ID: $id"
                
                # Get status
                STATUS=$(sudo getcert list -i "$id" 2>/dev/null | grep "status:" | awk '{print $2}' || echo "unknown")
                echo -e "    Status: $STATUS"
                
                # Get cert and key file
                CERTM_CERT=$(sudo getcert list -i "$id" 2>/dev/null | grep "certificate:" | awk '{print $2}' || echo "unknown")
                CERTM_KEY=$(sudo getcert list -i "$id" 2>/dev/null | grep "key pair storage:" | awk '{print $4}' || echo "unknown")
                
                if [ -n "$CERTM_CERT" ] && [ -f "$CERTM_CERT" ]; then
                    echo -e "    Certificate file: $CERTM_CERT"
                    if [ "$VERBOSE" = true ]; then
                        echo -e "    Details:"
                        sudo openssl x509 -in "$CERTM_CERT" -noout -subject -issuer -dates 2>/dev/null | sed 's/^/      /'
                    fi
                fi
                
                if [ -n "$CERTM_KEY" ] && [ -f "$CERTM_KEY" ]; then
                    echo -e "    Key file: $CERTM_KEY"
                fi
            fi
        done < <(sudo getcert list 2>/dev/null | grep "Request ID" | awk -F"'" '{print $2}' || echo "")
        
        if [ $CERTM_COUNT -eq 0 ]; then
            echo -e "  ${RED}✗${NC} No certificates tracked by certmonger"
        fi
    fi
    
    # Check NetworkManager 802.1X connections
    echo -e "\n${CYAN}NetworkManager 802.1X Connections:${NC}"
    NM_COUNT=0
    
    while read -r conn; do
        if [ -n "$conn" ]; then
            NM_COUNT=$((NM_COUNT + 1))
            echo -e "  ${GREEN}✓${NC} Connection: $conn"
            
            # Get connection details
            CONN_FILE="/etc/NetworkManager/system-connections/$conn.nmconnection"
            if [ -f "$CONN_FILE" ]; then
                INTERFACE=$(grep "interface-name=" "$CONN_FILE" 2>/dev/null | cut -d= -f2 || echo "unknown")
                EAP_TYPE=$(grep "eap=" "$CONN_FILE" 2>/dev/null | cut -d= -f2 || echo "unknown")
                IDENTITY=$(grep "identity=" "$CONN_FILE" 2>/dev/null | cut -d= -f2 || echo "unknown")
                
                echo -e "    Interface: $INTERFACE"
                echo -e "    EAP method: $EAP_TYPE"
                echo -e "    Identity: $IDENTITY"
                
                # Check if connection is active
                if nmcli -g GENERAL.STATE connection show "$conn" 2>/dev/null | grep -q "activated"; then
                    echo -e "    Status: ${GREEN}ACTIVE${NC}"
                else
                    echo -e "    Status: ${YELLOW}INACTIVE${NC}"
                fi
            fi
        fi
    done < <(nmcli -g NAME connection show 2>/dev/null | grep "8021x" || echo "")
    
    if [ $NM_COUNT -eq 0 ]; then
        echo -e "  ${RED}✗${NC} No 802.1X connections found in NetworkManager"
    fi
    
    echo -e "${MAGENTA}=====================================${NC}\n"
}

# Show SSCEP installation instructions
show_sscep_installation() {
    echo -e "\n${MAGENTA}=== SSCEP Installation Instructions ===${NC}"
    
    echo -e "${CYAN}Description:${NC}"
    echo "  SSCEP (Simple SCEP) is a command-line client for the SCEP protocol, which"
    echo "  is used for certificate enrollment and management. It needs to be installed"
    echo "  for the PortScepifier script to function correctly in direct mode."
    
    echo -e "\n${CYAN}Prerequisites:${NC}"
    echo "  1. Git - Used to clone the source code repository"
    echo "  2. GCC - C compiler required for building SSCEP"
    echo "  3. Make - Used to automate the build process"
    echo "  4. Autoconf/Automake - Required to generate the build system"
    echo "  5. OpenSSL development libraries - Required for cryptographic operations"
    
    echo -e "\n${CYAN}Installation Steps:${NC}"
    
    echo -e "\n${YELLOW}Ubuntu/Debian:${NC}"
    echo "  # Install dependencies"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install git gcc make libssl-dev autoconf automake libtool pkg-config"
    echo ""
    echo "  # Clone and build SSCEP"
    echo "  git clone https://github.com/certnanny/sscep.git /tmp/sscep"
    echo "  cd /tmp/sscep"
    echo "  autoreconf --install  # Generate configure script"
    echo "  ./configure"
    echo "  make"
    echo "  sudo make install"
    echo ""
    echo "  # Verify installation"
    echo "  sscep --version"
    
    echo -e "\n${YELLOW}RHEL/CentOS/Fedora:${NC}"
    echo "  # Install dependencies"
    echo "  sudo dnf install git gcc make openssl-devel autoconf automake libtool pkgconfig"
    echo ""
    echo "  # Clone and build SSCEP"
    echo "  git clone https://github.com/certnanny/sscep.git /tmp/sscep"
    echo "  cd /tmp/sscep"
    echo "  autoreconf --install  # Generate configure script"
    echo "  ./configure"
    echo "  make"
    echo "  sudo make install"
    echo ""
    echo "  # Verify installation"
    echo "  sscep --version"
    
    echo -e "\n${CYAN}Troubleshooting:${NC}"
    echo "  - If 'autoreconf' fails:"
    echo "    For Ubuntu/Debian: sudo apt-get install autoconf libtool pkg-config"
    echo "    For RHEL/CentOS/Fedora: sudo dnf install autoconf libtool pkgconfig"
    echo ""
    echo "  - If build fails with OpenSSL errors:"
    echo "    Check OpenSSL version and development package installation"
    echo ""
    echo "  - If 'make install' fails due to permissions:"
    echo "    Try 'sudo make install' instead"
    
    echo -e "\n${CYAN}Alternative Installation:${NC}"
    echo "  Some distributions may have SSCEP in their repositories:"
    echo "  - Ubuntu/Debian: sudo apt-get install sscep"
    echo "  - RHEL/CentOS (with EPEL): sudo dnf install sscep"
    
    echo -e "\n${CYAN}Manual Steps for Certificate Enrollment:${NC}"
    echo "  1. Generate a new key:"
    echo "     openssl genrsa -out /etc/certs/client.key 2048"
    echo ""
    echo "  2. Create a configuration file for CSR:"
    echo "     See \"Manual Certificate Enrollment\" in advanced help"
    echo ""
    echo "  3. Generate a Certificate Signing Request (CSR):"
    echo "     openssl req -new -key /etc/certs/client.key -config /tmp/openssl.cnf -out /tmp/request.csr"
    echo ""
    echo "  4. Get the CA certificate:"
    echo "     sscep getca -u <SCEP_URL> -c /var/portnox/ca.pem"
    echo ""
    echo "  5. Request a certificate:"
    echo "     sscep enroll -u <SCEP_URL> -c /var/portnox/ca.pem -k /etc/certs/client.key -r /tmp/request.csr -l /etc/certs/client.crt"
    
    echo -e "${MAGENTA}=====================================${NC}\n"
}

# Show detailed manual steps for certificate enrollment
show_manual_enrollment_steps() {
    echo -e "\n${MAGENTA}=== Manual Certificate Enrollment Steps ===${NC}"
    
    echo -e "${CYAN}Step 1: Create Directories${NC}"
    echo "# Create necessary directories with proper permissions"
    echo "sudo mkdir -p /etc/certs /var/portnox"
    echo "sudo chmod 755 /etc/certs /var/portnox"
    
    echo -e "\n${CYAN}Step 2: Download DigiCert Root CA${NC}"
    echo "# Download the DigiCert root CA certificate"
    echo "sudo curl -s -L -o /var/portnox/digicert_root_ca.crt https://www.digicert.com/CACerts/DigiCertTrustedRootG4.crt"
    echo "# Convert if in DER format"
    echo "sudo openssl x509 -inform der -in /var/portnox/digicert_root_ca.crt -out /var/portnox/digicert_root_ca.pem"
    echo "sudo chmod 644 /var/portnox/digicert_root_ca.crt"
    
    echo -e "\n${CYAN}Step 3: Get CA Certificate from SCEP Server${NC}"
    echo "# Using sscep (recommended)"
    echo "sudo sscep getca -u \"http://scep.example.com/scep\" -c /var/portnox/ca.pem -F"
    echo ""
    echo "# Or using curl"
    echo "sudo curl -s -f -L -o /tmp/ca_cert.crt \"http://scep.example.com/scep?operation=GetCACert\""
    echo "# If the certificate is in DER format, convert to PEM"
    echo "sudo openssl x509 -inform der -in /tmp/ca_cert.crt -out /var/portnox/ca.pem"
    echo "sudo chmod 644 /var/portnox/ca.pem"
    
    echo -e "\n${CYAN}Step 4: Generate Key Pair and CSR${NC}"
    echo "# Generate RSA key pair"
    echo "sudo openssl genrsa -out /etc/certs/device-\$(hostname).key 2048"
    echo "sudo chmod 600 /etc/certs/device-\$(hostname).key"
    echo ""
    echo "# Create OpenSSL config for CSR"
    echo "cat > /tmp/openssl.cnf << EOF"
    echo "[req]"
    echo "distinguished_name = req_dn"
    echo "req_extensions = req_ext"
    echo "attributes = req_attr"
    echo "prompt = no"
    echo ""
    echo "[req_dn]"
    echo "CN=\$(hostname)"
    echo ""
    echo "[req_ext]"
    echo "basicConstraints = CA:FALSE"
    echo "keyUsage = digitalSignature, keyEncipherment, dataEncipherment"
    echo "extendedKeyUsage = clientAuth"
    echo ""
    echo "[req_attr]"
    echo "challengePassword = your_secret_here"
    echo "EOF"
    echo ""
    echo "# Generate CSR"
    echo "sudo openssl req -new -key /etc/certs/device-\$(hostname).key -config /tmp/openssl.cnf -out /tmp/request.csr"
    
    echo -e "\n${CYAN}Step 5: Enroll Certificate with SCEP${NC}"
    echo "# Direct method with sscep"
    echo "sudo sscep enroll -u \"http://scep.example.com/scep\" -c /var/portnox/ca.pem \\"
    echo "  -k /etc/certs/device-\$(hostname).key -r /tmp/request.csr \\"
    echo "  -l /etc/certs/device-\$(hostname).crt -v"
    echo ""
    echo "# Set permissions"
    echo "sudo chmod 644 /etc/certs/device-\$(hostname).crt"
    
    echo -e "\n${CYAN}Step 6: Verify Certificate${NC}"
    echo "# Check certificate details"
    echo "sudo openssl x509 -in /etc/certs/device-\$(hostname).crt -text -noout"
    echo ""
    echo "# Verify certificate and key match"
    echo "sudo openssl x509 -in /etc/certs/device-\$(hostname).crt -noout -modulus | md5sum"
    echo "sudo openssl rsa -in /etc/certs/device-\$(hostname).key -noout -modulus | md5sum"
    echo "# These commands should produce identical MD5 hashes if the key matches the certificate"
    
    echo -e "\n${CYAN}Step 7: Configure NetworkManager for 802.1X${NC}"
    echo "# For Ethernet"
    echo "sudo nmcli connection add type ethernet con-name \"802.1x-eth0\" ifname eth0 \\"
    echo "  802-1x.eap tls 802-1x.identity \"CN=\$(hostname)\" \\"
    echo "  802-1x.ca-cert /var/portnox/ca.pem \\"
    echo "  802-1x.client-cert /etc/certs/device-\$(hostname).crt \\"
    echo "  802-1x.private-key /etc/certs/device-\$(hostname).key \\"
    echo "  ipv4.method auto ipv6.method auto"
    echo ""
    echo "# For WiFi"
    echo "sudo nmcli connection add type wifi con-name \"802.1x-wlan0\" ifname wlan0 \\"
    echo "  ssid \"YourSSID\" wifi.mode infrastructure wifi-security.key-mgmt wpa-eap \\"
    echo "  802-1x.eap tls 802-1x.identity \"CN=\$(hostname)\" \\"
    echo "  802-1x.ca-cert /var/portnox/ca.pem \\"
    echo "  802-1x.client-cert /etc/certs/device-\$(hostname).crt \\"
    echo "  802-1x.private-key /etc/certs/device-\$(hostname).key \\"
    echo "  ipv4.method auto ipv6.method auto"
    
    echo -e "\n${CYAN}Step 8: Activate Connection${NC}"
    echo "# Activate the connection"
    echo "sudo nmcli connection up \"802.1x-eth0\""
    
    echo -e "\n${CYAN}Troubleshooting:${NC}"
    echo "# Check NetworkManager status"
    echo "sudo systemctl status NetworkManager"
    echo ""
    echo "# View connection logs"
    echo "sudo journalctl -u NetworkManager -f"
    echo ""
    echo "# Test network connectivity"
    echo "ping -c 3 8.8.8.8"
    echo ""
    echo "# Check authentication logs"
    echo "sudo tail -f /var/log/auth.log"
    
    echo -e "${MAGENTA}=====================================${NC}\n"
}

# Validate URL
validate_url() {
    local url=$1
    if [[ ! "$url" =~ ^https?:// ]]; then
        log_error "Invalid URL format: $url"
        log_info "URL should begin with http:// or https://"
        return 1
    fi
    return 0
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/etc/os-release
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        log_info "Detected distribution: ${YELLOW}$DISTRO $VERSION${NC}"
    else
        log_error "Cannot detect distribution. Exiting."
        exit 1
    fi
}

# Improved fix_apt_errors function with better error handling
fix_apt_errors() {
    # Check if we have sufficient permissions
    if [ "$(id -u)" -ne 0 ]; then
        log_warning "Not running as root, cannot attempt to fix apt errors"
        return 1
    fi
    
    # Try to fix common apt errors
    log_info "Attempting to fix apt repository errors..."
    
    # Ensure our temp directory is set up properly
    local APT_TEMP_DIR="$PORTNOX_TEMP_DIR/apt"
    sudo mkdir -p "$APT_TEMP_DIR"
    sudo chmod 1777 "$APT_TEMP_DIR"
    
    # Create required subdirectories for APT operation
    for dir in etc etc/apt etc/apt/sources.list.d sources.list.d trusted.gpg.d cache archives state lists partial; do
        sudo mkdir -p "$APT_TEMP_DIR/$dir"
        sudo chmod 1777 "$APT_TEMP_DIR/$dir"
    done
    
    # Clean apt lists and cache
    log_info "Cleaning apt cache and lists..."
    sudo apt-get clean
    
    # Create a custom apt configuration file
    local APT_CONF_FILE="$APT_TEMP_DIR/apt.conf"
    sudo bash -c "cat > \"$APT_CONF_FILE\" << EOL
Acquire::AllowInsecureRepositories \"true\";
Acquire::AllowDowngradeToInsecureRepositories \"true\";
APT::Get::AllowUnauthenticated \"true\";
Dir::Etc::SourceList \"$APT_TEMP_DIR/sources.list\";
Dir::Etc::SourceParts \"$APT_TEMP_DIR/sources.list.d\";
Dir::State \"$APT_TEMP_DIR/state\";
Dir::Cache \"$APT_TEMP_DIR/cache\";
Dir::Cache::Archives \"$APT_TEMP_DIR/archives\";
EOL"
    
    # Create empty status file
    sudo touch "$APT_TEMP_DIR/state/status"
    
    # Copy main sources.list if it exists or create a minimal one
    if [ -f /etc/apt/sources.list ]; then
        sudo cp /etc/apt/sources.list "$APT_TEMP_DIR/sources.list"
    else
        # Create a minimal sources.list based on detected distro
        local CODENAME
        CODENAME=$(lsb_release -cs 2>/dev/null || echo "focal")
        sudo bash -c "cat > \"$APT_TEMP_DIR/sources.list\" << EOL
deb [trusted=yes] http://archive.ubuntu.com/ubuntu $CODENAME main restricted
deb [trusted=yes] http://archive.ubuntu.com/ubuntu $CODENAME-updates main restricted
deb [trusted=yes] http://security.ubuntu.com/ubuntu $CODENAME-security main restricted
EOL"
    fi
    
    # Try to update with minimized output and custom config
    log_info "Attempting modified apt-get update..."
    
    # Silence output but capture errors
    if sudo apt-get -qq -o "Dir::Etc=$APT_TEMP_DIR/etc" \
                 -o "Dir::State=$APT_TEMP_DIR/state" \
                 -o "Dir::Cache=$APT_TEMP_DIR/cache" \
                 -o "Acquire::AllowInsecureRepositories=true" \
                 -o "Acquire::AllowDowngradeToInsecureRepositories=true" \
                 -o "APT::Get::AllowUnauthenticated=true" \
                 update 2>"$APT_TEMP_DIR/apt-errors.log"; then
        log_success "Repository index updated successfully"
    else
        log_warning "Custom apt update failed, ignoring repository errors"
        if [ "$VERBOSE" = true ] && [ -f "$APT_TEMP_DIR/apt-errors.log" ]; then
            log_verbose "APT errors: $(cat "$APT_TEMP_DIR/apt-errors.log")"
        fi
    fi
    
    return 0
}

# Improved build_sscep function to handle modern repositories
build_sscep() {
    log_info "Building SSCEP from source..."
    
    # Set up build directory
    local SSCEP_BUILD_DIR="$PORTNOX_TEMP_DIR/sscep"
    sudo mkdir -p "$SSCEP_BUILD_DIR"
    sudo chmod 1777 "$SSCEP_BUILD_DIR"
    
    # Clone repository
    log_info "Cloning SSCEP repository..."
    if ! git clone https://github.com/certnanny/sscep.git "$SSCEP_BUILD_DIR"; then
        log_error "Failed to clone SSCEP repository"
        return 1
    fi
    
    # Enter build directory
    cd "$SSCEP_BUILD_DIR" || {
        log_error "Failed to change to SSCEP directory"
        return 1
    }
    
    # Check if we need to run autoreconf (newer builds require this)
    log_info "Preparing build system..."
    if [ -f "configure.ac" ] && [ ! -f "configure" ]; then
        log_info "Running autoreconf to generate configure script..."
        if ! autoreconf --install; then
            log_warning "autoreconf failed, trying alternative method..."
            # Try older method if available
            if [ -f "bootstrap" ]; then
                log_info "Running bootstrap script..."
                if ! ./bootstrap; then
                    log_error "Failed to bootstrap SSCEP build system"
                    cd - || return 1
                    return 1
                fi
            else
                log_error "No method available to generate configure script"
                cd - || return 1
                return 1
            fi
        fi
    fi
    
    # Configure and build
    log_info "Configuring SSCEP build..."
    if [ -f "configure" ]; then
        if ! ./configure; then
            log_error "Configure failed"
            cd - || return 1
            return 1
        fi
    else
        log_error "No configure script found"
        cd - || return 1
        return 1
    fi
    
    log_info "Building SSCEP..."
    if ! make; then
        log_error "Build failed"
        cd - || return 1
        return 1
    fi
    
    log_info "Installing SSCEP..."
    if ! sudo make install; then
        log_error "Installation failed"
        cd - || return 1
        return 1
    fi
    
    # Return to original directory
    cd - || {
        log_error "Failed to return from SSCEP directory"
        return 1
    }
    
    # Verify installation
    if command -v sscep >/dev/null 2>&1; then
        log_success "SSCEP built and installed successfully"
        return 0
    else
        log_error "SSCEP installation verification failed"
        return 1
    fi
}

# Improved install_dependencies function with better error handling
install_dependencies() {
    log_info "Checking and installing dependencies..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would install required packages"
        return 0
    fi
    
    # Set up our temp directory structure
    setup_temp_dir
    
    # Skip updates if requested
    if [ "$NO_UPDATES" = "true" ]; then
        log_info "Updates disabled, skipping update check"
    else
        # Ask about system updates
        read -r -p "$(echo -e "${YELLOW}Would you like to check for and install system updates? (y/n) [n]:${NC} ")" UPDATE_SYSTEM
        if [[ "$UPDATE_SYSTEM" =~ ^[Yy]$ ]]; then
            log_info "Starting system update..."
            
            case $DISTRO in
                "rhel" | "centos" | "fedora")
                    sudo dnf clean all
                    sudo dnf check-update || true  # Don't fail if updates available
                    sudo dnf upgrade -y
                    ;;
                "ubuntu" | "debian")
                    # Try comprehensive APT repair first
                    fix_apt_completely
                    
                    # Don't try to upgrade, it's too error-prone
                    log_info "Update completed, skipping upgrade for stability"
                    ;;
                *)
                    log_warning "Unknown distribution: $DISTRO, skipping system update"
                    ;;
            esac
        else
            log_info "Skipping system updates"
        fi
    fi
    
    # Install common dependencies without updating package lists
    log_info "Installing common dependencies..."
    case $DISTRO in
        "rhel" | "centos" | "fedora")
            # Try to install without updating if possible
            if ! sudo dnf install -y --setopt=install_weak_deps=False curl openssl NetworkManager; then
                log_warning "Failed to install dependencies with dnf, will try with --nobest option"
                sudo dnf install -y --setopt=install_weak_deps=False --nobest curl openssl NetworkManager || {
                    log_error "Failed to install common dependencies"
                    log_info "Try manually: sudo dnf install -y curl openssl NetworkManager"
                    cleanup_temp_dir
                    exit 1
                }
            fi
            ;;
        "ubuntu" | "debian")
            # Try installing without update if no-updates is specified
            if ! sudo apt-get --allow-unauthenticated -y install curl openssl network-manager; then
                log_warning "Standard install failed, trying individual package installation"
                
                # Try installing packages one by one
                for pkg in curl openssl network-manager; do
                    sudo apt-get --allow-unauthenticated --force-yes -y install "$pkg" || true
                done
                
                # Check if the essential packages are now installed
                if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
                    log_error "Failed to install essential dependencies"
                    log_info "Try manually: sudo apt-get --allow-unauthenticated -y install curl openssl network-manager"
                    cleanup_temp_dir
                    exit 1
                fi
            fi
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            cleanup_temp_dir
            exit 1
            ;;
    esac
    
    # Check/install sscep (always check regardless of method)
    log_info "Checking for sscep..."
    if ! command -v sscep >/dev/null 2>&1; then
        log_info "Installing sscep..."
        case $DISTRO in
            "rhel" | "centos" | "fedora")
                # Install build dependencies
                log_info "Installing build dependencies..."
                if ! sudo dnf install -y git gcc make autoconf automake libtool pkgconfig openssl-devel; then
                    log_warning "Failed to install build dependencies through dnf, trying with yum..."
                    if ! sudo yum install -y git gcc make autoconf automake libtool pkgconfig openssl-devel; then
                        log_error "Failed to install build dependencies"
                        log_info "Try manually: sudo dnf install -y git gcc make autoconf automake libtool pkgconfig openssl-devel"
                        cleanup_temp_dir
                        exit 1
                    fi
                fi
                
                # Build SSCEP
                if ! build_sscep; then
                    log_error "Failed to build SSCEP from source"
                    cleanup_temp_dir
                    exit 1
                fi
                ;;
            "ubuntu" | "debian")
                # Try using apt-cache to check if sscep is available in repos
                if apt-cache search sscep 2>/dev/null | grep -q sscep; then
                    sudo apt-get --allow-unauthenticated -y install sscep || {
                        log_warning "Failed to install sscep from repositories, will try building from source"
                    }
                fi
                
                # If sscep is still not installed, build from source
                if ! command -v sscep >/dev/null 2>&1; then
                    # Install build dependencies
                    log_info "Installing build dependencies..."
                    if ! sudo apt-get --allow-unauthenticated -y install git gcc make libssl-dev autoconf automake libtool pkg-config; then
                        log_error "Failed to install build dependencies"
                        log_info "Try manually: sudo apt-get --allow-unauthenticated -y install git gcc make libssl-dev autoconf automake libtool pkg-config"
                        cleanup_temp_dir
                        exit 1
                    fi
                    
                    # Build SSCEP
                    if ! build_sscep; then
                        log_error "Failed to build SSCEP from source"
                        cleanup_temp_dir
                        exit 1
                    fi
                fi
                ;;
        esac
        
        if ! command -v sscep >/dev/null 2>&1; then
            log_error "Failed to install sscep"
            log_info "Manual sscep installation steps:"
            log_info "1. git clone https://github.com/certnanny/sscep.git /tmp/sscep"
            log_info "2. cd /tmp/sscep"
            log_info "3. autoreconf --install && ./configure && make && sudo make install"
            cleanup_temp_dir
            exit 1
        fi
        log_success "sscep installed successfully"
    else
        log_success "sscep already installed"
    fi
    
    # Check/install certmonger (always check regardless of method)
    log_info "Checking for certmonger..."
    if ! command -v getcert >/dev/null 2>&1; then
        # Only install certmonger if it will be used
        if [ "$ENROLLMENT_METHOD" = "certmonger" ]; then
            log_info "Installing certmonger..."
            case $DISTRO in
                "rhel" | "centos" | "fedora")
                    if ! sudo dnf install -y certmonger; then 
                        log_warning "Failed with dnf, trying yum"
                        if ! sudo yum install -y certmonger; then
                            log_error "Failed to install certmonger" 
                            log_info "Try manually: sudo dnf install -y certmonger"
                            cleanup_temp_dir
                            exit 1 
                        fi
                    fi
                    ;;
                "ubuntu" | "debian")
                    if ! sudo apt-get --allow-unauthenticated -y install certmonger; then
                        log_error "Failed to install certmonger"
                        log_info "Try manually: sudo apt-get --allow-unauthenticated -y install certmonger"
                        cleanup_temp_dir
                        exit 1
                    fi
                    ;;
            esac
            
            if ! command -v getcert >/dev/null 2>&1; then
                log_error "Failed to install certmonger"
                cleanup_temp_dir
                exit 1
            fi
            log_success "certmonger installed successfully"
        else
            log_info "certmonger not installed (not needed for direct method)"
        fi
    else
        log_success "certmonger already installed"
    fi
    
    log_success "All dependencies installed successfully"
}

# Download DigiCert Root CA
download_digicert_root_ca() {
    local digicert_url="https://www.digicert.com/CACerts/DigiCertTrustedRootG4.crt"
    
    log_info "Downloading DigiCert Root CA..."
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would download DigiCert Root CA from $digicert_url"
        return 0
    fi
    
    sudo mkdir -p /var/portnox
    local temp_file
    temp_file="$PORTNOX_TEMP_DIR/digicert_root.crt"
    
    if ! curl -s -L -o "$temp_file" "$digicert_url"; then
        log_error "Failed to download DigiCert CA"
        log_info "Manual download command: curl -L -o /var/portnox/digicert_root_ca.crt $digicert_url"
        rm -f "$temp_file"
        return 1
    fi
    
    if grep -q "BEGIN CERTIFICATE" "$temp_file" 2>/dev/null; then
        sudo cp "$temp_file" "$DIGICERT_PATH"
    else
        log_info "Converting DER format to PEM format..."
        if ! sudo openssl x509 -inform der -in "$temp_file" -out "$DIGICERT_PATH" 2>/dev/null; then
            log_error "Failed to convert DigiCert CA"
            log_info "Manual conversion command: sudo openssl x509 -inform der -in $temp_file -out $DIGICERT_PATH"
            rm -f "$temp_file"
            return 1
        fi
    fi
    
    if sudo openssl x509 -in "$DIGICERT_PATH" -text -noout >/dev/null 2>&1; then
        log_success "DigiCert Root CA saved to $DIGICERT_PATH"
        return 0
    else
        log_error "Downloaded certificate is invalid"
        return 1
    fi
}

# Retrieve CA certificate from SCEP server (suppressing sscep output)
retrieve_ca_certificate() {
    local scep_url="$1"
    log_info "Retrieving CA certificate from: $scep_url"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would retrieve CA certificate"
        return 0
    fi
    
    sudo mkdir -p /var/portnox
    
    # First try with sscep getca (with output redirected)
    if command -v sscep >/dev/null 2>&1; then
        log_info "Using sscep to retrieve CA certificate..."
        if sudo sscep getca -u "$scep_url" -c "$CA_CERT_PATH" -F >/dev/null 2>&1; then
            log_success "Successfully retrieved CA certificate using sscep"
            if sudo openssl x509 -in "$CA_CERT_PATH" -text -noout >/dev/null 2>&1; then
                log_success "CA certificate verified"
                return 0
            else
                log_warning "CA certificate format validation failed, trying alternative method"
            fi
        else
            log_warning "Failed to retrieve CA certificate with sscep, trying curl method"
        fi
    fi
    
    # Fallback to curl method with our temp directory
    local temp_file
    temp_file="$PORTNOX_TEMP_DIR/ca_cert.crt"
    local operation_url="${scep_url}?operation=GetCACert"
    
    log_info "Retrieving CA certificate via curl..."
    if ! curl -s -f -L -o "$temp_file" "$operation_url" 2>"$PORTNOX_TEMP_DIR/curl_ca.log"; then
        log_error "Failed to retrieve CA certificate with curl."
        if [ -f "$PORTNOX_TEMP_DIR/curl_ca.log" ]; then
            cat "$PORTNOX_TEMP_DIR/curl_ca.log"
        fi
        log_info "Manual retrieval command: curl -f -L -o $CA_CERT_PATH ${scep_url}?operation=GetCACert"
        return 1
    fi
    
    if [ ! -s "$temp_file" ]; then
        log_error "Retrieved CA certificate file is empty"
        return 1
    fi
    
    # Check format and convert if needed
    if grep -q "BEGIN CERTIFICATE" "$temp_file"; then
        log_info "Certificate is in PEM format"
        sudo cp "$temp_file" "$CA_CERT_PATH"
    else
        log_info "Certificate is in DER format, converting to PEM"
        if ! sudo openssl x509 -inform der -in "$temp_file" -out "$CA_CERT_PATH" 2>/dev/null; then
            log_error "Failed to convert certificate from DER to PEM"
            # Save raw format for debugging
            sudo cp "$temp_file" "$CA_CERT_PATH.raw"
            log_warning "Raw certificate saved to $CA_CERT_PATH.raw for debugging"
            log_info "Manual conversion command: sudo openssl x509 -inform der -in $temp_file -out $CA_CERT_PATH"
            return 1
        fi
    fi
    
    # Verify the certificate
    if sudo openssl x509 -in "$CA_CERT_PATH" -text -noout >/dev/null 2>&1; then
        log_success "CA certificate verified"
        return 0
    else
        log_error "CA certificate validation failed"
        log_info "To manually validate: sudo openssl x509 -in $CA_CERT_PATH -text -noout"
        return 1
    fi
}

# Clean up existing certificates and CAs
clean_certificates() {
    echo -e "\n${MAGENTA}=== Cleaning Certificates and CAs ===${NC}"
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would clean up certificates and CAs"
        return 0
    fi
    
    # Remove certificate files
    log_info "Removing client certificates and keys..."
    COUNT_CERTS=$(find /etc/certs/ -name "client-*.crt" -o -name "user-*.crt" -o -name "device-*.crt" 2>/dev/null | wc -l || echo "0")
    COUNT_KEYS=$(find /etc/certs/ -name "client-*.key" -o -name "user-*.key" -o -name "device-*.key" 2>/dev/null | wc -l || echo "0")
    
    sudo rm -f /etc/certs/client-*.crt /etc/certs/client-*.key 2>/dev/null || true
    sudo rm -f /etc/certs/user-*.crt /etc/certs/user-*.key 2>/dev/null || true
    sudo rm -f /etc/certs/device-*.crt /etc/certs/device-*.key 2>/dev/null || true
    
    log_success "Removed $COUNT_CERTS certificates and $COUNT_KEYS keys from /etc/certs/"
    
    # Remove CA certificates
    log_info "Removing CA certificates..."
    sudo rm -f "$CA_CERT_PATH" "$CA_CERT_PATH.raw" 2>/dev/null || true
    if [ -f "$DIGICERT_PATH" ]; then
        sudo rm -f "$DIGICERT_PATH" 2>/dev/null || true
        log_success "Removed DigiCert Root CA from $DIGICERT_PATH"
    fi
    
    # Remove certmonger CAs and requests if certmonger is installed
    if command -v getcert >/dev/null 2>&1; then
        log_info "Removing certmonger CAs and requests..."
        
        # Count existing CAs to remove
        CA_COUNT=0
        while read -r ca; do
            if [ -n "$ca" ]; then
                CA_COUNT=$((CA_COUNT + 1))
                sudo getcert remove-ca -c "$ca" 2>/dev/null || true
            fi
        done < <(sudo getcert list-cas 2>/dev/null | grep "Nickname: 'portnox-[a-zA-Z0-9-]*'" | sed "s/Nickname: '\(.*\)'/\1/" || echo "")
        
        log_success "Removed $CA_COUNT certmonger CAs"
        
        # Count and remove certificate tracking requests
        REQ_COUNT=0
        while read -r id; do
            if [ -n "$id" ]; then
                REQ_COUNT=$((REQ_COUNT + 1))
                sudo getcert stop-tracking -i "$id" 2>/dev/null || true
            fi
        done < <(sudo getcert list 2>/dev/null | grep "Request ID" | awk -F"'" '{print $2}' || echo "")
        
        log_success "Stopped tracking $REQ_COUNT certificate requests"
    else
        log_info "Certmonger not installed, no CAs or requests to remove"
    fi
    
    echo -e "${MAGENTA}=== Cleanup Complete ===${NC}\n"
}
# Direct enrollment with OpenSSL and sscep (with suppressed output)
direct_enroll_cert() {
    SCEP_URL=${SCEP_URL:-$DEFAULT_SCEP_URL}
    SCEP_SECRET=${SCEP_SECRET:-$DEFAULT_SCEP_SECRET}
    USER_OR_DEVICE=${USER_OR_DEVICE:-$DEFAULT_USER_OR_DEVICE}
    UNIQUE_ID=$(hostname)-$(date +%s)

    # Set default paths with naming based on user or device
    if [ "$USER_OR_DEVICE" = "user" ]; then
        CERT_NAME="user-$(whoami)"
    else
        CERT_NAME="device-$(hostname)"
    fi

    CERT_PATH=${CERT_PATH:-"/etc/certs/$CERT_NAME-$UNIQUE_ID.crt"}
    KEY_PATH=${KEY_PATH:-"/etc/certs/$CERT_NAME-$UNIQUE_ID.key"}

    log_info "Using ${YELLOW}direct enrollment${NC} with OpenSSL and sscep"
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would enroll certificate from $SCEP_URL"
        return 0
    fi

    # Create directories
    sudo mkdir -p /etc/certs /var/portnox
    sudo chmod 755 /etc/certs /var/portnox

    # Get CA certificate
    if ! retrieve_ca_certificate "$SCEP_URL"; then
        log_error "Failed to retrieve CA certificate, cannot proceed"
        log_info "Manual troubleshooting steps:"
        log_info "1. Check SCEP URL: $SCEP_URL"
        log_info "2. Verify network connectivity to SCEP server"
        log_info "3. Try manual command: sscep getca -u \"$SCEP_URL\" -c \"$CA_CERT_PATH\""
        exit 1
    fi

    # Generate key pair
    log_info "Generating RSA key pair..."
    if ! sudo openssl genrsa -out "$KEY_PATH" 2048 2>/dev/null; then
        log_error "Failed to generate RSA key"
        log_info "Manual key generation command: sudo openssl genrsa -out \"$KEY_PATH\" 2048"
        exit 1
    fi
    sudo chmod 600 "$KEY_PATH"
    log_success "Generated RSA key pair at $KEY_PATH"

    # Determine subject name
    if [ "$USER_OR_DEVICE" = "user" ]; then
        SUBJECT="CN=$(whoami)"
    else
        SUBJECT="CN=$(hostname)"
    fi

    # Create OpenSSL config with challenge password
    local openssl_conf
    openssl_conf="$PORTNOX_TEMP_DIR/openssl-$UNIQUE_ID.cnf"
    log_info "Creating OpenSSL config with challenge password..."

    cat > "$openssl_conf" << EOF
[req]
distinguished_name = req_dn
req_extensions = req_ext
attributes = req_attr
prompt = no

[req_dn]
$SUBJECT

[req_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth

[req_attr]
challengePassword = $SCEP_SECRET
EOF

    # Add SAN if specified
    if [ -n "$SAN" ]; then
        log_info "Adding Subject Alternative Name: $SAN"
        echo "subjectAltName = $SAN" >> "$openssl_conf"
    fi

    # Generate CSR
    local csr_path
    csr_path="$PORTNOX_TEMP_DIR/request-$UNIQUE_ID.csr"
    log_info "Generating CSR with embedded challenge password..."
    if ! sudo openssl req -new -key "$KEY_PATH" -config "$openssl_conf" -out "$csr_path" 2>/dev/null; then
        log_error "Failed to generate CSR"
        log_info "Manual CSR generation command: sudo openssl req -new -key \"$KEY_PATH\" -config \"$openssl_conf\" -out \"$csr_path\""
        sudo rm -f "$openssl_conf" "$csr_path"
        exit 1
    fi
    log_success "Generated CSR at $csr_path"

    # Show CSR details in verbose mode
    if [ "$VERBOSE" = true ]; then
        log_verbose "CSR Details:"
        sudo openssl req -in "$csr_path" -noout -text 2>/dev/null | while read -r line; do
            log_verbose "$line"
        done
    fi

    # Enroll using sscep with suppressed usage info
    log_info "Enrolling certificate with sscep..."
    local sscep_output
    sscep_output="$PORTNOX_TEMP_DIR/sscep_output.txt"

    if sudo sscep enroll -u "$SCEP_URL" -c "$CA_CERT_PATH" -k "$KEY_PATH" -r "$csr_path" -l "$CERT_PATH" -v > "$sscep_output" 2>&1; then
        # Output only important messages from sscep, not the usage info
        grep -v "Usage:" "$sscep_output" | grep -v "^$" | while read -r line; do
            log_info "SSCEP: $line"
        done
        log_success "Certificate enrollment successful!"
    else
        log_warning "Certificate enrollment failed. Retrying with debugging..."
        # Show the output for troubleshooting
        if [ -f "$sscep_output" ]; then
            cat "$sscep_output"
        fi

        if ! sudo sscep enroll -u "$SCEP_URL" -c "$CA_CERT_PATH" -k "$KEY_PATH" -r "$csr_path" -l "$CERT_PATH" -d -v > "$sscep_output" 2>&1; then
            if [ -f "$sscep_output" ]; then
                grep -v "Usage:" "$sscep_output" | grep -v "^$" | while read -r line; do
                    log_info "SSCEP DEBUG: $line"
                done
            fi
            log_error "Certificate enrollment failed after retry"
            log_info "Manual enrollment command: sudo sscep enroll -u \"$SCEP_URL\" -c \"$CA_CERT_PATH\" -k \"$KEY_PATH\" -r \"$csr_path\" -l \"$CERT_PATH\" -d -v"
            sudo rm -f "$openssl_conf" "$csr_path" "$sscep_output"
            exit 1
        fi
    fi

    sudo rm -f "$sscep_output"

    # Verify certificate
    if [ ! -s "$CERT_PATH" ] || ! sudo openssl x509 -in "$CERT_PATH" -noout -subject >/dev/null 2>&1; then
        log_error "Generated certificate is invalid or missing"
        log_info "Manual verification command: sudo openssl x509 -in \"$CERT_PATH\" -text -noout"
        sudo rm -f "$openssl_conf" "$csr_path"
        exit 1
    fi

    # Set proper permissions
    sudo chmod 644 "$CERT_PATH"

    # Clean up
    sudo rm -f "$openssl_conf" "$csr_path"

    # Show certificate info
    log_success "Certificate successfully enrolled:"
    echo -e "${CYAN}Certificate Subject:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null || echo "N/A")"
    echo -e "${CYAN}Certificate Issuer:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -issuer 2>/dev/null || echo "N/A")"
    echo -e "${CYAN}Certificate Validity:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -dates 2>/dev/null || echo "N/A")"

    return 0
}

# Certmonger enrollment with improved error handling
certmonger_enroll_cert() {
    SCEP_URL=${SCEP_URL:-$DEFAULT_SCEP_URL}
    SCEP_SECRET=${SCEP_SECRET:-$DEFAULT_SCEP_SECRET}
    USER_OR_DEVICE=${USER_OR_DEVICE:-$DEFAULT_USER_OR_DEVICE}
    UNIQUE_ID=$(hostname)-$(date +%s)

    # Set default paths with naming based on user or device
    if [ "$USER_OR_DEVICE" = "user" ]; then
        CERT_NAME="user-$(whoami)"
    else
        CERT_NAME="device-$(hostname)"
    fi

    CERT_PATH=${CERT_PATH:-"/etc/certs/$CERT_NAME-$UNIQUE_ID.crt"}
    KEY_PATH=${KEY_PATH:-"/etc/certs/$CERT_NAME-$UNIQUE_ID.key"}
    CA_NICK="portnox-$CERT_NAME-$UNIQUE_ID"

    log_info "Using ${YELLOW}certmonger enrollment${NC} method"
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would enroll certificate using certmonger"
        return 0
    fi

    # Create directories and secret file
    sudo mkdir -p /etc/certs
    sudo chmod 755 /etc/certs

    local secret_file
    secret_file="$PORTNOX_TEMP_DIR/portnox_scep_secret.txt"
    sudo bash -c "echo '$SCEP_SECRET' > '$secret_file'"
    sudo chmod 600 "$secret_file"
    log_info "Created secret file with challenge password"

    # Remove existing CAs with portnox prefix
    if sudo getcert list-cas 2>/dev/null | grep -q "portnox-"; then
        log_info "Removing existing Portnox CAs..."
        CA_COUNT=0
        while read -r ca; do
            if [ -n "$ca" ]; then
                CA_COUNT=$((CA_COUNT + 1))
                sudo getcert remove-ca -c "$ca" 2>/dev/null || true
            fi
        done < <(sudo getcert list-cas 2>/dev/null | grep "Nickname: 'portnox-[a-zA-Z0-9-]*'" | sed "s/Nickname: '\(.*\)'/\1/" || echo "")
        log_success "Removed $CA_COUNT existing Portnox CAs"
    fi

    # Get CA certificate
    if ! retrieve_ca_certificate "$SCEP_URL"; then
        log_error "Failed to retrieve CA certificate, cannot proceed"
        log_info "Manual troubleshooting steps:"
        log_info "1. Check SCEP URL: $SCEP_URL"
        log_info "2. Verify network connectivity to SCEP server"
        log_info "3. Try manual command: sscep getca -u \"$SCEP_URL\" -c \"$CA_CERT_PATH\""
        sudo rm -f "$secret_file"
        exit 1
    fi

    # Add CA to certmonger
    log_info "Adding CA to certmonger: $CA_NICK"
    if ! sudo getcert add-scep-ca -c "$CA_NICK" -u "$SCEP_URL" -R "$CA_CERT_PATH" 2>/dev/null; then
        log_error "Failed to add SCEP CA"
        log_info "Manual command: sudo getcert add-scep-ca -c \"$CA_NICK\" -u \"$SCEP_URL\" -R \"$CA_CERT_PATH\""
        sudo rm -f "$secret_file"
        exit 1
    fi
    log_success "Added CA to certmonger"

    # Set subject name
    if [ "$USER_OR_DEVICE" = "user" ]; then
        SUBJECT_NAME="CN=$(whoami)"
    else
        SUBJECT_NAME="CN=$(hostname)"
    fi

    # Set duration (1 year default)
    CERT_DURATION=${CERT_DURATION:-365}

    # Build request command
    REQUEST_CMD="sudo getcert request -c \"$CA_NICK\" \
        -l \"$secret_file\" \
        -k \"$KEY_PATH\" \
        -f \"$CERT_PATH\" \
        -N \"$SUBJECT_NAME\" \
        -u dataEncipherment -u digitalSignature \
        -U id-kp-clientAuth \
        -D $CERT_DURATION"

    # Add SAN if specified
    if [ -n "$SAN" ]; then
        REQUEST_CMD="$REQUEST_CMD -A \"$SAN\""
        log_info "Adding Subject Alternative Name: $SAN"
    fi

    # Request certificate
    log_info "Requesting certificate..."
    local request_output
    request_output="$PORTNOX_TEMP_DIR/request_output.txt"
    eval "$REQUEST_CMD" > "$request_output" 2>&1
    local request_id
    request_id=$(grep "New signing request" "$request_output" 2>/dev/null | sed 's/.*"\(.*\)".*/\1/' || echo "")

    if [ -z "$request_id" ]; then
        log_error "Failed to initiate certificate request"
        log_info "Review the command output for errors:"
        if [ -f "$request_output" ]; then
            cat "$request_output"
        fi
        log_info "Manual request command: $REQUEST_CMD"
        sudo rm -f "$secret_file"
        exit 1
    fi
    log_success "Certificate request initiated with ID: $request_id"

    # Wait for completion
    log_info "Waiting for certmonger to complete request $request_id..."
    local timeout=60
    local count=0

    while [ $count -lt $timeout ]; do
        local status
        status=$(sudo getcert list 2>/dev/null | grep -A 10 "Request ID '$request_id'" | grep "status:" | awk '{print $2}' || echo "PENDING")
        log_info "Status: ${YELLOW}${status:-PENDING}${NC}"

        if [ "$status" = "MONITORING" ] || [ "$status" = "ISSUED" ]; then
            if [ -f "$KEY_PATH" ] && [ -f "$CERT_PATH" ]; then
                sudo rm -f "$secret_file"
                break
            fi
        elif [ "$status" = "CA_UNREACHABLE" ] || [ "$status" = "REQUEST_REJECTED" ] || [ "$status" = "CA_REJECTED" ]; then
            log_error "Certificate request failed with status: $status"
            log_info "Troubleshooting steps:"
            log_info "1. Check SCEP server availability"
            log_info "2. Verify SCEP secret password"
            log_info "3. Check certmonger logs: sudo journalctl -u certmonger"
            sudo rm -f "$secret_file"
            exit 1
        fi

        sleep 1
        count=$((count + 1))
    done

    if [ $count -ge $timeout ]; then
        log_error "Timeout waiting for certificate"
        log_info "Manual check command: sudo getcert list -i \"$request_id\""
        log_info "You may need to increase the timeout value for slow servers"
        sudo getcert remove-ca -c "$CA_NICK" 2>/dev/null || true
        sudo rm -f "$secret_file"
        exit 1
    fi

    # Verify certificate
    if [ ! -s "$CERT_PATH" ] || ! sudo openssl x509 -in "$CERT_PATH" -noout -subject >/dev/null 2>&1; then
        log_error "Generated certificate is invalid or missing"
        log_info "Manual verification command: sudo openssl x509 -in \"$CERT_PATH\" -text -noout"
        exit 1
    fi

    # Set proper permissions
    sudo chmod 644 "$CERT_PATH"
    sudo chmod 600 "$KEY_PATH"

    # Show certificate info
    log_success "Certificate successfully enrolled:"
    echo -e "${CYAN}Certificate Subject:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null || echo "N/A")"
    echo -e "${CYAN}Certificate Issuer:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -issuer 2>/dev/null || echo "N/A")"
    echo -e "${CYAN}Certificate Validity:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -dates 2>/dev/null || echo "N/A")"

    return 0
}

# Configure network for 802.1X
configure_network() {
    INTERFACE=${INTERFACE:-$(nmcli device | grep -E "wifi|ethernet" | head -1 | awk '{print $1}')}
    IS_WIFI=$(nmcli device | grep "$INTERFACE" | grep -q "wifi" && echo "yes" || echo "no")
    CONN_NAME="8021x-$INTERFACE-$(date +%s)"
    CONN_FILE="/etc/NetworkManager/system-connections/$CONN_NAME.nmconnection"
    EAP_METHOD=${EAP_METHOD:-$DEFAULT_EAP_METHOD}
    IDENTITY=${IDENTITY:-"CN=$(hostname)"}

    if [ -z "$INTERFACE" ]; then
        log_error "No network interface specified or detected"
        log_info "Available interfaces:"
        nmcli device | grep -E "wifi|ethernet"
        exit 1
    fi

    if [ "$IS_WIFI" = "yes" ] && [ -z "$SSID" ]; then
        log_error "Wi-Fi SSID required but not provided"
        log_info "Available Wi-Fi networks:"
        nmcli device wifi list
        exit 1
    fi

    if [ "$DRY_RUN" = false ] && [ ! -f "$KEY_PATH" ]; then
        log_error "Private key $KEY_PATH not found"
        log_info "Please ensure the certificate enrollment completed successfully"
        exit 1
    fi

    log_info "Configuring NetworkManager connection: ${YELLOW}$CONN_NAME${NC} (not activating)"
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY RUN] Would create connection file at $CONN_FILE"
        return 0
    fi

    # Backup existing connection
    if [ -f "/etc/NetworkManager/system-connections/$INTERFACE.nmconnection" ]; then
        local backup_file
        backup_file="/etc/NetworkManager/system-connections/$INTERFACE.nmconnection.bak.$(date +%s)"
        sudo cp "/etc/NetworkManager/system-connections/$INTERFACE.nmconnection" "$backup_file"
        log_info "Backed up existing connection to $backup_file"
    fi

    # Create connection config
    local connection_config="[connection]\n"
    connection_config+="id=$CONN_NAME\n"
    connection_config+="type=$( [ "$IS_WIFI" = "yes" ] && echo "wifi" || echo "ethernet" )\n"
    connection_config+="interface-name=$INTERFACE\n"

    if [ "$IS_WIFI" = "yes" ]; then
        connection_config+="[wifi]\nssid=$SSID\n[wifi-security]\nkey-mgmt=wpa-eap\n"
    fi

    connection_config+="[802-1x]\neap=$EAP_METHOD\nidentity=$IDENTITY\nsystem-ca-certs=true\n"
    if [ "$EAP_METHOD" = "tls" ]; then
        connection_config+="ca-cert=$DIGICERT_PATH\nclient-cert=$CERT_PATH\nprivate-key=$KEY_PATH\n"
        [ -n "$KEY_PASSWORD" ] && connection_config+="private-key-password=$KEY_PASSWORD\n"
        connection_config+="password=none\n"
    elif [ "$EAP_METHOD" = "peap" ] || [ "$EAP_METHOD" = "ttls" ]; then
        connection_config+="phase2-auth=mschapv2\n"
        connection_config+="password=$EAP_PASSWORD\nca-cert=$DIGICERT_PATH\n"
    fi

    connection_config+="[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n"

    # Write config file
    sudo bash -c "printf \"$connection_config\" > \"$CONN_FILE\""
    sudo chmod 600 "$CONN_FILE"
    if ! sudo nmcli connection reload; then
        log_error "Failed to reload NetworkManager connections"
        log_info "Manual command: sudo nmcli connection reload"
        return 1
    fi

    log_success "Connection configuration created at $CONN_FILE"
    log_info "To activate: ${YELLOW}sudo nmcli connection up $CONN_NAME${NC}"
    log_info "To test: ${YELLOW}sudo nmcli connection up $CONN_NAME --ask${NC}"
    log_info "If manual configuration needed: ${YELLOW}nmcli connection edit $CONN_NAME${NC}"
}

# Validate certificate
validate_certificate() {
    echo -e "\n${MAGENTA}=== Certificate Validation ===${NC}"

    if [ ! -f "$CERT_PATH" ]; then
        log_error "Certificate file not found: $CERT_PATH"
        log_info "Specify the path to the certificate file using -c option or in the validation menu"
        return 1
    fi

    log_info "Validating certificate: $CERT_PATH"

    # Basic validation
    if ! sudo openssl x509 -in "$CERT_PATH" -noout >/dev/null 2>&1; then
        log_error "Invalid certificate format"
        log_info "Check if the file is a valid X.509 certificate"
        log_info "Manual check: sudo openssl x509 -in \"$CERT_PATH\" -text -noout"
        return 1
    fi
    log_success "Certificate format is valid"

    # Certificate details
    echo -e "${CYAN}Certificate Subject:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null || echo "N/A")"
    echo -e "${CYAN}Certificate Issuer:${NC} $(sudo openssl x509 -in "$CERT_PATH" -noout -issuer 2>/dev/null || echo "N/A")"

    # Validity period
    local not_before
    not_before=$(sudo openssl x509 -in "$CERT_PATH" -noout -startdate 2>/dev/null | cut -d= -f2 || echo "N/A")
    local not_after
    not_after=$(sudo openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "N/A")
    echo -e "${CYAN}Valid From:${NC} $not_before"
    echo -e "${CYAN}Valid Until:${NC} $not_after"

    # Check validity period
    if ! sudo openssl x509 -in "$CERT_PATH" -noout -checkend 0 >/dev/null 2>&1; then
        log_warning "Certificate is expired or not yet valid"
        log_info "Current date: $(date)"
        log_info "Certificate validity dates may not match your system time"
    else
        log_success "Certificate is currently valid"
    fi

    # Subject Alternative Names
    local san
    san=$(sudo openssl x509 -in "$CERT_PATH" -noout -ext subjectAltName 2>/dev/null | sed 's/.*://' || echo "None")
    echo -e "${CYAN}Subject Alternative Names:${NC} $san"

    # Check key match if key file provided
    if [ -f "$KEY_PATH" ]; then
        log_info "Checking certificate and key match..."
        local cert_modulus
        cert_modulus=$(sudo openssl x509 -in "$CERT_PATH" -noout -modulus 2>/dev/null | cut -d= -f2 || echo "")
        local key_modulus
        key_modulus=$(sudo openssl rsa -in "$KEY_PATH" -noout -modulus 2>/dev/null | cut -d= -f2 || echo "")

        if [ "$cert_modulus" = "$key_modulus" ] && [ -n "$cert_modulus" ] && [ -n "$key_modulus" ]; then
            log_success "Certificate and private key match verified"
        else
            log_warning "Certificate and private key do not match"
            log_info "Manual verification commands:"
            log_info "sudo openssl x509 -in \"$CERT_PATH\" -noout -modulus | md5sum"
            log_info "sudo openssl rsa -in \"$KEY_PATH\" -noout -modulus | md5sum"
            log_info "These commands should produce identical MD5 hashes if the key matches the certificate"
        fi
    else
        log_warning "Private key not provided, cannot verify key match"
        log_info "To check key match, provide the key path using KEY_PATH variable"
        log_info "or try: sudo openssl rsa -in <key_path> -noout -modulus"
    fi

    # Detailed certificate info in verbose mode
    if [ "$VERBOSE" = true ]; then
        log_verbose "Full Certificate Details:"
        sudo openssl x509 -in "$CERT_PATH" -text -noout 2>/dev/null | while read -r line; do
            log_verbose "$line"
        done
    else
        log_info "For full certificate details, use the verbose flag (-v) or run:"
        log_info "sudo openssl x509 -in \"$CERT_PATH\" -text -noout"
    fi

    echo -e "${MAGENTA}=== End of Certificate Validation ===${NC}\n"
    return 0
}

# Display summary
display_summary() {
    local width=70
    local border
    border="${GREEN}$(printf '=%.0s' $(seq 1 $width))${NC}"

    echo -e "\n$border"
    echo -e "${GREEN}|          802.1X Authentication Setup Summary           |${NC}"
    echo -e "$border"
    echo -e "${YELLOW}| Certificates:${NC}"
    echo -e "${BLUE}|   DigiCert Root CA:${NC} $DIGICERT_PATH"
    echo -e "${BLUE}|   Client Certificate:${NC} $CERT_PATH"
    echo -e "${BLUE}|   Private Key:${NC} $KEY_PATH"

    if [ -f "$CERT_PATH" ]; then
        local subject
        subject=$(sudo openssl x509 -in "$CERT_PATH" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "N/A")
        local issuer
        issuer=$(sudo openssl x509 -in "$CERT_PATH" -noout -issuer 2>/dev/null | sed 's/issuer=//' || echo "N/A")
        local valid_from
        valid_from=$(sudo openssl x509 -in "$CERT_PATH" -noout -startdate 2>/dev/null | cut -d= -f2 || echo "N/A")
        local valid_until
        valid_until=$(sudo openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2 || echo "N/A")

        # Fixed syntax by avoiding command substitution in variable assignment
        local validation="N/A"
        if sudo openssl x509 -in "$CERT_PATH" -noout -checkend 0 >/dev/null 2>&1; then
            validation="Currently valid"
        else
            validation="Expired/Not yet valid"
        fi

        echo -e "${YELLOW}| Certificate Details:${NC}"
        echo -e "${BLUE}|   Subject:${NC} $subject"
        echo -e "${BLUE}|   Issuer:${NC} $issuer"
        echo -e "${BLUE}|   Valid From:${NC} $valid_from"
        echo -e "${BLUE}|   Valid Until:${NC} $valid_until"
        echo -e "${BLUE}|   Validation:${NC} $validation"
        echo -e "${BLUE}|   Enrollment Method:${NC} $ENROLLMENT_METHOD"
    fi

    if [ -n "$CONN_NAME" ]; then
        local ip_addr
        ip_addr=$(ip addr show "$INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}' || echo "Not assigned")

        echo -e "${YELLOW}| Network Configuration:${NC}"
        echo -e "${BLUE}|   Connection Name:${NC} $CONN_NAME"
        echo -e "${BLUE}|   Config File:${NC} $CONN_FILE"
        echo -e "${BLUE}|   Interface:${NC} $INTERFACE (IP: $ip_addr)"
        echo -e "${YELLOW}| Activation:${NC}"
        echo -e "${BLUE}|   Command:${NC} sudo nmcli connection up $CONN_NAME"
    fi

    echo -e "${YELLOW}| Logs:${NC}"
    echo -e "${RED}|   Location:${NC} $LOG_FILE"

    echo -e "${YELLOW}| Troubleshooting:${NC}"
    echo -e "${BLUE}|   Debug:${NC} sudo $0 -v"
    echo -e "${BLUE}|   Menu:${NC} sudo $0 → Option 4"
    echo -e "${BLUE}|   Help:${NC} sudo $0 --help"

    echo -e "$border"
}

# Perform advanced troubleshooting
perform_troubleshooting() {
    echo -e "\n${MAGENTA}============== Enhanced Troubleshooting ===============${NC}"

    # Create debug report
    local DEBUG_FILE
    DEBUG_FILE="$PORTNOX_TEMP_DIR/portnox_debug_$(date +%Y%m%d_%H%M%S).log"
    log_info "Generating debug report at $DEBUG_FILE..."

    {
        echo "=== Portnox SCEP Debug Report ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo ""

        echo "=== System Information ==="
        uname -a
        cat /etc/os-release 2>/dev/null || echo "OS release info not available"
        echo ""

        echo "=== Certificate Files ==="
        ls -la /var/portnox/ 2>/dev/null || echo "/var/portnox/ not found"
        ls -la /etc/certs/ 2>/dev/null || echo "/etc/certs/ not found"

        if [ -f "$CA_CERT_PATH" ]; then
            echo "=== CA Certificate Details ==="
            openssl x509 -in "$CA_CERT_PATH" -text -noout 2>/dev/null || echo "Invalid CA certificate"
            echo ""
        fi

        if [ -f "$CERT_PATH" ]; then
            echo "=== Client Certificate Details ==="
            openssl x509 -in "$CERT_PATH" -text -noout 2>/dev/null || echo "Invalid client certificate"
            echo ""
        fi

        echo "=== Network Configuration ==="
        ip addr show
        nmcli device show
        nmcli connection show
        
        echo "=== SCEP Test ==="
        if command -v sscep >/dev/null 2>&1; then
            sscep --version 2>&1
            echo "Testing SCEP connection to $SCEP_URL (if set):"
            [ -n "$SCEP_URL" ] && curl -I "$SCEP_URL" 2>/dev/null || echo "SCEP_URL not set"
        else
            echo "sscep not installed"
        fi
        
        echo "=== System Status ==="
        df -h /
        free -m
        
        echo "=== Logs ==="
        tail -n 50 "$LOG_FILE" 2>/dev/null || echo "Log file not available"
        
        if [ "$ENROLLMENT_METHOD" = "certmonger" ]; then
            echo "=== Certmonger Status ==="
            sudo getcert list 2>/dev/null || echo "Certmonger list not available"
            sudo getcert list-cas 2>/dev/null || echo "Certmonger CAs not available"
        fi
        
        echo "=== Temporary Directory Status ==="
        ls -la "$PORTNOX_TEMP_DIR" 2>/dev/null || echo "Temp directory not found"
        df -h "$PORTNOX_TEMP_DIR" 2>/dev/null || echo "Temp directory filesystem info not available"
        
        echo "=== File Permissions ==="
        ls -la /etc/NetworkManager/system-connections/ 2>/dev/null || echo "NetworkManager connections not found"
        ls -la /var/tmp/ | grep portnox 2>/dev/null || echo "No Portnox temp directories found"
        
        echo "=== Network Connectivity Test ==="
        ping -c 3 8.8.8.8 2>/dev/null || echo "Internet connectivity test failed"
        
        echo "=== End of Debug Report ==="
    } > "$DEBUG_FILE"
    
    # Copy the debug file to a more accessible location
    sudo cp "$DEBUG_FILE" "/tmp/portnox_debug_$(date +%Y%m%d_%H%M%S).log"
    ACCESSIBLE_DEBUG_FILE="/tmp/portnox_debug_$(date +%Y%m%d_%H%M%S).log"
    sudo chmod 644 "$ACCESSIBLE_DEBUG_FILE"
    
    log_success "Debug report generated: $ACCESSIBLE_DEBUG_FILE"
    log_info "You can view it with: ${YELLOW}cat $ACCESSIBLE_DEBUG_FILE${NC}"
    
    # Display quick system status
    echo -e "\n${CYAN}Quick System Status:${NC}"
    echo -e "${YELLOW}Disk Space:${NC}"
    df -h / | tail -n 1
    
    echo -e "\n${YELLOW}Memory:${NC}"
    free -m | head -n 2
    
    echo -e "\n${YELLOW}Network Connectivity:${NC}"
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "Internet: ${GREEN}Connected${NC}"
    else
        echo -e "Internet: ${RED}Not Connected${NC}"
    fi
    
    echo -e "\n${YELLOW}Certificate Status:${NC}"
    if [ -f "$CERT_PATH" ]; then
        echo -e "Client Certificate: ${GREEN}Found${NC}"
        if sudo openssl x509 -in "$CERT_PATH" -noout -checkend 0 >/dev/null 2>&1; then
            echo -e "Validity: ${GREEN}Valid${NC}"
        else
            echo -e "Validity: ${RED}Invalid${NC}"
        fi
    else
        echo -e "Client Certificate: ${RED}Not Found${NC}"
    fi
    
    echo -e "\n${YELLOW}Temp Directory:${NC}"
    if [ -d "$PORTNOX_TEMP_DIR" ]; then
        echo -e "Status: ${GREEN}Created${NC}"
        echo -e "Path: $PORTNOX_TEMP_DIR"
        echo -e "Permissions: $(ls -ld "$PORTNOX_TEMP_DIR" 2>/dev/null | awk '{print $1}' || echo "N/A")"
    else
        echo -e "Status: ${RED}Not Found${NC}"
    fi
    
    echo -e "\n${YELLOW}Manual Troubleshooting Commands:${NC}"
    echo -e "1. Check certificate: ${CYAN}sudo openssl x509 -in $CERT_PATH -text -noout${NC}"
    echo -e "2. Test network: ${CYAN}sudo nmcli connection up $CONN_NAME${NC}"
    echo -e "3. Check NetworkManager: ${CYAN}sudo systemctl status NetworkManager${NC}"
    echo -e "4. Monitor authentication logs: ${CYAN}sudo tail -f /var/log/auth.log${NC}"
    echo -e "5. View debug report: ${CYAN}cat $ACCESSIBLE_DEBUG_FILE${NC}"
    
    echo -e "\n${MAGENTA}=======================================================${NC}\n"
}

# Show advanced help with examples (text-only version without ANSI codes)
show_advanced_help() {
    # Check if output is to a terminal - if not, disable colors
    local use_colors=true
    if [ ! -t 1 ]; then
        use_colors=false
    fi
    
    if [ "$use_colors" = true ]; then
        echo -e "${MAGENTA}=== PortScepifier Advanced Help ===${NC}"
        echo -e "\n${CYAN}Description:${NC}"
    else
        echo "=== PortScepifier Advanced Help ==="
        echo -e "\nDescription:"
    fi
    
    echo "  PortScepifier automates certificate enrollment via SCEP and 802.1X network"
    echo "  authentication setup. It supports two enrollment methods: direct (using OpenSSL"
    echo "  and sscep) and certmonger (using the certmonger service)."
    
    if [ "$use_colors" = true ]; then
        echo -e "\n${CYAN}Usage Examples:${NC}"
    else
        echo -e "\nUsage Examples:"
    fi
    
    echo "  1. Interactive setup with GUI:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh${NC}"
    else
        echo "     sudo ./PortSCepX.sh"
    fi
    
    echo "  2. Clean existing certificates then run setup:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh --clean${NC}"
    else
        echo "     sudo ./PortSCepX.sh --clean"
    fi
    
    echo "  3. Run in verbose mode to see detailed logs:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh -v${NC}"
    else
        echo "     sudo ./PortSCepX.sh -v"
    fi
    
    echo "  4. Simulation mode (no changes made):"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh -d${NC}"
    else
        echo "     sudo ./PortSCepX.sh -d"
    fi
    
    echo "  5. Use direct enrollment method:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh --direct${NC}"
    else
        echo "     sudo ./PortSCepX.sh --direct"
    fi
    
    echo "  6. Skip system updates check:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh --no-updates${NC}"
    else
        echo "     sudo ./PortSCepX.sh --no-updates"
    fi
    
    echo "  7. Fix APT repository issues before running:"
    if [ "$use_colors" = true ]; then
        echo -e "     ${GREEN}sudo ./PortSCepX.sh --fix-apt${NC}"
    else
        echo "     sudo ./PortSCepX.sh --fix-apt"
    fi
    
    if [ "$use_colors" = true ]; then
        echo -e "\n${CYAN}Troubleshooting:${NC}"
    else
        echo -e "\nTroubleshooting:"
    fi
    
    echo "  1. If you encounter apt/yum errors:"
    if [ "$use_colors" = true ]; then
        echo -e "     - Use ${GREEN}--fix-apt${NC} flag to repair repository issues"
        echo -e "     - Use ${GREEN}--no-updates${NC} flag to skip package updates"
        echo -e "     - Try running the troubleshooting tool: ${GREEN}sudo ./PortSCepX.sh${NC} → Option 4"
    else
        echo "     - Use --fix-apt flag to repair repository issues"
        echo "     - Use --no-updates flag to skip package updates"
        echo "     - Try running the troubleshooting tool: sudo ./PortSCepX.sh → Option 4"
    fi
    
    echo "  2. If certificate enrollment fails:"
    echo "     - Check internet connectivity"
    echo "     - Verify SCEP URL and secret"
    echo "     - Check certificate authority is reachable"
    echo "     - See manual enrollment steps below"
    
    echo "  3. If SSCEP installation fails:"
    echo "     - Make sure build dependencies are installed"
    echo "     - Use manual SSCEP installation from menu option 9"
    
    echo "  4. If network configuration fails:"
    if [ "$use_colors" = true ]; then
        echo -e "     - Check NetworkManager service is running: ${GREEN}sudo systemctl status NetworkManager${NC}"
    else
        echo "     - Check NetworkManager service is running: sudo systemctl status NetworkManager"
    fi
    echo "     - Ensure 802.1X authentication is supported by your network"
}

# Main menu function
display_menu() {
    while true; do
        echo -e "\n${GREEN}=== PortScepifier Menu ===${NC}"
        echo "1) Configure and Setup 802.1X"
        echo "2) Clean up certificates and CAs"
        echo "3) Validate existing certificate"
        echo "4) Run troubleshooting"
        echo "5) Check dependency versions"
        echo "6) Show advanced help"
        echo "7) List certificates and CAs"
        echo "8) Show manual enrollment steps"
        echo "9) Install SSCEP instructions"
        echo "10) Fix APT repository issues"
        echo "11) Exit"
        echo "===================="
        
        read -r -p "Enter a selection (1-11): " selection
        
        case $selection in
            1)
                # Initialize enrollment
                echo -e "\n${MAGENTA}=== Configure and Setup 802.1X ===${NC}"
                
                # Ask for enrollment method if not already set
                if [ -z "$ENROLLMENT_METHOD" ]; then
                    echo -e "\n${CYAN}Select certificate enrollment method:${NC}"
                    echo "1) Direct enrollment (OpenSSL + sscep)"
                    echo "2) Certmonger enrollment"
                    read -r -p "Select method (1-2) [1]: " method_choice
                    
                    case $method_choice in
                        2)
                            ENROLLMENT_METHOD="certmonger"
                            ;;
                        *)
                            ENROLLMENT_METHOD="direct"
                            ;;
                    esac
                fi
                
                # Ask for SCEP URL
                read -r -p "Enter SCEP URL [$DEFAULT_SCEP_URL]: " SCEP_URL
                SCEP_URL=${SCEP_URL:-$DEFAULT_SCEP_URL}
                
                # Validate URL
                if ! validate_url "$SCEP_URL"; then
                    continue
                fi
                
                # Ask for SCEP secret
                read -r -p "Enter SCEP challenge password [$DEFAULT_SCEP_SECRET]: " SCEP_SECRET
                SCEP_SECRET=${SCEP_SECRET:-$DEFAULT_SCEP_SECRET}
                
                # Ask for user or device enrollment
                echo -e "\n${CYAN}Enroll certificate for:${NC}"
                echo "1) Device (uses hostname as CN)"
                echo "2) User (uses username as CN)"
                read -r -p "Select (1-2) [1]: " user_device_choice
                
                case $user_device_choice in
                    2)
                        USER_OR_DEVICE="user"
                        ;;
                    *)
                        USER_OR_DEVICE="device"
                        ;;
                esac
                
                # Install dependencies
                install_dependencies
                
                # Download DigiCert root CA
                download_digicert_root_ca
                
                # Enroll certificate
                if [ "$ENROLLMENT_METHOD" = "certmonger" ]; then
                    certmonger_enroll_cert
                else
                    direct_enroll_cert
                fi
                
                # Configure network
                echo -e "\n${CYAN}Configure network for 802.1X:${NC}"
                echo "1) Configure now"
                echo "2) Skip network configuration"
                read -r -p "Select (1-2) [1]: " network_choice
                
                case $network_choice in
                    2)
                        log_info "Skipping network configuration"
                        ;;
                    *)
                        echo -e "\n${CYAN}Network Interface:${NC}"
                        nmcli device | grep -E "wifi|ethernet"
                        read -r -p "Enter interface name: " INTERFACE
                        
                        if [[ "$INTERFACE" == *"wifi"* ]] || [[ "$(nmcli device | grep "$INTERFACE" | grep -c "wifi")" -gt 0 ]]; then
                            read -r -p "Enter WiFi SSID: " SSID
                        fi
                        
                        echo -e "\n${CYAN}EAP Method:${NC}"
                        echo "1) TLS (certificate-based)"
                        echo "2) PEAP (username/password)"
                        echo "3) TTLS (username/password)"
                        read -r -p "Select method (1-3) [1]: " eap_choice
                        
                        case $eap_choice in
                            2)
                                EAP_METHOD="peap"
                                read -r -p "Enter username: " EAP_USERNAME
                                read -r -s -p "Enter password: " EAP_PASSWORD
                                echo ""
                                IDENTITY="$EAP_USERNAME"
                                ;;
                            3)
                                EAP_METHOD="ttls"
                                read -r -p "Enter username: " EAP_USERNAME
                                read -r -s -p "Enter password: " EAP_PASSWORD
                                echo ""
                                IDENTITY="$EAP_USERNAME"
                                ;;
                            *)
                                EAP_METHOD="tls"
                                # Use certificate subject as identity
                                if [ "$USER_OR_DEVICE" = "user" ]; then
                                    IDENTITY="CN=$(whoami)"
                                else
                                    IDENTITY="CN=$(hostname)"
                                fi
                                ;;
                        esac
                        
                        configure_network
                        ;;
                esac
                
                # Display summary
                display_summary
                ;;
            2)
                clean_certificates
                ;;
            3)
                if [ -z "$CERT_PATH" ]; then
                    read -r -p "Enter certificate path: " CERT_PATH
                fi
                if [ -z "$KEY_PATH" ]; then
                    read -r -p "Enter key path (optional): " KEY_PATH
                fi
                validate_certificate
                ;;
            4)
                perform_troubleshooting
                ;;
            5)
                check_dependency_versions
                ;;
            6)
                show_advanced_help
                ;;
            7)
                list_certificates_and_cas
                ;;
            8)
                show_manual_enrollment_steps
                ;;
            9)
                show_sscep_installation
                ;;
            10)
                echo -e "\n${MAGENTA}=== Fixing APT Repository Issues ===${NC}"
                fix_apt_completely
                echo -e "${MAGENTA}=== Fix Complete ===${NC}\n"
                ;;
            11)
                echo -e "\n${GREEN}Exiting PortScepifier. Goodbye!${NC}"
                cleanup_temp_dir
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid selection. Please try again.${NC}"
                ;;
        esac
    done
}

# Main function to process command line arguments
main() {
    # Process command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --advanced-help)
                show_advanced_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --direct)
                ENROLLMENT_METHOD="direct"
                shift
                ;;
            --certmonger)
                ENROLLMENT_METHOD="certmonger"
                shift
                ;;
            --clean)
                setup_temp_dir
                clean_certificates
                cleanup_temp_dir
                exit 0
                ;;
            --no-updates)
                NO_UPDATES=true
                shift
                ;;
            --fix-apt)
                setup_temp_dir
                fix_apt_completely
                cleanup_temp_dir
                exit 0
                ;;
            --list-certs)
                setup_temp_dir
                list_certificates_and_cas
                cleanup_temp_dir
                exit 0
                ;;
            --show-sscep-install)
                show_sscep_installation
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Load configuration
    load_config
    
    # Set up temp directory
    setup_temp_dir
    
    # Detect Linux distribution
    detect_distro
    
    # Display header
    display_header
    
    # Display interactive menu
    display_menu
}

# Call main function
main "$@"
