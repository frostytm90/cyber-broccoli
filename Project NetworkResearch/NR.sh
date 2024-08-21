#!/bin/bash

# Log file for debugging
DEBUG_LOG="debug.log"

# Function to check and install necessary applications
check_install() {
    for app in "$@"; do
        if ! command -v $app &> /dev/null; then
            echo "$app is not installed. Installing..." | tee -a $DEBUG_LOG
            sudo apt-get update | tee -a $DEBUG_LOG
            sudo apt-get install -y $app | tee -a $DEBUG_LOG
        else
            echo "$app is already installed." | tee -a $DEBUG_LOG
        fi
    done
}

# Function to install and configure Nipe
install_nipe() {
    if [ ! -d "nipe" ]; then
        sudo apt-get update | tee -a $DEBUG_LOG
        sudo apt-get install -y perl cpanminus git | tee -a $DEBUG_LOG
        sudo cpanm Switch JSON LWP::UserAgent | tee -a $DEBUG_LOG
        git clone https://github.com/htrgouvea/nipe | tee -a $DEBUG_LOG
        cd nipe
        sudo perl nipe.pl install | tee -a $DEBUG_LOG
        cd ..
    fi
}

# Function to start Nipe and check its status
start_nipe() {
    cd nipe
    sudo perl nipe.pl stop | tee -a $DEBUG_LOG
    sudo perl nipe.pl start | tee -a $DEBUG_LOG
    sleep 5
    status=$(sudo perl nipe.pl status | tee -a $DEBUG_LOG)
    echo "Nipe status output: $status" | tee -a $DEBUG_LOG
    connected=$(echo "$status" | grep "Status: true")
    if [ -z "$connected" ]; then
        echo "Failed to connect anonymously through Nipe. Exiting..." | tee -a $DEBUG_LOG
        exit 1
    fi
    IP=$(echo "$status" | grep "Ip:" | awk '{print $3}')
    country_response=$(curl -s http://ip-api.com/json/$IP)
    echo "Country response: $country_response" | tee -a $DEBUG_LOG
    COUNTRY=$(echo "$country_response" | jq -r '.country')
    if [ -z "$COUNTRY" ]; then
        echo "Failed to retrieve country information." | tee -a $DEBUG_LOG
        COUNTRY="Unknown"
    fi
    echo "Spoofed IP: $IP, Country: $COUNTRY" | tee -a $DEBUG_LOG
    cd ..
}

# Function to perform the scan on the remote server
perform_remote_scan() {
    local domain=$1
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_SERVER << EOF
        echo "Connected to remote server."
        mkdir -p $REMOTE_PATH
        echo "Scanning $domain..."
        nmap -A $domain -oN $REMOTE_PATH/scan_results.txt
        echo "Scan results saved to $REMOTE_PATH/scan_results.txt"
EOF

    if [ $? -ne 0 ]; then
        echo "SSH connection failed. Please check your SSH credentials." | tee -a $DEBUG_LOG
        exit 1
    fi

    sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_SERVER:$REMOTE_PATH/scan_results.txt $LOCAL_PATH/scan_results.txt

    if [ $? -ne 0 ]; then
        echo "Failed to retrieve scan results. Please check your SCP credentials." | tee -a $DEBUG_LOG
        exit 1
    fi

    echo "$(date): Scanned $domain. Results saved to $LOCAL_PATH/scan_results.txt" | sudo tee -a $LOG_FILE
    echo "Scan operation complete. Results saved to $LOCAL_PATH/scan_results.txt" | tee -a $DEBUG_LOG
}

# Step 1: Check and install necessary applications
check_install curl jq sshpass nmap tor

# Step 2: Install and configure Nipe
install_nipe

# Step 2.1: Start Nipe and display spoofed IP and country
start_nipe

# Step 3: Get user input for the domain/URL to scan
read -p "Enter the domain/URL to scan: " domain

# SSH connection details
REMOTE_USER="tc"
REMOTE_SERVER="192.168.232.129"
REMOTE_PATH="/home/$REMOTE_USER/scan_results" # Update this path to ensure the remote user has write permissions
LOCAL_PATH="/home/$USER/scan_results"         # Update this path to ensure it exists and is writable
LOG_FILE="/var/log/domain_scan.log"
SSH_PASS="tc"

# Step 4: Ensure local directory exists
mkdir -p $LOCAL_PATH

# Step 5: Perform the scan on the remote server
perform_remote_scan $domain
