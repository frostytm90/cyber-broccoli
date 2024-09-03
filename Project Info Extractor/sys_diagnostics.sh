#!/bin/bash

# Above this is called 'Shebang' line, it tells the system what interpreter to use to run the commands written within this script.

# Below is a separator function for visual separation between sections for easier reading

separator () {
	echo "---------- ---------- ----------"
}

# The first command will be ran to get and display your external/public IP Address.
public_ip=$(curl -s ifconfig.io)
separator
	echo "Your External/Public IP Address is: $public_ip"
# The second command will be ran to get and display your internal/private IP Address.
private_ip=$(ip addr show | grep -Eo 'inet [0-9.]+' | grep -v '127.0.0.1' | awk '{print $2}')
separator
	echo "Your Internal/Private IP Address is: $private_ip"

# The third command will be ran to get and display your MAC Address
mac_add=$(ip addr show | grep link/ether | awk '{print $2}' | awk -F: '{print $1 ":XX:XX:" $4 ":" $5 ":" $6}')
separator	
	echo "Your MAC Address is: $mac_add"

# The fourth command will be ran to get and display the top 5 CPU Processes
separator
echo "Below are the top 5 processes retrived from your CPU"
ps aux --sort=%cpu | head -n 6

# The fifth command will be ran to get and display the Memory Usage on the device
separator
echo "Memory Usage:"
free -h

# The sixth command will be ran to get and display the Active Services on the device
separator
echo "Active Services and Status:"
systemctl list-units --type=service --state=active --no-pager

# The seventh and final command will be ran to get and display the Top 10 largest files in the /home directory
separator
echo "Top 10 Largest File in the /home directory:"
find "$HOME" -type f -exec du -h {} + | sort -rh | head -n 10

