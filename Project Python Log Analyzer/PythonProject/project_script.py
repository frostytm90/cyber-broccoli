import re
from datetime import datetime

# Regular expressions for parsing auth.log
command_regex = r"^(\S+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+server\s+sudo\[(\d+)\]:\s+(\S+)\s+:\s+TTY=pts/\d+\s+;\s+PWD=\S+\s+;\s+USER=\S+\s+;\s+COMMAND=(.+)$"
user_regex = r"^(\S+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+server\s+(useradd|userdel|passwd|su|sudo)\[(\d+)\]:\s+(.*)$"
sudo_command_regex = r"^(\S+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+server\s+sudo\[(\d+)\]:\s+(\S+)\s+:\s+TTY=pts/\d+\s+;\s+PWD=\S+\s+;\s+USER=root\s+;\s+COMMAND=(.+)$"
sudo_failure_regex = r"^(\S+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+server\s+sudo\[(\d+)\]:\s+pam_unix\(sudo:auth\):\s+authentication\s+failure;\s+logname=\S+\s+uid=\d+\s+euid=\d+\s+tty=\S+\s+ruser=\S*\s+rhost=\S+\s+user=(\S+)$"
hydra_attack_regex = r"^(\S+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+server\s+sshd\[(\d+)\]:\s+(Failed|Accepted)\s+password\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2$"

current_year = 2024  # Assuming logs are from the year 2024

log_entries = []

def parse_line(line):
    # Parse command usage
    match = re.match(command_regex, line)
    if match:
        timestamp_str = f"{current_year} {match.group(1)} {match.group(2)} {match.group(3)}"
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
        user = match.group(5)
        command = match.group(6)
        return (timestamp, f"Command Log - Timestamp: {timestamp}, User: {user}, Command: {command}\n")

    # Monitor user authentication changes
    match = re.match(user_regex, line)
    if match:
        timestamp_str = f"{current_year} {match.group(1)} {match.group(2)} {match.group(3)}"
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
        event = match.group(4)
        details = match.group(6)
        if event == "useradd":
            return (timestamp, f"User Add - Timestamp: {timestamp}, New user added: {details}\n")
        elif event == "userdel":
            return (timestamp, f"User Delete - Timestamp: {timestamp}, User removed: {details}\n")
        elif event == "passwd":
            return (timestamp, f"Password Change - Timestamp: {timestamp}, Password changed: {details}\n")
        elif event == "sudo":
            return (timestamp, f"ALERT!!!! sudo Command - Timestamp: {timestamp}, User used sudo command: {details}\n")

    # Monitor sudo command usage
    match = re.match(sudo_command_regex, line)
    if match:
        timestamp_str = f"{current_year} {match.group(1)} {match.group(2)} {match.group(3)}"
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
        user = match.group(6)
        command = match.group(7)
        return (timestamp, f"sudo Command - Timestamp: {timestamp}, User: {user}, Command: {command}\n")

    # Monitor failed sudo attempts
    match = re.match(sudo_failure_regex, line)
    if match:
        timestamp_str = f"{current_year} {match.group(1)} {match.group(2)} {match.group(3)}"
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
        user = match.group(7)
        return (timestamp, f"ALERT! Failed sudo - Timestamp: {timestamp}, User: {user}, Command: sudo command failed\n")

    # Monitor Hydra attack logs
    match = re.match(hydra_attack_regex, line)
    if match:
        timestamp_str = f"{current_year} {match.group(1)} {match.group(2)} {match.group(3)}"
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
        except ValueError:
            return None
        status = match.group(5)
        target_user = match.group(6)
        ip_address = match.group(7)
        port = match.group(8)
        if status == "Failed":
            return (timestamp, f"Hydra Attack - Failed login attempt - Timestamp: {timestamp}, User: {target_user}, IP: {ip_address}, Port: {port}\n")
        elif status == "Accepted":
            return (timestamp, f"Hydra Attack - Successful login - Timestamp: {timestamp}, User: {target_user}, IP: {ip_address}, Port: {port}\n")

    return None

# Open the auth.log file
with open('/home/kali/PythonProject/simulated_auth.log', 'r') as infile:
    for line in infile:
        entry = parse_line(line)
        if entry:
            log_entries.append(entry)

# Sort log entries by timestamp (date and time)
log_entries.sort(key=lambda x: x[0])

# Print out the entries before writing to the file
for entry in log_entries:
    print(f"Writing entry: {entry}")

# Write sorted log entries to the output file
with open('/home/kali/PythonProject/parsed_logs.txt', 'w') as outfile:
    for entry in log_entries:
        outfile.write(entry[1])

print("Finished writing to parsed_logs.txt")
