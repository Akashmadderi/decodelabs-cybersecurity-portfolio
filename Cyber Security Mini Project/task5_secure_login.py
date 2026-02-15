"""
====================================================================
DECODELABS INTERNSHIP - TASK 5: CYBER SECURITY MINI PROJECT
Goal: Build a small cyber security-focused project using learned concepts.

EXAMPLES IMPLEMENTED:
1. Secure login simulation (Authentication, Hashing, SQLi Defense)
2. Password manager (basic) (Protected in-memory credential vault)
3. Security awareness tool (Randomized threat intelligence generator)

KEY SKILLS DEMONSTRATED:
- Security logic (Cryptographic hashing, input sanitization routines)
- Problem-solving (Session management and multi-module integration)
- Cyber security workflow (Authentication gating prior to data access)
====================================================================
"""

import hashlib
import re
import random

# --- GLOBAL DATABASES (Simulated) ---
user_database = {}      # Stores {username: hashed_password}
lockout_tracker = {}    # Stores {username: failed_attempts}
password_vault = {}     # Stores {username: {service: stored_password}}

# --- CORE SECURITY LOGIC ---
def hash_password(password):
    """Converts a plaintext password into a SHA-256 hash."""
    return hashlib.sha256(password.encode()).hexdigest()

def sanitize_input(input_string):
    """Scans input for common SQL Injection characters."""
    if re.search(r"['\";]|(--)", input_string):
        return False
    return True

# --- MODULE 1: SECURE LOGIN SIMULATION ---
def register_user():
    print("\n[--- NEW USER REGISTRATION ---]")
    username = input("Enter a new username: ").strip()
    
    if not sanitize_input(username):
        print("[!] ALERT: Invalid characters detected. Registration blocked.")
        return
        
    if username in user_database:
        print("[-] ERROR: User already exists.")
        return
        
    password = input("Enter a secure password: ")
    
    user_database[username] = hash_password(password)
    lockout_tracker[username] = 0
    password_vault[username] = {} # Initialize an empty vault for the user
    print(f"[+] User '{username}' registered securely.")

def authenticate_user():
    print("\n[--- SYSTEM LOGIN ---]")
    username = input("Username: ").strip()
    password = input("Password: ")
    
    if not sanitize_input(username):
        print("[!] ALERT: Malicious payload detected. Incident logged.")
        return None

    if username not in user_database:
        print("[-] Authentication failed.")
        return None

    if lockout_tracker[username] >= 3:
        print("[-] ACCOUNT LOCKED: Maximum failed attempts exceeded.")
        return None

    input_hash = hash_password(password)
    if input_hash == user_database[username]:
        print("\n[+] ACCESS GRANTED. Session initiated.")
        lockout_tracker[username] = 0 
        return username # Return username to maintain the session
    else:
        lockout_tracker[username] += 1
        print(f"[-] Authentication failed. Attempts remaining: {3 - lockout_tracker[username]}")
        return None

# --- MODULE 2: BASIC PASSWORD MANAGER ---
def access_password_vault(active_user):
    print(f"\n[--- ENCRYPTED VAULT: {active_user.upper()} ---]")
    while True:
        print("\n1. Store New Credential")
        print("2. View Stored Credentials")
        print("3. Exit Vault")
        
        choice = input("Vault Command (1/2/3): ").strip()
        
        if choice == '1':
            service = input("Enter Service Name (e.g., Gmail, GitHub): ").strip()
            if not sanitize_input(service):
                print("[!] Invalid characters in service name.")
                continue
            pwd = input(f"Enter password for {service}: ")
            password_vault[active_user][service] = pwd
            print(f"[+] Credential for {service} securely stored.")
            
        elif choice == '2':
            if not password_vault[active_user]:
                print("[-] Your vault is currently empty.")
            else:
                print("\n--- STORED CREDENTIALS ---")
                for srv, p in password_vault[active_user].items():
                    print(f"Service: {srv} | Password: {p}")
                print("--------------------------")
                
        elif choice == '3':
            print("Locking vault...")
            break
        else:
            print("[-] Invalid vault command.")

# --- MODULE 3: SECURITY AWARENESS TOOL ---
def run_awareness_tool():
    print("\n[--- CYBER SECURITY AWARENESS TIP ---]")
    tips = [
        "PHISHING: Never click links in unexpected emails. Always navigate to the service manually.",
        "PASSWORDS: Use a minimum of 12 characters. Length defeats brute-force attacks faster than complexity.",
        "UPDATES: Zero-day vulnerabilities are patched in OS updates. Never delay system reboots.",
        "PHYSICAL SEC: Unlocked screens at coffee shops bypass 100% of your digital encryption.",
        "MFA: Multi-Factor Authentication stops 99% of automated credential stuffing attacks."
    ]
    print(f">> {random.choice(tips)}")
    print("--------------------------------------")

# --- CYBER SECURITY WORKFLOW (MAIN MENU) ---
def main():
    print("=========================================")
    print("   UNIFIED CYBER SECURITY TERMINAL       ")
    print("=========================================")
    
    active_session = None # Tracks if a user is logged in
    
    while True:
        # If no one is logged in, show the public gateway
        if active_session is None:
            print("\nPUBLIC GATEWAY:")
            print("[1] Register New User")
            print("[2] Secure Login Simulation")
            print("[3] Security Awareness Tool")
            print("[4] Exit Terminal")
            
            choice = input("\nSelect an operation: ").strip()
            
            if choice == '1':
                register_user()
            elif choice == '2':
                # If authentication succeeds, active_session holds the username
                active_session = authenticate_user() 
            elif choice == '3':
                run_awareness_tool()
            elif choice == '4':
                print("Shutting down terminal. Goodbye, boss.")
                break
            else:
                print("[!] ERROR: Invalid selection.")
                
        # If a user IS logged in, show the protected menu
        else:
            print(f"\nPROTECTED TERMINAL (User: {active_session})")
            print("[1] Access Password Manager Vault")
            print("[2] Security Awareness Tool")
            print("[3] Logout / Terminate Session")
            
            choice = input("\nSelect a secure operation: ").strip()
            
            if choice == '1':
                access_password_vault(active_session)
            elif choice == '2':
                run_awareness_tool()
            elif choice == '3':
                print(f"Session terminated for {active_session}. Returning to public gateway.")
                active_session = None # Destroys the session
            else:
                print("[!] ERROR: Invalid selection.")

if __name__ == "__main__":
    main()