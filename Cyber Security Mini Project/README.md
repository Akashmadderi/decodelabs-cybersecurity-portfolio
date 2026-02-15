# Decodelabs Cyber Security Internship - Final Portfolio

## Overview
This repository contains my final capstone submission for the Decodelabs Cyber Security Internship. The project demonstrates an understanding of core cyber-security concepts through a unified, interactive terminal application. 

## Task 5: Cyber Security Mini Project (Capstone)
**File:** `task5_secure_login.py`

### Project Scope
This application utilizes a monolithic architecture to integrate multiple security modules into a single, session-based environment. It addresses the following conceptual modules:
* **Authentication Gateway:** A simulated login environment utilizing SHA-256 cryptographic hashing, active SQL Injection (SQLi) sanitization, and brute-force lockout trackers.
* **Encrypted Vault:** A credential manager that is strictly inaccessible until a user successfully passes the secure authentication gateway.
* **Threat Intelligence Tool:** An integrated utility dispensing actionable cyber-security tips to educate the operator on modern attack vectors.

### Technical Skills Demonstrated
* **Applied Security Logic:** Implemented through robust input validation, cryptographic hashing, and automated defense mechanisms against common web vulnerabilities.
* **Problem Resolution:** Demonstrated by engineering a stateful application that manages user sessions and seamlessly integrates multiple functional modules.
* **Workflow Management:** Architected a strict gateway model ensuring that authorization and data access are rigidly gated behind successful authentication protocols.

### Execution Instructions
1. Open a terminal or IDE console.
2. Run the unified script using the command: `python task5_secure_login.py`
3. **Public Gateway Phase**: 
   - Press `1` to register a new secure account.
   - Press `2` to authenticate and initiate a secure session.
   - Press `3` to run the standalone threat intelligence tool.
4. **Protected Terminal Phase**: 
   - Upon successful authentication, your session state elevates. 
   - Press `1` to interact with your secure password vault (store and retrieve credentials).
   - Press `3` to securely log out, terminate the active session, and return to the public gateway.
5. Select the exit command from the public gateway to terminate the program completely.