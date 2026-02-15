import re

def analyze_phishing_email(email_text):
    """
    Analyzes an email string for phishing indicators based on keywords and unsafe URLs.
    """
    red_flags = []
    
    # 1. Identify suspicious keywords
    suspicious_keywords = [
        'urgent', 'verify', 'suspend', 'password', 
        'click here', 'account closed', 'immediate action'
    ]
    email_lower = email_text.lower()
    
    for word in suspicious_keywords:
        if word in email_lower:
            red_flags.append(f"Suspicious Keyword Detected: '{word}'")
            
    # 2. Identify suspicious links using Regular Expressions
    # This regex finds anything starting with http:// or https://
    links = re.findall(r'(https?://[^\s]+)', email_text)
    
    for link in links:
        # Flag 1: Insecure protocol
        if link.startswith('http://'):
            red_flags.append(f"Unsafe Link Protocol (HTTP instead of HTTPS): {link}")
            
        # Flag 2: IP address instead of domain name (e.g., http://192.168.1.1/login)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link):
            red_flags.append(f"Suspicious IP-based Link (Obfuscated destination): {link}")

    # 3. List red flags found and explain why the message is unsafe
    print("\n=========================================")
    print("       PHISHING AWARENESS ANALYSIS       ")
    print("=========================================")
    
    if red_flags:
        print("[!] STATUS: DANGER - PHISHING ATTEMPT DETECTED [!]\n")
        print("Identified Red Flags:")
        for flag in red_flags:
            print(f" - {flag}")
            
        print("\nExplanation of Risk:")
        print("This message uses psychological manipulation (urgency/fear) alongside unsafe routing. ")
        print("Clicking these links or complying with the demands is highly unsafe and will likely ")
        print("lead to credential harvesting, identity theft, or malware injection into the system.")
    else:
        print("[+] STATUS: SAFE - No obvious phishing indicators detected.")
        print("Note: Always remain vigilant. Automated heuristic tools do not catch zero-day attacks.")
    print("=========================================\n")

def main():
    print("--- AUTOMATED PHISHING EMAIL ANALYZER ---")
    print("Paste the suspicious email text below.")
    print("Type 'ANALYZE' on a new line when finished pasting.\n")
    
    email_lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'ANALYZE':
                break
            email_lines.append(line)
        except EOFError:
            break
            
    email_text = '\n'.join(email_lines)
    
    if email_text.strip() == "":
        print("Error: No text provided. Shutting down.")
        return
        
    analyze_phishing_email(email_text)

if __name__ == "__main__":
    main()