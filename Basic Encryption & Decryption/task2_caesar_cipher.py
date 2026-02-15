def caesar_cipher(text, shift, mode='encrypt'):
    """
    Performs encryption or decryption on a string using the Caesar Cipher.
    """
    result = ""
    
    # Adjust shift for decryption to move backwards
    if mode == 'decrypt':
        shift = -shift
        
    for char in text:
        if char.isupper():
            shifted_char = chr((ord(char) - 65 + shift) % 26 + 65)
            result += shifted_char
        elif char.islower():
            shifted_char = chr((ord(char) - 97 + shift) % 26 + 97)
            result += shifted_char
        else:
            result += char
            
    return result

def main():
    print("=========================================")
    print("   ADVANCED ENCRYPTION/DECRYPTION TOOL   ")
    print("=========================================")
    
    while True:
        print("\nAVAILABLE MODES:")
        print("[1] Encrypt Text")
        print("[2] Decrypt Text")
        print("[3] Exit Program")
        
        choice = input("\nSelect an operation (1/2/3): ").strip()
        
        # 1. Control Flow: Exit condition
        if choice == '3':
            print("Terminating session. Keep your keys secure, boss.")
            break
            
        # 2. Control Flow: Invalid menu selection
        elif choice not in ['1', '2']:
            print("[!] ERROR: Invalid selection. Read the menu and try again.")
            continue
            
        # Determine the mode based on the valid choice
        mode = 'encrypt' if choice == '1' else 'decrypt'
        
        text = input(f"\nEnter the text to {mode}: ")
        
        # 3. Input Validation: Forcing an integer shift key
        while True:
            try:
                shift = int(input("Enter the shift key (integer value): "))
                break # Exit the validation loop if successful
            except ValueError:
                print("[!] ERROR: The shift key must be a whole number. Try again.")
                
        # Execute the cipher logic
        output = caesar_cipher(text, shift, mode)
        
        # Display the targeted output
        print("\n" + "-"*30)
        print("          RESULTS          ")
        print("-" * 30)
        print(f"Original Text : {text}")
        print(f"Active Mode   : {mode.upper()}")
        print(f"Shift Key     : {shift}")
        print(f"Final Output  : {output}")
        print("-" * 30)

if __name__ == "__main__":
    main()