import string

def check_password_strength(password):
    """
    Evaluates the strength of a given password based on length, 
    uppercase, numbers, and symbols.
    """
    # Initialize our condition flags to False
    has_upper = False
    has_lower = False
    has_digit = False
    has_symbol = False
    
    # 1. Check Password Length
    length = len(password)
    
    # 2. String handling and condition checks via iteration
    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif char in string.punctuation:
            has_symbol = True

    # Calculate a score based on how many conditions are met
    score = 0
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_symbol: score += 1

    # 3. Evaluate Strength based on score and length
    # A strong password must be long AND complex
    if length >= 12 and score >= 4:
        return "STRONG"
    # A medium password has decent length and some complexity
    elif length >= 8 and score >= 3:
        return "MEDIUM"
    # Anything else is weak garbage
    else:
        return "WEAK"

def main():
    print("--- PASSWORD STRENGTH CHECKER ---")
    print("Enter a password to evaluate its strength.")
    print("Type 'exit' to quit the program.\n")
    
    while True:
        user_input = input("Password: ")
        
        if user_input.lower() == 'exit':
            print("Exiting program. Goodbye, boss.")
            break
            
        strength = check_password_strength(user_input)
        
        # Display password strength result
        if strength == "STRONG":
            print(f"Result: {strength} - Excellent. This meets security standards.\n")
        elif strength == "MEDIUM":
            print(f"Result: {strength} - Acceptable, but could be better. Consider adding more symbols or length.\n")
        else:
            print(f"Result: {strength} - Pathetic. This will be brute-forced in seconds.\n")

if __name__ == "__main__":
    main()