import re

def check_password_strength(password):

    def has_uppercase(password):
        return any(char.isupper() for char in password)

    def has_lowercase(password):
        return any(char.islower() for char in password)

    def has_numbers(password):
        return any(char.isdigit() for char in password)

    def has_special_characters(password):
        return bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    strength = 0
    criteria = {
        "length": len(password) >= 8,
        "uppercase": has_uppercase(password),
        "lowercase": has_lowercase(password),
        "numbers": has_numbers(password),
        "special_characters": has_special_characters(password)
    }

    # Evaluate strength based on criteria
    for key, passed in criteria.items():
        if passed:
            strength += 1

    # Provide feedback
    if strength == 5:
        return "Strong password"
    elif strength >= 3:
        return "Moderate password"
    else:
        return "Weak password"


def main():
    print("Welcome to the Password Strength Checker!")
    password = input("Enter a password to test: ")
    result = check_password_strength(password)
    print(f"Password strength: {result}")


if __name__ == "__main__":
    main()
