import re
import hashlib
import math
import random
import string
import requests


class PasswordChecker:
    def __init__(self, min_length=8, require_uppercase=True, require_lowercase=True,
                 require_numbers=True, require_special=True):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_numbers = require_numbers
        self.require_special = require_special

    def _has_uppercase(self, password):
        return any(char.isupper() for char in password)

    def _has_lowercase(self, password):
        return any(char.islower() for char in password)

    def _has_numbers(self, password):
        return any(char.isdigit() for char in password)

    def _has_special_characters(self, password):
        return bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    def check_strength(self, password):
        """Check password strength against predefined criteria."""
        criteria = {
            "length": len(password) >= self.min_length,
            "uppercase": self._has_uppercase(password) if self.require_uppercase else True,
            "lowercase": self._has_lowercase(password) if self.require_lowercase else True,
            "numbers": self._has_numbers(password) if self.require_numbers else True,
            "special_characters": self._has_special_characters(password) if self.require_special else True,
        }

        strength = sum(criteria.values())

        feedback = self._get_feedback(criteria)
        if strength == len(criteria):
            return "Strong password 💪", feedback
        elif strength >= len(criteria) - 1:
            return "Moderate password ⚠️", feedback
        else:
            return "Weak password 😟", feedback

    def _get_feedback(self, criteria):
        """Provide feedback on which criteria the password fails."""
        feedback = []
        if not criteria["length"]:
            feedback.append(f"Password must be at least {self.min_length} characters long.")
        if not criteria["uppercase"]:
            feedback.append("Add at least one uppercase letter.")
        if not criteria["lowercase"]:
            feedback.append("Add at least one lowercase letter.")
        if not criteria["numbers"]:
            feedback.append("Include at least one number.")
        if not criteria["special_characters"]:
            feedback.append("Add at least one special character (!@#$%^&*...).")
        return feedback

    def check_breach(self, password):
        """Check if the password has been part of a known data breach."""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5, tail = sha1_password[:5], sha1_password[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")
        if response.status_code == 200 and tail in response.text:
            return True
        return False

    def calculate_entropy(self, password):
        """Calculate the entropy of the password."""
        charset_size = 0
        if self._has_lowercase(password):
            charset_size += 26
        if self._has_uppercase(password):
            charset_size += 26
        if self._has_numbers(password):
            charset_size += 10
        if self._has_special_characters(password):
            charset_size += len("!@#$%^&*(),.?\":{}|<>")
        entropy = len(password) * math.log2(charset_size)
        return entropy

    def suggest_password(self, length=12):
        """Generate a strong password suggestion."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.choice(chars) for _ in range(length))


# Example Usage
if __name__ == "__main__":
    checker = PasswordChecker()

    print("Welcome to the Password Strength Checker!")
    password = input("Enter a password to test: ")

    # Check strength
    strength, feedback = checker.check_strength(password)
    print(f"Password strength: {strength}")
    if feedback:
        print("Feedback:")
        for item in feedback:
            print(f"- {item}")

    # Check for breaches
    if checker.check_breach(password):
        print("Warning: This password has been found in a data breach!")

    # Show entropy
    entropy = checker.calculate_entropy(password)
    print(f"Password entropy: {entropy:.2f} bits")

    # If the password is weak or moderate, suggest a new strong password
    if strength in ["Weak password 😟", "Moderate password ⚠️"]:
        print("Suggested strong password:", checker.suggest_password())
