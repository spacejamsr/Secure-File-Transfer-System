import bcrypt
import json
import os
import getpass

# Always save users.json in the same folder as this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(SCRIPT_DIR, "users.json")

def validate_password(password):
    """
    Validates password complexity requirements per FR-ING-001.
    Minimum 12 characters, uppercase, number, and special character required.
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, "OK"

def create_or_reset_user():
    """
    Creates a new user or resets an existing user's password.
    Passwords are hashed with bcrypt before saving to users.json.
    No plain text passwords are ever stored. (NFR-SEC-001)
    """
    # Load existing users if file exists
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    else:
        users = {}

    print("=== User Management ===")
    username = input("Enter username: ")

    if username in users:
        print(f"User '{username}' already exists.")
        reset = input("Reset their password? (y/n): ")
        if reset.lower() != "y":
            return

    # getpass hides password input so it's never visible on screen (Section 8.1)
    password = getpass.getpass("Enter password: ")

    # Validate password complexity before accepting it
    is_valid, message = validate_password(password)
    if not is_valid:
        print(f"Weak password: {message}")
        return

    # Require password confirmation to prevent typos
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match. Try again.")
        return

    # Hash password with bcrypt before storing
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed

    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

    print(f"User '{username}' saved successfully.")
    print(f"File location: {USERS_FILE}")

if __name__ == "__main__":
    while True:
        create_or_reset_user()
        another = input("Manage another user? (y/n): ")
        if another.lower() != "y":
            break
    print(f"Done. Users saved to: {USERS_FILE}")