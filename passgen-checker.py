import getpass
import bcrypt
import json
import os
import re
from argon2 import PasswordHasher  
from datetime import datetime

DATA_FILE = "passwords.json"

# storages 
password_manager = {}
failed_attempts = {}
lockout_threshold = 3
ph = PasswordHasher()  # init argon2 hasher

# load from json
def load_data():
    global password_manager
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                content = f.read().strip()
                if not content:  # if the json is empty
                    password_manager = {}
                    return
                password_manager = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"Error reading password file: {e}")
            print("Starting with empty password manager...")
            password_manager = {}
        except Exception as e:
            print(f"Unexpected error loading data: {e}")
            password_manager = {} # exception handling stuff

# json saver
def save_data():
    try:
        #note to self no byte conversion needed for argon2 hashes
        serializable = {
            user: {'hash': data['hash'],
                   'last_login': data.get('last_login')}
            for user, data in password_manager.items()
        }
        with open(DATA_FILE, "w") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        print(f"Error saving data: {e}")

# strength checker
def is_strong(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+=\-{}\[\]:;\"'<>,.?/]", password) # list of whatever characters
    )

def create_account():
    username = input("Enter a username: ")
    if username in password_manager:
        print("Account already exists")
        return

    password = getpass.getpass("Enter a password: ")
    if not is_strong(password):
        print("Password too weak, Please enter a password with at least 8 characters, an uppercase letter, a lowercase letter, a digit and a special character")
        return

    hashed = ph.hash(password) 
    password_manager[username] = {"hash": hashed, "last_login": None}
    save_data()
    print(f"Account created for {username}")

def login():
    username = input("Enter your username: ")

    if username not in password_manager:
        print("User not found")
        return

    # lockout
    if failed_attempts.get(username, 0) >= lockout_threshold:
        print("Account locked due to too many failed attempts")
        return

    password = getpass.getpass("Enter your password: ")
    stored_hash = password_manager[username]["hash"]

    try:
        # using argon for verification
        ph.verify(stored_hash, password)
        print(f"Login successful for {username}.")
        password_manager[username]["last_login"] = str(datetime.now())
        failed_attempts[username] = 0  # reset counter
        save_data()
    except Exception:  # raises exception on verification failure
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        print("Login failed. Invalid username or password.")
        if failed_attempts[username] >= lockout_threshold:
            print("Account locked after 3 failed attempts")

def main():
    load_data()
    while True:
        choice = input("Choose an option: (1) Create Account (2) Login (3) Exit: ")
        if choice == '1':
            create_account()
        elif choice == '2':
            login()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
