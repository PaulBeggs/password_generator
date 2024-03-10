import os
import secrets
import string
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.fernet import Fernet
import json
import re
import pyperclip
import getpass


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def load_passwords(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            # Load and return the JSON data as a dictionary
            return json.loads(decrypted_data)
    except FileNotFoundError:
        return {}  # Return an empty dictionary if the file doesn't exist
    except cryptography.fernet.InvalidToken:
        print("Invalid key - cannot decrypt passwords.")
        return {}


def save_passwords(file_path, passwords, key):
    fernet = Fernet(key)
    # Convert the entire passwords dictionary (with notes) to a JSON string
    encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)


def process_url(url):
    match = re.match(r'https?://([A-Za-z0-9.-]+)\.com', url)
    if match:
        return f"https://{match.group(1)}.com"
    else:
        return None


def generate_password(length=20):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def main():
    salt_file = 'salt.bin'
    passwords_file = 'passwords.json'

    # Check for the salt file's existence or create a new one
    if not os.path.exists(salt_file):
        salt = os.urandom(16)
        with open(salt_file, 'wb') as f:
            f.write(salt)
    else:
        with open(salt_file, 'rb') as f:
            salt = f.read()

    # Prompt for the passphrase
    passphrase = getpass.getpass("Enter your passphrase: ")
    key = derive_key(passphrase, salt)

    # Initialize an empty passwords dictionary
    passwords = {}

    # Check for the passwords file's existence
    if os.path.exists(passwords_file):
        # Load and decrypt existing passwords
        with open(passwords_file, 'rb') as f:
            encrypted_data = f.read()
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            passwords = json.loads(decrypted_data)
    else:
        # Encrypt and save the empty passwords dictionary for the first time
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
        with open(passwords_file, 'wb') as f:
            f.write(encrypted_data)

    while True:
        print()
        choice = input(
            "Do you want to (1) look up a password, (2) print all passwords, (3) create a new password, (4) save a "
            "custom password, \n(5) edit / view a note, or (6) remove a URL? \n\nEnter 1, 2, 3, 4, 5, or 6: ")

        if choice == '1':
            print()
            search_term = input("Enter the search term: ")
            found = False
            for domain, password in passwords.items():
                if search_term.lower() in domain.lower():
                    print(f"Password for {domain}: {password}")
                    found = True
            if not found:
                print("No passwords found containing the search term.")

            elif choice == '2':
                if passwords:  # Check if the dictionary is not empty
                    for domain, data in passwords.items():
                        # Assuming data is a dictionary with 'password' and 'note', adjust as needed
                        print(f"{domain}: {data.get('password')}")
                else:
                    print("No passwords have been stored yet.")

        elif choice == '3':
            print()
            url = input("Enter the URL: ")
            if url.lower() == 'back':
                continue  # Skip the rest of the loop and show the main menu again
            domain = process_url(url)
            if domain:
                password = generate_password()
                pyperclip.copy(password)
                print(f"Generated and copied to clipboard: {password}")
                if domain in passwords:
                    # Update the existing entry with the new password, preserve the existing note
                    passwords[domain]['password'] = password
                else:
                    # Create a new entry for the domain with the new password and an empty note
                    passwords[domain] = {'password': password, 'note': ''}

                save_passwords(passwords_file, passwords, key)
                print("Password saved for " + domain)
            else:
                print("Invalid URL format. Make sure it's like https://{website}.com")

        elif choice == '4':
            # New option to save a custom password
            print()
            url = input("Enter the URL for the custom password: ")
            if url.lower() == 'back':
                continue  # Skip the rest of the loop and show the main menu again
            domain = process_url(url)
            if domain:
                custom_password = getpass.getpass("Enter the custom password (input will be hidden): ")
                if domain in passwords:
                    # Update the existing entry with the new password, preserve the existing note
                    passwords[domain]['password'] = custom_password
                else:
                    # Create a new entry for the domain with the new password and an empty note
                    passwords[domain] = {'password': custom_password, 'note': ''}

                save_passwords(passwords_file, passwords, key)
                print(f"Custom password saved for {domain}.")
            else:
                print("Invalid URL format. Please ensure it's like https://{website}.com")

        elif choice == '5':
            print()
            search_url = input(
                "Enter the URL for which you want to view or add a note or type 'back' to return to the main menu: ")
            if search_url.lower() == 'back':
                continue  # Return to the main menu
            found_domains = [domain for domain in passwords if search_url.lower() in domain.lower()]
            if found_domains:
                for domain in found_domains:
                    print(
                        f"Match found for {domain}: Password - {passwords[domain].get('password', 'No password found')}")
                    # Assuming you've migrated to the new data structure correctly
                    print()
                    action = input("Do you want to (1) view or (2) add/update a note? Enter 1 or 2: ")
                    if action == '1':
                        print(f"Note for {domain}: {passwords[domain].get('note', 'No note found')}")
                    elif action == '2':
                        print()
                        note = input("Enter your note: ")
                        passwords[domain]['note'] = note  # Update or add a note
                        save_passwords(passwords_file, passwords, key)
                        print("Note saved for", domain)
            else:
                print("No passwords found containing the search term.")

        elif choice == '6':
            print()
            url_to_remove = input("Enter the URL you wish to remove: ")
            # Normalize and process the URL to ensure consistency
            domain_to_remove = process_url(url_to_remove)

            print()
            confirmation = input(f"Are you sure you want to remove {domain_to_remove}? (yes/no): ").lower()
            if confirmation == 'yes':
                if domain_to_remove and domain_to_remove in passwords:
                    # Remove the URL and its associated data
                    del passwords[domain_to_remove]
                    save_passwords(passwords_file, passwords, key)
                    print(f"Removed {domain_to_remove} from your password history.")
                elif domain_to_remove:
                    print("URL not found in your password history.")
                else:
                    print("Invalid URL format. Please ensure it's like https://{website}.com")
            else:
                print("Removal canceled.")

        print()
        if input("Do you want to continue? (press any key/no): ").lower() == 'no':
            print()
            break


if __name__ == "__main__":
    main()
