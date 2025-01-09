"""
********************************************************************************************
* Title: Zencrypt CLI              |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: November 23rd 2023 |********************************************************
* Version: 3.0                     |********************************************************
* ******************************************************************************************
* <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
* <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
*                                                                                          *
********************************| Description: |********************************************
*                                                                                          *
*              Zencrypt CLI is a Python based application that can be used to:             *
*                                                                                          *
*       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    *
*       - Encrypt text and files: using Fernet symmetric encryption algorithm.             *
*       - PGP Encryption: using RSA asymmetric encryption algorithm, with key handling.    *
*                                                                                          *  
********************************************************************************************
"""

import hashlib
import getpass
import os
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
import base64

"""    Path to the key file    """
KEY_FILE = "zencrypt_p.key"

""" Generate a key and save it to a file    """
def save_key_to_file(key):

    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

""" Load the key from the file  """
def load_key_from_file():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()
    
""" Check if the key file exists, if not generate a new key and save it to a file   """
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    save_key_to_file(key)
else:
    key = load_key_from_file()

cipher_suite = Fernet(key)

""" clears the clipboard   """
def clear_clipboard():
    pyperclip.copy('')
    print("\n\nClipboard cleared.")

""" copies the output to the clipboard   """
def copy_to_clipboard(text):
    pyperclip.copy(text)
    print("\n\nOutput copied to clipboard.")

""" generates a key using PBKDF2HMAC   """
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

""" decrypts the text   """
def decrypt_text():
    try:
        encrypted_text = input("\nEnter the encrypted text to decrypt: ")
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
        print(f"\nDecrypted Text: {decrypted_text}")
    except Exception as e:
        print(f"\nError during decryption: {e}")

""" decrypts the text   """
def encrypt_text():
    try:
        text_to_encrypt = input("\nEnter the text to encrypt: ")
        encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode()).decode()
        print(f"\nEncrypted Text: {encrypted_text}")
        return encrypted_text
    except Exception as e:
        print(f"\nError during encryption: {e}")
        return None
    
""" encrypts the file   """
def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(salt + iv + ciphertext)

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

""" PGP Encryption Functions   """
def generate_pgp_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_pgp_message(message, public_key):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_pgp_message(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def export_public_key_to_file(public_key, filename):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(public_key_pem)

def import_public_key_from_file(filename):
    with open(filename, 'rb') as f:
        public_key_pem = f.read()
    public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    return public_key

""" Main Menu   """
def main_menu():
    while True:
        print("\n\n\n")
        print("=><=" * 20)
        print("************************|  Main Menu  |*****************************************")
        print("=><=" * 20)
        print("********************************************************************************")
        print("* 1 | Hash Manager      |*******************************************************")
        print("* 2 | Encrypt Text      |*******************************************************")
        print("* 3 | Encrypt Files     |*******************************************************")
        print("* 4 | PGP Encryption    |*******************************************************")
        print("********************************************************************************")
        print("* 5 | Clear Clipboard   |*******************************************************")
        print("* 6 | Exit              |*******************************************************")
        print("********************************************************************************")
        print("\n\n")

        choice = input("Enter Option: ")
        if choice == "1":
            # Hashing Menu
            main_loop()

        elif choice == "2":
            # Encrypt Text Menu
            encryption_manager()

        elif choice == "3":
            # Encrypt Files Menu
            parse_files_menu()

        elif choice == "4":
            # PGP Encryption Menu
            pgp_encryption_menu()

        elif choice == "5":
            # Clear Clipboard
            clear_clipboard()

        elif choice == "6":
            # Exit
            break
        
        else:
            # Invalid Input
            print("\nInvalid Input.")

""" PGP Encryption Menu with Export/Import functionalities  """
def pgp_encryption_menu():
    private_key, public_key = generate_pgp_keys()

    message = "" 
    """ Variable to store the last encrypted/decrypted message  """

    while True:
        print("\n\n\n")
        print("=><=" * 20)
        print("************************|  PGP Encryption  |************************************")
        print("=><=" * 20)
        print("********************************************************************************")
        print("* 1 | Encrypt Message    |******************************************************")
        print("* 2 | Decrypt Message    |******************************************************")
        print("********************************************************************************")
        print("* 3 | Export Public Key  |******************************************************")
        print("* 4 | Import Public Key  |******************************************************")
        print("********************************************************************************")
        print("* 5 | Copy to Clipboard  |******************************************************")
        print("* 6 | Clear Clipboard    |******************************************************")
        print("********************************************************************************")
        print("* 7 | Back to Main Menu  |******************************************************")
        print("********************************************************************************")
        print("\n\n")

        choice = input("Enter Option: ")
        if choice == "1":
            message_to_encrypt = input("\nEnter the message to encrypt: ")
            encrypted_message = encrypt_pgp_message(message_to_encrypt, public_key)

            message = base64.b64encode(encrypted_message).decode() 
            """ Convert to Base64 string    """

            print("\nEncrypted Message:", message)
        elif choice == "2":
            encrypted_message = input("\nEnter the message to decrypt (Base64): ")
            try:
                decoded_message = base64.b64decode(encrypted_message)
                decrypted_message = decrypt_pgp_message(decoded_message, private_key)
                
                message = decrypted_message
                """#Store the decrypted message """

                print("\nDecrypted Message:", decrypted_message)
            except Exception as e:
                print(f"\nError during decryption: {e}")
        elif choice == "3":
            filename = input("\nEnter filename to save public key: ")
            export_public_key_to_file(public_key, filename)
            print(f"Public key exported to {filename}")
        elif choice == "4":
            filename = input("\nEnter filename to import public key from: ")
            try:
                public_key = import_public_key_from_file(filename)
                print(f"Public key imported from {filename}")
            except Exception as e:
                print(f"\nError during importing public key: {e}")
        elif choice == "5":
            if message:
                copy_to_clipboard(message)

                # print("\n\nOutput copied to clipboard.")
            else:
                print("\n\nNo message to copy.")

            # copy_to_clipboard(message)
        elif choice == "6":
            clear_clipboard()
        elif choice == "7":
            break
        else:
            print("\nInvalid Input.")

""" Encrypt Files Menu  """
def parse_files_menu():
    while True:
        print("\n\n\n")
        print("=><=" * 20)
        print("************************|  Encrypt Files  |*************************************")
        print("=><=" * 20)
        print("********************************************************************************")
        print("* 1 | Encrypt File      |*******************************************************")
        print("* 2 | Decrypt File      |*******************************************************")
        print("********************************************************************************")
        print("* 3 | Clear Clipboard   |*******************************************************")
        print("********************************************************************************")
        print("* 4 | Return To Hashing |*******************************************************")
        print("********************************************************************************")
        print("\n\n")

        choice = input("Enter Option: ")
        if choice == "1":
            encrypt_file_menu()
        elif choice == "2":
            decrypt_file_menu()
        elif choice == "3":
            clear_clipboard()
        elif choice == "4":
            break
        else:
            print("\nInvalid Input.")

""" Encrypts a file """
def encrypt_file_menu():
    try:
        input_file = input("\nEnter the path to the file to encrypt: ")
        output_file = input("Enter the path for the encrypted file: ")
        password = getpass.getpass("Enter the encryption password: ").encode()
        encrypt_file(input_file, output_file, password)
        print("Encryption complete.")
    except Exception as e:
        print(f"\nError during encryption: {e}")

def decrypt_file_menu():
    try:
        input_file = input("\nEnter the path to the encrypted file: ")
        output_file = input("Enter the path for the decrypted file: ")
        password = getpass.getpass("Enter the decryption password: ").encode()
        decrypt_file(input_file, output_file, password)
        print("Decryption complete.")
    except Exception as e:
        print(f"\nError during decryption: {e}")

""" Encryption Manager Menu """
def encryption_manager():
    while True:
        print("\n\n\n")
        print("=><=" * 20)
        print("************************|  Encrypt Text  |**************************************")
        print("=><=" * 20)
        print("********************************************************************************")
        print("* 1 | Clear Clipboard   |*******************************************************")
        print("********************************************************************************")
        print("* 2 | Encrypt Text      |*******************************************************")
        print("* 3 | Decrypt Text      |*******************************************************")
        print("********************************************************************************")
        print("* 4 | Return to Hashing |*******************************************************")
        print("********************************************************************************")
        print("\n\n")

        choice = input("Enter Option: ")
        if choice == "1":
            clear_clipboard()
        elif choice == "2":
            encrypted_text = encrypt_text()
            if encrypted_text:
                copy_to_clipboard(encrypted_text)
        elif choice == "3":
            decrypt_text()
        elif choice == "4":
            break
        else:
            print("\nInvalid Input.")
            
""" Main Hash Generator Menu    """
def print_menu(sha256_hash):
    print("\n\n\n")
    print("=><=" * 20)
    print("************************|  Hash Manager  |**************************************")
    print("=><=" * 20)
    print("********************************************************************************")
    print("* 1 | Generate Hash     |*******************************************************")
    print("* 2 | Verify Hash       |*******************************************************")
    print("********************************************************************************")
    print("* 3 | Clear Clipboard   |*******************************************************")
    print("* 4 | Copy Output       |*******************************************************")
    print("********************************************************************************")
    print("* 5 | Encrypt Text Menu |*******************************************************")
    print("* 6 | Encrypt File Menu |*******************************************************")
    print("* 7 | PGP Encryption    |*******************************************************")
    print("********************************************************************************")
    print("* 8 | Close Zencrypt    |*******************************************************")
    print("********************************************************************************")
    print("\n\n")

    answer = input("\nEnter Option: ")
    if answer == "1":
        main_loop()
    elif answer == "2":
        verify_hash()
    elif answer == "3":
        clear_clipboard()
    elif answer == "4":
        copy_to_clipboard(sha256_hash)
    elif answer == "5":
        encryption_manager()
    elif answer == "6":
        parse_files_menu()
    elif answer == "7":
        pgp_encryption_menu()
    elif answer == "8":
        exit()
    else:
        print("\nInvalid Input.")

def verify_hash():
    try:
        input_hash = input("\nEnter the hash to verify: ")
        original_text = input("\nEnter the original text to verify against the hash: ")
        salt = input("Enter the salt value used during hashing: ")
        computed_hash = hashlib.sha256((original_text + salt).encode()).hexdigest()

        if computed_hash == input_hash:
            print("\nHash successfully verified.")
        else:
            print("\nVerification unsuccessful. Hash does not match.")
    except Exception as e:
        print(f"\nError during verification: {e}")

def main_loop():
    counter = 0

    while True:
        text = getpass.getpass(prompt="\nEnter text: ")
        if text == "exit":
            break
        counter += 1
        try:
            salt = input("Enter salt value:")
            sha256_hash = hashlib.sha256((text + salt).encode()).hexdigest()
            print("\nOutput:\n")
            print(sha256_hash)
            print_menu(sha256_hash)
        except Exception as e:
            print(f"\nError: {e}")

    input("\nPress Enter To Exit.")

""" ASCII Art   """
print("\n")
print("                           /\\")
print("                          /__\\")
print("                         /\\  /\\")
print("                        /__\\/__\\")
print("                       /\\      /\\")
print("                      /__\\    /__\\")
print("                     /\\  /\\  /\\  /\\")
print("                    /__\\/__\\/__\\/__\\")

main_menu()