"""
********************************************************************************************
* Title: Zencrypt CLI              |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: January 22nd 2025  |********************************************************
* Version: 5.2                     |********************************************************
* ******************************************************************************************
* <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
* <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
* - 1/20/25 - updated comments                                                             *
********************************| Description: |********************************************
*              Zencrypt CLI is a Python based application that can be used to:             *
*       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    *
*       - Encrypt text and files: using Fernet symmetric encryption algorithm.             *
*       - PGP Encryption: using RSA asymmetric encryption algorithm, with key handling.    *
********************************************************************************************
"""

# ----------------------------
#  Existing imports
# ----------------------------

import hashlib
import getpass
import os
import pyperclip
import base64
import argparse
import os

from flask import Flask, request, redirect, url_for, render_template_string, make_response
from flask import send_from_directory

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

# ----------------------------
#  Global Variables
# ----------------------------

KEY_FILE = "private.key"

WEB_APP_PASSWORD = "password"
IS_LOGGED_IN = False  # In-memory login state

def save_key_to_file(key):
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key_from_file():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    save_key_to_file(key)
else:
    key = load_key_from_file()

cipher_suite = Fernet(key)


# ----------------------------
#  Clipboard / Helper Functions
# ----------------------------

def clear_clipboard() -> None:
    pyperclip.copy('')
    print("\n\nClipboard cleared.")

def copy_to_clipboard(text):
    pyperclip.copy(text)
    print("\n\nOutput copied to clipboard.")

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# ----------------------------
#  Encryption / Decryption
# ----------------------------

def decrypt_text():
    try:
        encrypted_text = input("\nEnter the encrypted text to decrypt: ")
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
        print(f"\nDecrypted Text: {decrypted_text}")
    except Exception as e:
        print(f"\nError during decryption: {e}")

def encrypt_text():
    try:
        text_to_encrypt = input("\nEnter the text to encrypt: ")
        encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode()).decode()
        print(f"\nEncrypted Text: {encrypted_text}")
        return encrypted_text
    except Exception as e:
        print(f"\nError during encryption: {e}")
        return None

def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    key_derived = generate_key(password, salt)
    iv = os.urandom(16)

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key_derived), modes.CFB(iv), backend=default_backend())
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

    key_derived = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key_derived), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

# ----------------------------
#  PGP Functions
# ----------------------------

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


# ----------------------------
#  CLI Menus
# ----------------------------

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
            main_loop()   # Hash Manager
        elif choice == "2":
            encryption_manager()
        elif choice == "3":
            parse_files_menu()
        elif choice == "4":
            pgp_encryption_menu()
        elif choice == "5":
            clear_clipboard()
        elif choice == "6":
            break
        else:
            print("\nInvalid Input.")

def pgp_encryption_menu():
    private_key, public_key = generate_pgp_keys()
    message = ""

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
            print("\nEncrypted Message:", message)
        elif choice == "2":
            encrypted_message = input("\nEnter the message to decrypt (Base64): ")
            try:
                decoded_message = base64.b64decode(encrypted_message)
                decrypted_message = decrypt_pgp_message(decoded_message, private_key)
                message = decrypted_message
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
            else:
                print("\n\nNo message to copy.")
        elif choice == "6":
            clear_clipboard()
        elif choice == "7":
            break
        else:
            print("\nInvalid Input.")

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


# -------------------------------------------------------------------------
#   Triforce banner & CLI start
# -------------------------------------------------------------------------

BOLD = '\033[1m'
END = '\033[0m'

ASCII_BANNER = f"""{BOLD}

                           /\\
                          /__\\
                         /\\  /\\
                        /__\\/__\\
                       /\\      /\\
                      /__\\    /__\\
                     /\\  /\\  /\\  /\\
                    /__\\/__\\/__\\/__\\
                    
{END}
"""

print(ASCII_BANNER)

#* Old Triforce Banner Method (Not in bold)
# print("\n")
# print("                           /\\")
# print("                          /__\\")
# print("                         /\\  /\\")
# print("                        /__\\/__\\")
# print("                       /\\      /\\")
# print("                      /__\\    /__\\")
# print("                     /\\  /\\  /\\  /\\")
# print("                    /__\\/__\\/__\\/__\\")
# print("\n\n")

# main_menu()  # Moving to safegaurd below.

#######################################
#*       Flask Web App
#######################################
#
# -------------------------------------------------------------------------
#   v5.3 Flask Integration
# -------------------------------------------------------------------------


app = Flask(__name__)

# Create static folder if it doesn't exist
if not os.path.exists('static'):
    os.makedirs('static')

# ---------- Embedded CSS from Hashing Generator ----------

WEB_APP_CSS = """
body {
    background-color: black;     /* Black background */
    color: white;
}

form {
    margin-top: 50px;            /* Space between the form and the ASCII banner */
}

pre {
    color: #00ff00; /* Green text for the ASCII banner */
}

a {
    color: #00ff00; /* Green link color */
}

input[type="text"], input[type="submit"] { /* Text input and submit button */
    background-color: #333;
    color: white;
    border: 1px solid #00ff00; /* Green border */
}

input[type="submit"]:hover {
    background-color: #00ff00; /* Green background on hover */
    color: black;              /* Black text on hover */
}
"""

# WEB_APP_CSS = """
# body {
#     background-color: black;
#     color: white;
# }
# form {
#     margin-top: 50px;
# }
# pre {
#     color: #00ff00; /* green text for ASCII banners */
# }
# a {
#     color: #00ff00;
# }
# input[type="text"], input[type="password"], input[type="submit"] {
#     background-color: #333;
#     color: white;
#     border: 1px solid #00ff00;
#     margin: 5px;
# }
# input[type="submit"]:hover {
#     background-color: #00ff00; /* green background on hover */
#     color: black;              /* black text on hover */
# }
# """

# ---------- "SHA256 Hashing" HTML templates as multiline strings ----------

LOGIN_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Zencrypt - Login</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <h2>Enter password:</h2>
    <form action="/" method="post">
        <label for="password">Password:</label>
        <input type="password" name="password" required>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

# ---------- "Zencrypt" HTML for the /encrypt route ----------

ENCODING_INDEX_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Zencrypt Web-Application</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
<h2>Zencrypt Web-Application: <code>Encrypt</code> or <code>Decrypt</code> text.</h2>
<hr>
<form method="POST" action="/encrypt">
    <label><bold>Input <code>TEXT</code>:</bold></label><br>
    <textarea name="text" rows="4" cols="50">{{ text }}</textarea><br><br>
    <input type="submit" name="action" value="Encrypt"/>
    <input type="submit" name="action" value="Decrypt"/>
</form>

{% if output %}
    <h2>Output:</h2>
    <pre>{{ output }}</pre>
{% endif %}
<br>
<p><a href="/hash">Visit Hashing Generator</a></p>
</body>
</html>
"""

# BOLD = '\033[1m'
# END = '\033[0m'

# ASCII_BANNER = f"""{BOLD}

#                            /\\
#                           /__\\
#                          /\\  /\\
#                         /__\\/__\\
#                        /\\      /\\
#                       /__\\    /__\\
#                      /\\  /\\  /\\  /\
#                     /__\\/__\\/__\\/__\

# {END}
# """

# print(ASCII_BANNER)

APP_INDEX_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>SHA256</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <pre>{{ ascii_banner }}</pre>
    <h2>Zencrypt Web-Application: <code>Encrypt</code> or <code>Decrypt</code> text.</h2>
    <form action="/hash" method="post">
    <label><bold>Input <code>TEXT</code>:</bold></label><br>
    <textarea name="plaintext" rows="4" cols="50">{{ plaintext }}</textarea><br><br>
    <input type="submit" name="action" value="Encrypt"/>
    <input type="submit" name="action" value="Decrypt"/>
</form>

{% if output %}
    <h2><bold>Output:</bold></h2>
    <pre>{{ output }}</pre>
{% endif %}
</body>
</html>
"""

SHA256_HASH_RESULT_HTML = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Encrypted Text</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <h2>Input: {{ plaintext }}</h2>
    <h2>Output:</h2>
    <pre>{{ sha256_hash }}</pre>
    <a href="/lite">Go back</a>
</body>
</html>
"""

# <head>
#     <title>Zencrypt Web-App</title>
#     <link rel="shortcut icon" type="image/vnd.microsoft.icon" href="/favicon.ico">
# </head>
# <body>
# <h2>Zencrypt Web-Application: <code>Encrypt</code> or <code>Decrypt</code> text.</h2>
# <hr>
# <form method="POST" action="/">
#     <label><bold>Input <code>TEXT</code>:</bold></label><br>
#     <textarea name="plaintext" rows="4" cols="50">{{ plaintext }}</textarea><br><br>
#     <input type="submit" name="action" value="Encrypt"/>
#     <input type="submit" name="action" value="Decrypt"/>
# </form>

# {% if output %}
#     <h2><bold>Output:</bold></h2>
#     <pre>{{ output }}</pre>
# {% endif %}
# </body>
# </html>
# """

# ---------- Flask Routes ----------

@app.route('/static/styles.css')
def serve_css():
    """Serve the CSS file for styling the web interface"""
    response = make_response(WEB_APP_CSS)
    response.headers["Content-Type"] = "text/css"
    return response

@app.route("/")
def index():
    """Main index page with navigation links"""
    return render_template_string("""
        <h1>Zencrypt Web Interface</h1>
        <a href="/encrypt">Encrypt Text</a><br>
        <a href="/decrypt">Decrypt Text</a><br>
        <a href="/hash">Hash Text</a>
    """)

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    """Handle text encryption"""
    if request.method == "POST":
        plaintext = request.form.get('text', '')
        if plaintext:
            try:
                encrypted_text = cipher_suite.encrypt(plaintext.encode()).decode()
                return render_template_string(ENCODING_INDEX_HTML, 
                    text=plaintext,
                    output=f"Encrypted text:\n{encrypted_text}")
            except Exception as e:
                return render_template_string(ENCODING_INDEX_HTML,
                    text=plaintext, 
                    output=f"Error encrypting: {e}")
    return render_template_string(ENCODING_INDEX_HTML, text='', output=None)

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    """Handle text decryption"""
    if request.method == "POST":
        ciphertext = request.form.get('text', '')
        if ciphertext:
            try:
                decrypted_text = cipher_suite.decrypt(ciphertext.encode()).decode()
                return render_template_string(ENCODING_INDEX_HTML,
                    text=ciphertext,
                    output=f"Decrypted text:\n{decrypted_text}")
            except Exception as e:
                return render_template_string(ENCODING_INDEX_HTML,
                    text=ciphertext,
                    output=f"Error decrypting: {e}")
    return render_template_string(ENCODING_INDEX_HTML, text='', output=None)

@app.route("/hash", methods=["GET", "POST"])
def hash_text():
    """Handle text hashing"""
    if request.method == "POST":
        text = request.form.get('text', '')
        if text:
            try:
                hashed = hashlib.sha256(text.encode()).hexdigest()
                return render_template_string(ENCODING_INDEX_HTML,
                    text=text,
                    output=f"SHA256 Hash:\n{hashed}")
            except Exception as e:
                return render_template_string(ENCODING_INDEX_HTML,
                    text=text,
                    output=f"Error hashing: {e}")
    return render_template_string(ENCODING_INDEX_HTML, text='', output=None)

# @app.route("/", methods=["GET", "POST"])
# def lite_login():
#     """Cipher Lite login page."""
#     global IS_LOGGED_IN
#     if IS_LOGGED_IN:
#         return redirect(url_for('lite_index'))

#     if request.method == "POST":
#         password = request.form.get("password", "")
#         # Simple check if password hashed matches
#         if hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256(WEB_APP_PASSWORD.encode()).hexdigest():
#             IS_LOGGED_IN = True
#             return redirect(url_for('lite_index'))
#         else:
#             return "Invalid password. <a href='/'>Try again</a>"

#     return render_template_string(LOGIN_HTML)

# @app.route("/logout")
# def lite_logout():
#     """Logout from Cipher Lite."""
#     global IS_LOGGED_IN
#     IS_LOGGED_IN = False
#     return redirect(url_for('/'))

# ########################
# # Cipher Lite Routes
# ########################

# @app.route("/lite")
# def lite_index():
#     """Cipher Lite home page with ASCII banner and hashing form."""
#     if not IS_LOGGED_IN:
#         return redirect(url_for('lite_index'))

#     return render_template_string(APP_INDEX_HTML,
#                                   ascii_banner=ASCII_BANNER)

# @app.route("/hash", methods=["POST"])
# def lite_hash():
#     """Handles the hashing from Cipher Lite form."""
#     global IS_LOGGED_IN
#     if not IS_LOGGED_IN:
#         return redirect(url_for('lite_login'))

#     text_to_hash = request.form.get("text", "")
#     sha256_hash = hashlib.sha256(text_to_hash.encode()).hexdigest()
#     return render_template_string(SHA256_HASH_RESULT_HTML,
#                                   text=text_to_hash,
#                                   sha256_hash=sha256_hash)

# @app.route("/encrypt", methods=["GET", "POST"])
# def zencrypt_index():
#     """Zencrypt main page: encrypt/decrypt text with Fernet."""
#     global IS_LOGGED_IN
#     if not IS_LOGGED_IN:
#         return redirect(url_for('lite_login'))
#     plaintext = ""
#     output = None
#     if request.method == "POST":
#         action = request.form.get("action")
#         plaintext = request.form.get("plaintext", "")
#         if action == "Encrypt":
#             try:
#                 enc = cipher_suite.encrypt(plaintext.encode()).decode()
#                 output = f"Encrypted text:\n{enc}"
#             except Exception as ex:
#                 output = f"Error encrypting: {ex}"
#         elif action == "Decrypt":
#             try:
#                 dec = cipher_suite.decrypt(plaintext.encode()).decode()
#                 output = f"Decrypted text:\n{dec}"
#             except Exception as ex:
#                 output = f"Error decrypting: {ex}"

#     return render_template_string(APP_INDEX_HTML,
#                                   plaintext=plaintext,
#                                   output=output)
    
# @app.route('/favicon.ico')
# def favicon():
#     return send_from_directory(os.path.join(app.root_path, 'static'),
#                              'favicon.ico', mimetype='image/vnd.microsoft.icon')

# HTML_FORM = """
# <!DOCTYPE html>
# <html>
# <head>
#     <title>Zencrypt Web-App</title>
#     <link rel="shortcut icon" type="image/vnd.microsoft.icon" href="/favicon.ico">
# </head>
# <body>
# <h2>Zencrypt Web-Application: <code>Encrypt</code> or <code>Decrypt</code> text.</h2>
# <hr>
# <form method="POST" action="/">
#     <label><bold>Input <code>TEXT</code>:</bold></label><br>
#     <textarea name="plaintext" rows="4" cols="50">{{ plaintext }}</textarea><br><br>
#     <input type="submit" name="action" value="Encrypt"/>
#     <input type="submit" name="action" value="Decrypt"/>
# </form>

# {% if output %}
#     <h2><bold>Output:</bold></h2>
#     <pre>{{ output }}</pre>
# {% endif %}
# </body>
# </html>
# """

# @app.route("/", methods=["GET", "POST"])
# def index():
#     plaintext = ""
#     output = None

#     if request.method == "POST":
#         action = request.form.get("action")
#         plaintext = request.form.get("plaintext", "").strip()

#         if action == "Encrypt":
#             if plaintext:
#                 try:
#                     enc = cipher_suite.encrypt(plaintext.encode()).decode()
#                     output = f"Encrypted text:\n{enc}"
#                 except Exception as ex:
#                     output = f"Error encrypting: {ex}"
#             else:
#                 output = "No plaintext provided."
#         elif action == "Decrypt":
#             if plaintext:
#                 try:
#                     dec = cipher_suite.decrypt(plaintext.encode()).decode()
#                     output = f"Decrypted text:\n{dec}"
#                 except Exception as ex:
#                     output = f"Error decrypting: {ex}"
#             else:
#                 output = "No text to decrypt."

#     return render_template_string(HTML_FORM, plaintext=plaintext, output=output)

def run_web_server():
    # print("Zencrypt Web Application v5.2 is Developed And Owned Entirely By Ryanshatch\nZencrypt Whitepapers and Docs - https://zencrypt.gitbook.io/zencrypt\nRyanshatch ePortfolio - https://www.ryanshatch.com\n\n")
    # print("Thank you for using my Zencrypt v5.2 Cipher, the Web App is now successfully up and running:\nhttp://localhost:5000/\n\n")
        # Bold text using ANSI escape codes
    BOLD = '\033[1m'
    END = '\033[0m'
    
    print(f"{BOLD}Zencrypt Web Application{END} v5.2 {BOLD}is Developed And Owned Entirely By Ryanshatch{END}\n")
    print(f"Zencrypt {BOLD}Whitepapers and Docs{END} - {BOLD}https://zencrypt.gitbook.io/zencrypt{END}")
    print(f"Ryanshatch {BOLD}ePortfolio{END} - {BOLD}https://www.ryanshatch.com{END}\n")
    print(f"Thank you for using my Zencrypt {BOLD}v5.2{END} Cipher, the Web App is now successfully up and running:")
    print(f"{BOLD}http://localhost:5000/{END}\n\n")
    app.run(debug=True, port=5000)

# -------------------------------------------------------------------------
#   Main entry point
# -------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zencrypt: CLI or Web")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli",
                        help="Select 'cli' for the classic CLI menu or 'web' to launch a Flask server.")
    args = parser.parse_args()

    if args.mode == "web":
        run_web_server()
    else:
        main_menu()

#* Old CLI Code For Reference Below:
#
############################################################################################
#*                                  Zencrypt CLI v5.0.1
############################################################################################
#* Developed by: Ryan Hatch

# #* Importing the required Libraries for building the CLI
# import hashlib
# import getpass
# import os
# import pyperclip
# import base64
# #* Importing dependencies for encryption and decryption
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives.serialization import load_pem_public_key
# from cryptography.hazmat.primitives import serialization

# #* Global Variables:

# #* The name of the .key file.
# KEY_FILE = "zencryptv5.key" # This is a private key file that is used to encrypt and decrypt the text.

# #* Saves the key to a new key file with the default name: `zencryptv5.key`
# def save_key_to_file(key):                 # saves the key to the key file
#     with open(KEY_FILE, "wb") as key_file: # opens the key file in `write binary` mode
#         key_file.write(key)               # writes the key to the key file

# #* Loads the key from the .key file and then returns the name of the key file
# def load_key_from_file():                  # loads the key from the key file
#     with open(KEY_FILE, "rb") as key_file: # opens the key file in `read binary` mode
#         return key_file.read()             # reads the name of the key file
    
# #* Checks if the .key file exists already, and if it does not exist then it will generate a new key here
# if not os.path.exists(KEY_FILE):    # checks if the key file does not exist
#     key = Fernet.generate_key()     # generates a new key if the key file does not exist
#     save_key_to_file(key)           # saves the key to the new key file and the default name
# else:                               # if the key file already exists
#     key = load_key_from_file()      # loads the key from the key file

# cipher_suite = Fernet(key)          # creates a new cipher suite using the key

# #* Clears the clipboard by setting it to an empty string
# def clear_clipboard() -> None:      # sets the clipboard to an empty string
#     pyperclip.copy('')              # copies an empty string to the clipboard
#     print("\n\nClipboard cleared.") # prints a message to the user that the clipboard has been cleared

# #* Copies the output to the clipboard to be parsed
# def copy_to_clipboard(text):                 # function to copy the output text to the clipboard
#     pyperclip.copy(text)                     # uses pyperclip to copy the output text to the clipboard
#     print("\n\nOutput copied to clipboard.") # prints a message to the user that the output has been copied

# #* Generates a key using the password and salt
# def generate_key(password, salt):  # generates a key using the password and salt
#     kdf = PBKDF2HMAC(              # uses the PBKDF2HMAC algorithm to generate the key
#         algorithm=hashes.SHA256(), # uses the SHA256 hashing algorithm
#         length=32,                 # sets the length of the key to 32 bytes
#         salt=salt,                 # sets the salt value to be the `salt` value that the user inputs
#         iterations=100000,         # sets the number of iterations to 100000
#         backend=default_backend()  # uses the default backend for the key generation
#     )

#     return kdf.derive(password) # returns the key that is derived from the password and salt

# #* Decrypts the text using AES symmetric encryption
# def decrypt_text(): # function to decrypt the text using AES symmetric encryption
#     try:
#         encrypted_text = input("\nEnter the encrypted text to decrypt: ") 
#         # prompts the user to enter the encrypted text that they would like to decrypt
#         decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
#         # decrypts the text using the cipher suite and then decodes it
#         print(f"\nDecrypted Text: {decrypted_text}") # prints the decoded text to the user
#     except Exception as e:
#         # uses error handling and catches any exceptions during the decryption process
#         print(f"\nError during decryption: {e}")    # prints an error message to the user if an error occurs

# #* Encrypts the text using AES symmetric encryption
# def encrypt_text():
#     # function to encrypt the text using AES symmetric encryption
#     try:
#         text_to_encrypt = input("\nEnter the text to encrypt: ")
#         # prompts the user to enter the text that they would like to encrypt
#         encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode()).decode()
#         # encrypts the text using the cipher suite and then decodes it
#         print(f"\nEncrypted Text: {encrypted_text}") # logs the encoded text to the user
#         return encrypted_text                        # returns the encrypted text

#     except Exception as e:
#         # uses error handling to catch any exceptions during the encryption process
#         print(f"\nError during encryption: {e}") # prints an error message to the user if an error occurs
#         return None                              # returns `None` if an error occurs
    
# #* Encrypts the file using AES symmetric encryption
# def encrypt_file(input_file, output_file, password):
#     # function to encrypt the file using AES symmetric encryption with a password and salt 
#     salt = os.urandom(16)              # generates a random salt value of 16 bytes
#     key = generate_key(password, salt) # generates a key using the password and salt values
#     iv = os.urandom(16)                # generates a random initialization vector of 16 bytes

#     with open(input_file, 'rb') as file:
#         # opens the input file in `read binary` mode and reads the encoded file
#         plaintext = file.read()     # reads the encoded file and stores it in the `plaintext` variable

#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()) 
#     # creates a new cipher using the AES algorithm, CFB mode, and the iv value

#     encryptor = cipher.encryptor() # creates a new encryptor using the cipher 
#     ciphertext = encryptor.update(plaintext) + encryptor.finalize() 
#     # encrypts the plaintext using the encryptor and finalizes the encryption

#     with open(output_file, 'wb') as file:  # opens the output file in `write binary` mode
#         file.write(salt + iv + ciphertext) # writes the salt, iv, and ciphertext to the output file

# #* Decrypts the file using AES symmetric encryption
# def decrypt_file(input_file, output_file, password): 
#     # function to decrypt the file using AES symmetric encryption with a password and salt
#     with open(input_file, 'rb') as file: # opens the file in `read binary` mode and reads the encoded file
#         data = file.read()               # reads the encoded file and stores it in the `data` variable

#     salt = data[:16]                     # sets the salt value to the first 16 bytes of the data
#     iv = data[16:32]                     # sets the iv value to the next 16 bytes of the data
#     ciphertext = data[32:]               # sets the ciphertext to the remaining bytes of the data

#     key = generate_key(password, salt)   # generates a key using the password and salt values

#     cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
#     # creates a new cipher using the AES algorithm, CFB mode, and the iv value
#     decryptor = cipher.decryptor()       # creates a new decryptor using the cipher
#     decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
#     # decrypts the ciphertext using the decryptor and finalizes the decryption

#     with open(output_file, 'wb') as file:
#         # opens the output file in `write binary` mode and writes the decrypted data to the file
#         file.write(decrypted_data)      # writes the decrypted data to the output file


# """ PGP Variables Section """

# #* PGP Encryption Functions:
# def generate_pgp_keys():                    # generates the PGP keys for RSA asymmetric encryption
#     private_key = rsa.generate_private_key( # generates a new private key using the RSA algorithm
#         public_exponent=65537,              # sets the public exponent to 65537
#         key_size=2048,                      # sets the key size to 2048 bits
#         backend=default_backend()           # uses the default backend for the key generation
#     )

#     public_key = private_key.public_key()  # generates a new public key using the private key
#     return private_key, public_key         # returns the private and public keys

# #* Encrypts the message using RSA asymmetric encryption
# def encrypt_pgp_message(message, public_key): # encrypts the message using RSA asymmetric encryption
#     encrypted = public_key.encrypt(           # encrypts the message using the public key
#         message.encode(),                     # encodes the message to bytes
#         padding.OAEP(                         # uses the OAEP padding scheme for encryption
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             # uses the MGF1 mask generation function with the SHA256 hashing algorithm
#             algorithm=hashes.SHA256(),       # uses the SHA256 hashing algorithm
#             label=None                       # sets the label to `None`
#         )
#     )
#     return encrypted                       # returns the encrypted message

# #* Decrypts the message using RSA asymmetric encryption
# def decrypt_pgp_message(encrypted_message, private_key):
#     # decrypts the message using RSA asymmetric encryption
#     decrypted = private_key.decrypt(         # decrypts the message using the private key
#         encrypted_message,                   # uses the encrypted message as input
#         padding.OAEP(                        # uses the OAEP padding scheme for the decryption process
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             # uses the MGF1 mask generation function with the SHA256 hashing algorithm
#             algorithm=hashes.SHA256(),      # uses the SHA256 hashing algorithm for decryption
#             label=None                      # sets the label to `None`
#         )
#     )

#     return decrypted.decode()              # returns the decrypted message and decodes it to a string

# #* Exports the public key to a file in PEM format for proper handling and storage
# def export_public_key_to_file(public_key, filename):
#     # exports the public key to a file in PEM format for proper handling for the user to parse
#     public_key_pem = public_key.public_bytes( # exports the public key to a PEM format in bytes
#         encoding=serialization.Encoding.PEM,  # uses the PEM encoding for the public key
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#         # uses the SubjectPublicKeyInfo format for the public key
#     )

#     with open(filename, 'wb') as f: # opens the file in `write binary` mode
#         f.write(public_key_pem)     # writes the public key to the file

# #* Imports the public key from a file in PEM format for proper security and validation
# def import_public_key_from_file(filename): # imports the public key from a file in PEM format
#     with open(filename, 'rb') as f:        # opens the file in `read binary` mode and reads the public key
#         public_key_pem = f.read()          # reads the public key from the file
#     public_key = load_pem_public_key(public_key_pem, backend=default_backend()) 
#     # loads the public key from the PEM format using the default backend
#     return public_key                      # returns the public key

# #* Main Menu for the PGP Submenu for Zencrypt CLI
# def main_menu(): # This is the first menu that the user will see
#     while True:
#         print("\n\n\n")
#         print("=><=" * 20)
#         print("************************|  Main Menu  |*****************************************")
#         print("=><=" * 20)
#         print("********************************************************************************")
#         print("* 1 | Hash Manager      |*******************************************************")
#         print("* 2 | Encrypt Text      |*******************************************************")
#         print("* 3 | Encrypt Files     |*******************************************************")
#         print("* 4 | PGP Encryption    |*******************************************************")
#         print("********************************************************************************")
#         print("* 5 | Clear Clipboard   |*******************************************************")
#         print("* 6 | Exit              |*******************************************************")
#         print("********************************************************************************")
#         print("\n\n")

#         choice = input("Enter Option: ") # prompts the user to enter an option from the menu and select which submenu they would like to access/ which Zencrypt feature they would like to use
#         if choice == "1":                # if the user selects option 1
#             # Hash Manager Menu ( SHA256 Hashing )
#             main_loop()

#         elif choice == "2":             # if the user selects option 2
#             # Encrypt Text Menu ( Fernet Symmetric Encryption )
#             encryption_manager()

#         elif choice == "3":             # if the user selects option 3
#             # Encrypt Files Menu ( AES Symmetric Encryption )
#             parse_files_menu()

#         elif choice == "4":             # if the user selects option 4
#             # PGP Encryption Menu ( RSA Asymmetric Encryption )
#             pgp_encryption_menu()

#         elif choice == "5":             # if the user selects option 5
#             # Clear Clipboard
#             clear_clipboard()           # clears the clipboard by setting it to an empty string

#         elif choice == "6":             # if the user selects option 6
#             # Exit
#             break                       # breaks out of the loop and exits the program
        
#         else:                           # if the user enters an invalid input
#                                         # Invalid Input for error handling
#             print("\nInvalid Input.")   # prints a message to the user that the input is invalid

# #* PGP Encryption Menu with Export/Import functionalities for public keys
# def pgp_encryption_menu(): # This is the PGP Encryption Menu for the Zencrypt CLI
#     private_key, public_key = generate_pgp_keys() # when the user enters the PGP Encryption Menu, it will generate a new set of private and public keys for the user

#     message = "" 
#     #* Assigns an empty variable to store the message into the clipboard to make it efficient for the user to copy the output and parse the output.

#     while True:
#         print("\n\n\n")
#         print("=><=" * 20)
#         print("************************|  PGP Encryption  |************************************")
#         print("=><=" * 20)
#         print("********************************************************************************")
#         print("* 1 | Encrypt Message    |******************************************************")
#         print("* 2 | Decrypt Message    |******************************************************")
#         print("********************************************************************************")
#         print("* 3 | Export Public Key  |******************************************************")
#         print("* 4 | Import Public Key  |******************************************************")
#         print("********************************************************************************")
#         print("* 5 | Copy to Clipboard  |******************************************************")
#         print("* 6 | Clear Clipboard    |******************************************************")
#         print("********************************************************************************")
#         print("* 7 | Back to Main Menu  |******************************************************")
#         print("********************************************************************************")
#         print("\n\n")

#         choice = input("Enter Option: ") # prompts the user to enter an option from the menu and select which PGP Encryption feature they would like to use
#         if choice == "1":                # if the user selects option 1
#             message_to_encrypt = input("\nEnter the message to encrypt: ")          # prompts the user to enter the message that they would like to encrypt
#             encrypted_message = encrypt_pgp_message(message_to_encrypt, public_key) # encrypts the message using the public key

#             message = base64.b64encode(encrypted_message).decode() 
#             #* Encodes the message to Base64 for proper handling and storage

#             print("\nEncrypted Message:", message) # prints the encrypted message to the user for them to copy and parse

#         elif choice == "2":                                                           # if the user selects option 2
#             encrypted_message = input("\nEnter the message to decrypt (Base64): ")    # prompts the user to enter the encrypted message that they would like to decrypt
#             try: # uses error handling to catch any exceptions during the decryption process
#                 decoded_message = base64.b64decode(encrypted_message)                 # decodes the message from Base64
#                 decrypted_message = decrypt_pgp_message(decoded_message, private_key) # decode the message using the private key
                
#                 message = decrypted_message
#                 #* Store the decrypted message

#                 print("\nDecrypted Message:", decrypted_message) # prints the decrypted message to the user for them to copy and parse
#             except Exception as e:                               # if an error occurs during the decryption process for error handling
#                 print(f"\nError during decryption: {e}")         # prints an error message to the user that an error occurred during decryption 

#         elif choice == "3":                                           # if the user selects option 3
#             filename = input("\nEnter filename to save public key: ") # prompts the user to enter the filename to save the public key
#             export_public_key_to_file(public_key, filename)           # exports the public key to a file in PEM format
#             print(f"Public key exported to {filename}")               # prints a message to the user that the public key has been exported

#         elif choice == "4":                                                  # if the user selects option 4
#             filename = input("\nEnter filename to import public key from: ") # prompts the user to enter the filename to import the public key from
#             try:                                                             # uses error handling to catch any exceptions during the importing process
#                 public_key = import_public_key_from_file(filename)           # imports the public key from the file in PEM format
#                 print(f"Public key imported from {filename}")                # prints a message to the user that the public key has been imported
#             except Exception as e:                                           # if an error occurs during the importing process for error handling
#                 print(f"\nError during importing public key: {e}")           # prints an error message to the user that an error occurred during importing the public key

#         elif choice == "5":                # if the user selects option 5
#             if message:                    # if there is a message to copy
#                 copy_to_clipboard(message) # copies the message to the clipboard for the user to parse

#                                                  # print("\n\nOutput copied to clipboard.")
#             else:                                # if there is no message to copy
#                 print("\n\nNo message to copy.") # prints a message to the user that there is no message to copy

#                                 # copy_to_clipboard(message)
#         elif choice == "6":     # if the user selects option 6
#             clear_clipboard()   # clears the clipboard by setting it to an empty string

#         elif choice == "7":           # if the user selects option 7
#             break                     # breaks out of the loop and returns to the main menu
#         else:                         # if the user enters an invalid input for error handling
#             print("\nInvalid Input.") # prints a message to the user that the input is invalid

# #* File Encryption Menu
# def parse_files_menu(): # This is the File Encryption Menu for the Zencrypt CLI
#     while True:
#         print("\n\n\n")
#         print("=><=" * 20)
#         print("************************|  Encrypt Files  |*************************************")
#         print("=><=" * 20)
#         print("********************************************************************************")
#         print("* 1 | Encrypt File      |*******************************************************")
#         print("* 2 | Decrypt File      |*******************************************************")
#         print("********************************************************************************")
#         print("* 3 | Clear Clipboard   |*******************************************************")
#         print("********************************************************************************")
#         print("* 4 | Return To Hashing |*******************************************************")
#         print("********************************************************************************")
#         print("\n\n")

#         choice = input("Enter Option: ")    # prompts the user to enter an option from the menu and select which File Encryption feature they would like to use
#         if choice == "1":                   # if the user selects option 1
#             encrypt_file_menu()             # Encrypt File Menu ( AES Symmetric Encryption )

#         elif choice == "2":                 # if the user selects option 2
#             decrypt_file_menu()             # Decrypt File Menu ( AES Symmetric Encryption )

#         elif choice == "3":                 # if the user selects option 3
#             clear_clipboard()               # Clear Clipboard

#         elif choice == "4":                 # if the user selects option 4
#             break                           # Return to Hashing Menu ( SHA256 Hashing )

#         else:                               # if the user enters an invalid input for error handling
#             print("\nInvalid Input.")       # prints a message to the user that the input is invalid

# #* Encrypts the file using AES symmetric encryption
# def encrypt_file_menu():                                                        # This is the logic for encrypting files using AES symmetric encryption
#     try:
#         input_file = input("\nEnter the path to the file to encrypt: ")         # prompts the user to enter the path to the decrypted file
#         output_file = input("Enter the path for the encrypted file: ")          # prompts the user to enter the path for where they would like to save the encrypted file
#         password = getpass.getpass("Enter the encryption password: ").encode()  # prompts the user to enter the encryption password and then encodes it
#         encrypt_file(input_file, output_file, password)                         # encrypts the file using the input file, output file, and password
#         print("Encryption complete.")                                           # prints a message to the user that the encryption process has been completed

#     except Exception as e:                                                      # uses error handling to catch any exceptions during the encryption process
#         print(f"\nError during encryption: {e}")                                # prints an error message to the user that an error occurred during encryption

# #* Decrypts the file using AES symmetric encryption
# def decrypt_file_menu():                                                        # This is the logic for decrypting files using AES symmetric encryption
#     try:
#         input_file = input("\nEnter the path to the encrypted file: ")          # prompts the user to enter the path to the encrypted file
#         output_file = input("Enter the path for the decrypted file: ")          # prompts the user to enter the path for where they would like to save the decrypted file
#         password = getpass.getpass("Enter the decryption password: ").encode()  # prompts the user to enter the decryption password and then encodes it
#         decrypt_file(input_file, output_file, password)                         # decrypts the file using the input file, output file, and password
#         print("Decryption complete.")                                           # prints a message to the user that the decryption process has been completed.
    
#     except Exception as e:                          # uses error handling to catch any exceptions during the decryption process
#         print(f"\nError during decryption: {e}")    # prints an error message to the user that an error occurred during decryption

# #* Text Encryption Manager Menu
# def encryption_manager(): # This is the Text Encryption Manager Menu for the Zencrypt CLI
#     while True:
#         print("\n\n\n")
#         print("=><=" * 20)
#         print("************************|  Encrypt Text  |**************************************")
#         print("=><=" * 20)
#         print("********************************************************************************")
#         print("* 1 | Clear Clipboard   |*******************************************************")
#         print("********************************************************************************")
#         print("* 2 | Encrypt Text      |*******************************************************")
#         print("* 3 | Decrypt Text      |*******************************************************")
#         print("********************************************************************************")
#         print("* 4 | Return to Hashing |*******************************************************")
#         print("********************************************************************************")
#         print("\n\n")

#         choice = input("Enter Option: ")            # prompts the user to enter an option from the menu and select which Text Encryption feature they would like to use
#         if choice == "1":                           # if the user selects option 1
#             clear_clipboard()                       # Clear Clipboard
#         elif choice == "2":                         # if the user selects option 2
#             encrypted_text = encrypt_text()         # Encrypt Text
#             if encrypted_text:                      # if there is encrypted text to copy
#                 copy_to_clipboard(encrypted_text)   # copies the encrypted text to the clipboard for the user to parse
#         elif choice == "3":                         # if the user selects option 3
#             decrypt_text()                          # Decrypt Text
#         elif choice == "4":                         # if the user selects option 4
#             break                                   # Return to Hashing Menu ( SHA256 Hashing )
#         else:                                       # if the user enters an invalid input for error handling
#             print("\nInvalid Input.")               # prints a message to the user that the input is invalid
            
# #* Main Menu for the Zencrypt CLI/ Hash Manager
# def print_menu(sha256_hash):                        # This is the Main Menu for the Zencrypt CLI
#     print("\n\n\n")
#     print("=><=" * 20)
#     print("************************|  Hash Manager  |**************************************")
#     print("=><=" * 20)
#     print("********************************************************************************")
#     print("* 1 | Generate Hash     |*******************************************************")
#     print("* 2 | Verify Hash       |*******************************************************")
#     print("********************************************************************************")
#     print("* 3 | Clear Clipboard   |*******************************************************")
#     print("* 4 | Copy Output       |*******************************************************")
#     print("********************************************************************************")
#     print("* 5 | Encrypt Text Menu |*******************************************************")
#     print("* 6 | Encrypt File Menu |*******************************************************")
#     print("* 7 | PGP Encryption    |*******************************************************")
#     print("********************************************************************************")
#     print("* 8 | Close Zencrypt    |*******************************************************")
#     print("********************************************************************************")
#     print("\n\n")

#     answer = input("\nEnter Option: ")  # prompts the user to enter an option from the menu and select which Zencrypt feature they would like to use
#     if answer == "1":                   # if the user selects option 1
#         main_loop()                     # Generate Hash Menu ( SHA256 Hashing )
#     elif answer == "2":                 # if the user selects option 2
#         verify_hash()                   # Verify Hash Menu ( SHA256 Hashing )
#     elif answer == "3":                 # if the user selects option 3
#         clear_clipboard()               # Clear Clipboard
#     elif answer == "4":                 # if the user selects option 4
#         copy_to_clipboard(sha256_hash)  # Copy Output
#     elif answer == "5":                 # if the user selects option 5
#         encryption_manager()            # Encrypt Text Menu ( Fernet Symmetric Encryption )
#     elif answer == "6":                 # if the user selects option 6
#         parse_files_menu()              # Encrypt File Menu ( AES Symmetric Encryption )
#     elif answer == "7":                 # if the user selects option 7
#         pgp_encryption_menu()           # PGP Encryption Menu ( RSA Asymmetric Encryption )
#     elif answer == "8":                 # if the user selects option 8
#         exit()                          # Close Zencrypt
#     else:                               # if the user enters an invalid input for error handling
#         print("\nInvalid Input.")       # prints a message to the user that the input is invalid

# def verify_hash():                      # This is the Verify Hash Menu for the Zencrypt CLI
#     try:                                                    # uses error handling to catch any exceptions during the verification process
#         input_hash = input("\nEnter the hash to verify: ")  # prompts the user to enter the hash that they would like to verify
#         original_text = input("\nEnter the original text to verify against the hash: ") # prompts the user to enter the original text to verify against the hash
#         salt = input("Enter the salt value used during hashing: ")                      # prompts the user to enter the salt value that was used during the hashing process
#         computed_hash = hashlib.sha256((original_text + salt).encode()).hexdigest()     # generates hash using the original text and salt value and then converts it to a hexadecimal string

#         if computed_hash == input_hash:             # if the computed hash matches the input hash
#             print("\nHash successfully verified.")  # prints a message to the user that the hash has been successfully verified
#         else:                                       # if the computed hash does not match the input hash
#             print("\nVerification unsuccessful. Hash does not match.") # prints a message to the user that the verification was unsuccessful and the hash does not match
#     except Exception as e:                          # if an error occurs during the verification process for error handling
#         print(f"\nError during verification: {e}")  # prints an error message to the user that an error occurred during verification

# #* Main Loop for the Zencrypt CLI to handle hashes and salt values for the hashing algorithm
# def main_loop():                                    # This is the Main Loop for the Zencrypt CLI
#     counter = 0                                     # initializes a counter variable to keep track of the number of times the loop has run

#     while True:                                     # runs the loop until the user exits the program
#         text = getpass.getpass(prompt="\nEnter text: ") # prompts the user to enter the text that they would like to hash
#         if text == "exit":                              # if the user enters `exit`
#             break                                       # breaks out of the loop and returns to the main menu
#         counter += 1                                    # increments the counter variable by 1
#         try:                                            # uses error handling to catch any exceptions during the hashing process
#             salt = input("Enter salt value:") # prompts the user to enter the salt value that they would like to use during the hashing process
#             sha256_hash = hashlib.sha256((text + salt).encode()).hexdigest() # generates the SHA256 hash using the text and salt value and then converts it to a hexadecimal string
#             print("\nOutput:\n")                        # prints a message to the user that the output is being displayed
#             print(sha256_hash)                          # prints the SHA256 hash to the user
#             print_menu(sha256_hash)                     # prints the main menu for the user to select the next action
#         except Exception as e:                          # if an error occurs during the hashing process for error handling
#             print(f"\nError: {e}")                      # prints an error message to the user that an error occurred during the hashing process

#     input("\nPress Enter To Exit.")                     # prompts the user to press `Enter` to exit the program

# #* Main Function to run the Zencrypt CLI in the terminal displayed in ASCII Art as a Triforce thats being used as a banner for the CLI
# print("\n")
# print("                           /\\")
# print("                          /__\\")
# print("                         /\\  /\\")
# print("                        /__\\/__\\")
# print("                       /\\      /\\")
# print("                      /__\\    /__\\")
# print("                     /\\  /\\  /\\  /\\")
# print("                    /__\\/__\\/__\\/__\\")
# print("\n\n")
# main_menu()                                             # runs the main menu for the Zencrypt CLI under the Triforce banner