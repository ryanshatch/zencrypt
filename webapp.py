"""
********************************************************************************************
* Title: Zencrypt WebApp           |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: January 27th 2025  |********************************************************
* Version: 5.3                     |********************************************************
********************************************************************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
|    - 1/21/25 -#* Updated app to Flask app                                                *
|    - 1/21/25 -#* updated comments                                                        *
|    - 1/22/25 -#* Updated routes to perform optimally                                     *
|    - 1/23/25 -#* Added ASCII banner and CLI start function to print on the console       *
|    - 1/24/25 -#* Added a secret key for secure session management                        *
|    - 1/25/25 -#* Updated the HTML for the web-app                                        *
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
********************************#* Description: |*******************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
*              Zencrypt Web-App is a Flask application that can be used to:                *
*       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    *
*       - Encrypt text and files: using Fernet symmetric encryption algorithm.             *
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
""""""********************#* Web-App Implementations: |*************************************
- The CLI and webapp code are separated for clarity, scalability and modularity.           *
- The Web-App uses Flask and cryptography libraries with a HTML interface for the UI/UX.   *
- The webapp v5 is hosted on a local server, and can be accessed via a web browser.        *
********************************************************************************************
*           #* Some key differences in the Web-Apps functionality are:                     *
- File uploads/processing, text input handling, navigation menus, a user friendly UI/UX,   *
*   error handling, and password/salt inputs.                                              *
- Its also important to note that PGP encryption is not implemented currently in v5.3,     *
*    but will be in the final stages of Zencrypt v6.0.0.                                   *
********************************************************************************************
"""

# #* Importing the required functions from the utils module
# from utils import (
#     initialize_key,
#     # generate_hash,
#     # encrypt_text,
#     # decrypt_text,
# )

#* Importing the required libraries for the webapp
from flask import Flask, request, render_template_string, redirect, url_for, session
from cryptography.fernet import Fernet
import hashlib
import os
import base64
import secrets

#* Setting up the Flask application and the secret key
app = Flask(__name__)

#* Secret keys for session management
app.secret_key = secrets.token_hex(32)         # A random secret key is generated using the secrets module for session management

#* Setting up the private key for encryption/decryption
KEY_FILE = "zen.key"                       # The private key is stored in a file called "private.key"

def initialize_key(): 
    if not os.path.exists(KEY_FILE):           # If the private key file does not exist in the directory
        key = Fernet.generate_key()            # A new key is generated and stored in the file under the name "private.key"
        with open(KEY_FILE, "wb") as key_file: # The key is written to the file in binary mode
            key_file.write(key)                # The key is written to the file
    with open(KEY_FILE, "rb") as key_file:     # If the private key file exists, the key is read from the file
        return key_file.read()                 # The key is returned as a binary string from the file and stored in the key variable

cipher_suite = Fernet(initialize_key())        # The cipher suite is initialized with the new or old private key

#* ---------------------- | Styling and HTML for the Web-App | ---------------------- #
APP_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Zencrypt Web-App</title>
    <style>
        body {
            background-color: black;
            color: white;
            font-family: monospace;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .menu {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        textarea {
            width: 100%;
            min-height: 100px;
            margin: 10px 0;
            background-color: #1a1a1a;
            color: white;
            border: 1px solid #333;
            padding: 10px;
        }
        button {
            background-color: #333;
            color: white;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
        }
        button:hover {
            background-color: #444;
        }
        .output {
            background-color: #1a1a1a;
            padding: 10px;
            margin-top: 20px;
            white-space: pre-wrap;
        }
        .ascii-art {
            white-space: pre;
            text-align: center;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Zencrypt v5.3.0</h1>
    <hr>
        <h3><b>The Zencrypt Web-Application is still being developed And Owned Entirely By <code>Ryanshatch</code></b></h3>
        <h4><b>Zencrypt Whitepapers and Docs</b> - <b>https://zencrypt.gitbook.io/zencrypt</b></h4>
        <h3><b>Ryanshatch ePortfolio</b> - <b>https://www.ryanshatch.com</b></h3>
        <hr>
        <h4>With this web-app you can:
        <br><li>Hash text using SHA256, Encrypt text, Decrypt text.</li>
        <li>handle Encrypting and Decrypting Uploaded Files securely and online.</li></h4>
        <div class="menu">
            <a href="/"><button>Hash</button></a>
            <a href="/encrypt"><button>Encrypt</button></a>
            <a href="/decrypt"><button>Decrypt</button></a>
            <a href="/file"><button>File Operations</button></a>
        </div>
        <hr>
        
        {{ content | safe }}
        
        {% if output %}
        <div class="output">
            {{ output }}
        </div>
        {% endif %}
    </div>
    <br><hr>
</body>
</html>
"""

#* ---------------------- | Web-App Routes | ---------------------- #

#* Route to the home page of the web-app with the hash function
@app.route('/', methods=['GET', 'POST'])
def hash_page():                                                 # The hash_page function is defined to handle the home / hash page of the web-app
    output = None                                                # The output variable is initialized to None
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to hash"></textarea>
        <input type="text" name="salt" placeholder="Salt (optional)">
        <button type="submit">Generate Hash</button>
    </form>
    """
    
    if request.method == 'POST':                                 # If the request method is POST, for example, when the form is submitted
        text = request.form.get('text', '')                      # The text input from the form is retrieved from the request
        salt = request.form.get('salt', '')                      # The salt input from the form is retrieved from the request
        if text:                                                 # If the text input is not empty or "None"
            hash_input = (text + salt).encode()                  # The text and salt are concatenated and encoded as bytes
            hash_output = hashlib.sha256(hash_input).hexdigest() # The SHA256 hash is generated from the input and converted to a hexadecimal string
            output = f"SHA256 Hash:\n{hash_output}"              # The output is set to the hash output with a message
    
    #* The HTML is rendered with the content and all output variables
    return render_template_string(APP_TEMPLATE, content=content, output=output)

#* Route to the encrypt text page of the web-app with the encryption function
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_page(): 
    output = None
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to encrypt"></textarea>
        <button type="submit">Encrypt</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            try:
                encrypted = cipher_suite.encrypt(text.encode())
                output = f"Encrypted Text:\n{encrypted.decode()}"
            except Exception as e:
                output = f"Error: {str(e)}"
    
    return render_template_string(APP_TEMPLATE, content=content, output=output)

#* Route to the decrypt text page of the web-app with the decryption function
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_page():
    output = None
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to decrypt"></textarea>
        <button type="submit">Decrypt</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            try:
                decrypted = cipher_suite.decrypt(text.encode())
                output = f"Decrypted Text:\n{decrypted.decode()}"
            except Exception as e:
                output = f"Error: {str(e)}"
    
    return render_template_string(APP_TEMPLATE, content=content, output=output)

#* Route to the file operations page of the web-app with the file encryption/decryption function
@app.route('/file', methods=['GET', 'POST'])
def file_page():
    output = None
    content = """
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="password" name="password" placeholder="Password" required>
        <select name="operation">
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
        </select>
        <button type="submit">Process File</button>
    </form>
    """
    
    if request.method == 'POST':
        if 'file' not in request.files:
            output = "No file uploaded"
            return render_template_string(APP_TEMPLATE, content=content, output=output)
            
        file = request.files['file']
        password = request.form.get('password', '').encode()
        operation = request.form.get('operation')
        
        if file.filename == '':
            output = "No file selected"
            return render_template_string(APP_TEMPLATE, content=content, output=output)
            
        try:
            file_content = file.read()
            salt = os.urandom(16)
            
            if operation == 'encrypt':
                encrypted = cipher_suite.encrypt(file_content)
                output = f"File encrypted successfully:\n{base64.b64encode(encrypted).decode()}"
            else:
                decrypted = cipher_suite.decrypt(base64.b64decode(file_content))
                output = f"File decrypted successfully:\n{decrypted.decode()}"
        except Exception as e:
            output = f"Error processing file: {str(e)}"
    
    return render_template_string(APP_TEMPLATE, content=content, output=output)

#* ---------------------- | Triforce banner & CLI start | ----------------------
#*  HTML code displays the web-app in the browser with Zencrypts information.
#*  Flask app runs on a local server and prints a Zencrypt banner in console.
#* -----------------------------------------------------------------------------

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
#* Function to print the Zencrypt banner in the console along with Zencrypt whitepapers and ePortfolio links to my website.
def print_startup_banner():
    print(ASCII_BANNER)
    print(f"{BOLD}Zencrypt Web Application{END} v5.2 {BOLD}is Developed And Owned Entirely By Ryanshatch{END}\n")
    print(f"Zencrypt {BOLD}Whitepapers and Docs{END} - {BOLD}https://zencrypt.gitbook.io/zencrypt{END}")
    print(f"Ryanshatch {BOLD}ePortfolio{END} - {BOLD}https://www.ryanshatch.com{END}\n")
    print(f"Thank you for using my Zencrypt {BOLD}v5.2{END} Cipher, the Web App is now successfully up and running:")
    print(f"{BOLD}http://localhost:5000/{END}\n\n")

#* Main function to run the Flask application
if __name__ == '__main__':
    print_startup_banner()                          # Displays the Triforce, ePortfolio, and Zencrypt documentation in the console when the webapp is started
    app.run(debug=True, host='0.0.0.0', port=5000)  # Runs the Flask application on a local server with debug mode enabled