from flask import Flask, request, render_template_string, redirect, url_for, session
from cryptography.fernet import Fernet
import hashlib
import os
import base64
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Key management
KEY_FILE = "private.key"

def initialize_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

cipher_suite = Fernet(initialize_key())

# Template for the main application
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
        <h3><b>The Zencrypt Web-Application is still being developed And Owned Entirely By <code>Ryanshatch</code></b></h3>
        <h4><b>Zencrypt Whitepapers and Docs</b> - <b>https://zencrypt.gitbook.io/zencrypt</b></h4>
        <h3><b>Ryanshatch ePortfolio</b> - <b>https://www.ryanshatch.com</b></h3>
        <hr>
        <h3>Online Zencrypt Cipher:</h3>
        <br>
        <h4>With this web-app you can:<br> Hash text using SHA256, Encrypt text, Decrypt text, and also with the ability to handle Encrypting and Decrypting Uploaded Files securely and online.</h4>
        <div class="menu">
            <a href="/"><button>Hash</button></a>
            <a href="/encrypt"><button>Encrypt</button></a>
            <a href="/decrypt"><button>Decrypt</button></a>
            <a href="/file"><button>File Operations</button></a>
        </div>
        
        {{ content | safe }}
        
        {% if output %}
        <div class="output">
            {{ output }}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

# Route handlers
@app.route('/', methods=['GET', 'POST'])
def hash_page():
    output = None
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to hash"></textarea>
        <input type="text" name="salt" placeholder="Salt (optional)">
        <button type="submit">Generate Hash</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        salt = request.form.get('salt', '')
        if text:
            hash_input = (text + salt).encode()
            hash_output = hashlib.sha256(hash_input).hexdigest()
            output = f"SHA256 Hash:\n{hash_output}"
    
    return render_template_string(APP_TEMPLATE, content=content, output=output)

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

BOLD = '\033[1m'
END = '\033[0m'

print(f"{BOLD}Zencrypt Web Application{END} v5.2 {BOLD}is Developed And Owned Entirely By Ryanshatch{END}\n")
print(f"Zencrypt {BOLD}Whitepapers and Docs{END} - {BOLD}https://zencrypt.gitbook.io/zencrypt{END}")
print(f"Ryanshatch {BOLD}ePortfolio{END} - {BOLD}https://www.ryanshatch.com{END}\n")
print(f"Thank you for using my Zencrypt {BOLD}v5.2{END} Cipher, the Web App is now successfully up and running:")
print(f"{BOLD}http://localhost:5000/{END}\n\n")
app.run(debug=True, port=5000)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)