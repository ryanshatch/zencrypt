"""
********************************************************************************************
* Title: Zencrypt WebApp           |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: Febuary 13th 2025  |********************************************************
* Version: 6.2-A                   |********************************************************
********************************************************************************************
*****************************#*| Zencrypt v6.2-A |******************************************
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
- Securely handle MongoDB operations for storing hashes and encrypted texts.               *
- Implement user authentication and session management using JWT tokens.                   *
- Handle file uploads, encryption/decryption, and text input handling.                     *
- Its also important to note that PGP encryption is not implemented currently in v5.3,     *
    but will be in the final stages of Zencrypt v6-A1                                      *
********************************************************************************************
"""

from models import db, User, Hash, EncryptedText, Key, PGPKey  # Add PGPKey here
#* Importing the required libraries for the webapp
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import os
import base64
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from utils import generate_pgp_keypair, pgp_encrypt_message, pgp_decrypt_message
from flask_migrate import Migrate

# #* ---------------------- | Environment & Database Configuration | ---------------------- #

# Load environment variables from .env file
load_dotenv()

# Flask Configuration and JWT Manager
app = Flask(__name__)

# SQLite Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{basedir}/zencrypt.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Create tables
with app.app_context():
    db.create_all()

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# #* ---------------------- | JWT Configuration | ---------------------- #

# secret key and token expiration time of 1 hour
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialize JWT Manager
jwt = JWTManager(app)

# #* ---------------------- | Key Management | ---------------------- #
def initialize_key(user_id):
    """Initialize or retrieve encryption key for a user"""
    # Check for existing active key
    key = Key.query.filter_by(user_id=user_id, active=True).first()
    
    if key:
        return key.key_value.encode()
    
    # Generate new key
    new_key = Fernet.generate_key()
    
    # Store in database
    key_entry = Key(
        key_value=new_key.decode(),
        user_id=user_id
    )
    
    try:
        db.session.add(key_entry)
        db.session.commit()
        return new_key
    except Exception as e:
        db.session.rollback()
        print(f"Error storing key: {e}")
        # Fallback to temporary key if database storage fails
        return Fernet.generate_key()

def get_cipher_suite(user_id):
    """Get Fernet cipher suite for a user"""
    key = initialize_key(user_id)
    return Fernet(key)

def rotate_key(user_id):
    """Rotate encryption key for a user"""
    try:
        # Deactivate old key
        old_key = Key.query.filter_by(user_id=user_id, active=True).first()
        if old_key:
            old_key.active = False
            
        # Generate and store new key
        new_key = Fernet.generate_key()
        key_entry = Key(
            key_value=new_key.decode(),
            user_id=user_id
        )
        
        db.session.add(key_entry)
        db.session.commit()
        
        return new_key
    except Exception as e:
        db.session.rollback()
        print(f"Error rotating key: {e}")
        return None

# #* ---------------------- | Styling and HTML for the Web-App | ---------------------- #

STYLE_TEMPLATE = """
    body {
        background-color: #1e1e1e;
        color: #ffffff;
        font-family: 'Nunito Sans', sans-serif;
        line-height: 1.6;
    }
    .menu form {
    margin: 0;
    padding: 0;
    }

    .menu input[type="file"] {
        display: none;
    }

    .menu button {
        margin: 0 5px;
    }
    .auth-container {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
}
"""

# Define header/banner separately as it's reused
HEADER_TEMPLATE = """
    <div class="header">
        <h1 style="text-align: center; font-family: 'Arial', sans-serif; font-size: 2.5em; margin-bottom: 0.3em;">
            Zencrypt v6.2.2-alpha
        </h1>
        <div style="text-align: center; font-family: 'Helvetica', sans-serif; color: #999;">
            <p style="font-size: 1.1em; margin: 0.5em 0;">
                <span style="font-family: 'Consolas', monospace;">© 2025</span> 
                All rights reserved by 
                <span style="font-family: 'Consolas', monospace; color: #0066ff;">Ryanshatch</span>
            </p>
        </div>
        <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0,102,255,0), rgba(0,102,255,0.75), rgba(0,102,255,0));">
    </div>
"""

# Main application template
APP_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zencrypt Web-App</title>
    <style>
        {STYLE_TEMPLATE}
        .links a {{
            color: #0066ff;
            text-decoration: none;
        }}
        .links a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        {HEADER_TEMPLATE}
        
        {{% if session.get('user_id') %}}
        <!---    <h4>With this web-app you can:</h4>
            <ul>
                <li>Hash text using SHA256, Encrypt text, Decrypt text.</li>
                <li>Handle Encrypting and Decrypting Uploaded Files securely and online.</li>
            </ul>  -->
                <div class="menu">
                    <a href="/"><button>Hash</button></a>
                    <a href="/encrypt"><button>Encrypt</button></a>
                    <a href="/decrypt"><button>Decrypt</button></a>
                    <a href="/file"><button>File Operations</button></a>
                    <a href="/export-key"><button>Export Key</button></a>
                    <form style="display: inline;" action="/import-key" method="POST" enctype="multipart/form-data">
                        <input type="file" name="key_file" style="display: none;" id="key_file">
                        <button type="button" onclick="document.getElementById('key_file').click()">Import Key</button>
                        <script>
                            document.getElementById('key_file').onchange = function() {{
                                this.form.submit();
                            }};
                        </script>
                    </form>
                    <a href="/pgp"><button>PGP Operations</button></a>
                    <a href="/logout"><button>Logout</button></a>
                </div>
<!--            <div class="menu">
                <a href="/"><button>Hash</button></a>
                <a href="/encrypt"><button>Encrypt</button></a>
                <a href="/decrypt"><button>Decrypt</button></a>
                <a href="/file"><button>File Operations</button></a>
                <a href="/logout"><button>Logout</button></a>
            </div>  -->
            <hr>
            {{{{ content | safe }}}}
            {{% if output %}}
                <div class="output">{{{{ output }}}}</div>
            {{% endif %}}
        {{% else %}}
            <div class="auth-container">
                <h2>{{% if request.path == '/register' %}}Register{{% else %}}Login{{% endif %}}</h2>
                {{% if error %}}
                    <div class="error-message">{{{{ error }}}}</div>
                {{% endif %}}
                <form method="POST" action="{{% if request.path == '/register' %}}/register{{% else %}}/login{{% endif %}}">
                    <input type="email" name="email" placeholder="Email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">{{% if request.path == '/register' %}}Register{{% else %}}Login{{% endif %}}</button>
                </form>
                {{% if request.path == '/register' %}}
                    <p>Already have an account? <a href="/login">Login</a></p>
                {{% else %}}
                    <p>Don't have an account? <a href="/register">Register</a></p>
                {{% endif %}}
            </div>
            <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0,102,255,0), rgba(0,102,255,0.75), rgba(0,102,255,0));">
            <div class="links">
                <h6>
                <ul>
                <li><b>White Papers</b> - <a href="https://zencrypt.gitbook.io/zencrypt" target="_blank">https://zencrypt.gitbook.io/zencrypt</a></li>
                <li><b>ePortfolio</b> - <a href="https://www.ryanshatch.com" target="_blank">https://www.ryanshatch.com</a></li>
                </ul>
                </h6>
            </div>
            <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0,102,255,0), rgba(0,102,255,0.75), rgba(0,102,255,0));">
        {{% endif %}}
    </div>
</body>
</html>
"""

# * ---------------------- | Web-App Routes | ---------------------- #
# * Checks if the database is connected and returns an error message if not connected when the webapp is started.
def safe_db_operation(operation): 
    if db is None:                                      # Check if the database is connected
        return None, "Database not connected"           # Return an error message if the database is not connected
    try:
        result = operation()                            # Perform the database operation and store the result
        return result, None                             # Return the result and no error message if the operation is successful
    except Exception as e:                              # Catch any exceptions that occur during the database operation
        print(f"Database operation error: {e}")         # Print an error message if the database operation fails
        return None, str(e)                             # Return no result and an error message if the operation fails

#* ---------------------- | Favicon Route | ---------------------- #
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

#* ---------------------- | Authentication Routes | ---------------------- #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            access_token = create_access_token(identity=user.id)
            session['access_token'] = access_token
            return redirect(url_for('hash_page'))
        
        return render_template_string(APP_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(APP_TEMPLATE)

#* ---------------------- | Registration Route | ---------------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            return render_template_string(APP_TEMPLATE, 
                error="Email and password are required")
            
        if User.query.filter_by(email=email).first():
            return render_template_string(APP_TEMPLATE, 
                error="Email already exists")
        
        try:
            user = User(
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()

            initialize_key(user.id)
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            return render_template_string(APP_TEMPLATE, 
                error=f"Registration failed: {str(e)}")
    
    return render_template_string(APP_TEMPLATE)

#* ---------------------- | Logout Route | ---------------------- #
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
    #* ---------------------- | Deleting Logged Data | ---------------------- #
        # try:
        #     # Clean up user data
        #     Hash.query.filter_by(user_id=user_id).delete()
        #     EncryptedText.query.filter_by(user_id=user_id).delete()
        #     # Deactivate user's keys
        #     Key.query.filter_by(user_id=user_id, active=True).update({"active": False})
        #     db.session.commit()
        # except Exception as e:
        #     db.session.rollback()
        #     print(f"Error cleaning up user data: {e}")
        pass
    
    session.clear()
    return redirect(url_for('login'))

#* ---------------------- | Encryption & Decryption Routes | ---------------------- #
@app.route('/', methods=['GET', 'POST'])
def hash_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to hash"></textarea>
        <br>
        <input type="text" name="salt" placeholder="Salt (optional)">
        <button type="submit">Generate Hash</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        salt = request.form.get('salt', '')
        if text:
            hash_value = hashlib.sha256((text + salt).encode()).hexdigest()
            
            new_hash = Hash(
                hash_value=hash_value,
                salt=salt,
                user_id=session['user_id']
            )
            db.session.add(new_hash)
            db.session.commit()
            
            return render_template_string(APP_TEMPLATE,
                content=content,
                output=f"SHA256 Hash:\n{hash_value}")
    
    return render_template_string(APP_TEMPLATE, content=content)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to encrypt"></textarea>
        <br>
        <button type="submit">Encrypt</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            try:
                cipher_suite = get_cipher_suite(session['user_id'])
                encrypted = cipher_suite.encrypt(text.encode())
                
                # Store in database
                new_encrypted = EncryptedText(
                    encrypted_content=encrypted.decode(),
                    user_id=session['user_id']
                )
                db.session.add(new_encrypted)
                db.session.commit()
                
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Encrypted Text:\n{encrypted.decode()}")
            except Exception as e:
                db.session.rollback()
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Error: {str(e)}")
    
    return render_template_string(APP_TEMPLATE, content=content)

#* Route to the decrypt text page of the web-app with the decryption function
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to decrypt"></textarea>
        <br>
        <button type="submit">Decrypt</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            try:
                cipher_suite = get_cipher_suite(session['user_id'])
                decrypted = cipher_suite.decrypt(text.encode())
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Decrypted Text:\n{decrypted.decode()}")
            except Exception as e:
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Error: {str(e)}")
    
    return render_template_string(APP_TEMPLATE, content=content)

#* ---------------------- | File Operations Route | ---------------------- #
#* Route to the file operations page of the web-app with the file encryption/decryption function
@app.route('/file', methods=['GET', 'POST'])
def file_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    content = """
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <br>
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
            return render_template_string(APP_TEMPLATE,
                content=content,
                output="No file uploaded")
            
        file = request.files['file']
        if file.filename == '':
            return render_template_string(APP_TEMPLATE,
                content=content,
                output="No file selected")
            
        try:
            file_content = file.read()
            salt = os.urandom(16)
            password = request.form.get('password', '').encode()
            operation = request.form.get('operation')
            
            cipher_suite = get_cipher_suite(session['user_id'])
            if operation == 'encrypt':
                encrypted = cipher_suite.encrypt(file_content)
                output = f"File encrypted successfully:\n{base64.b64encode(encrypted).decode()}"
            else:
                decrypted = cipher_suite.decrypt(base64.b64decode(file_content))
                output = f"File decrypted successfully:\n{decrypted.decode()}"
                
            return render_template_string(APP_TEMPLATE,
                content=content,
                output=output)
        except Exception as e:
            return render_template_string(APP_TEMPLATE,
                content=content,
                output=f"Error processing file: {str(e)}")
    
    return render_template_string(APP_TEMPLATE, content=content)

@app.route('/export-key')
def export_key():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        key = Key.query.filter_by(user_id=session['user_id'], active=True).first()
        if key:
            response = app.response_class(
                key.key_value,
                mimetype='application/octet-stream',
                headers={'Content-Disposition': 'attachment;filename=zen_key.key'}
            )
            return response
        return "No active key found", 404
    except Exception as e:
        return f"Error exporting key: {str(e)}", 500

@app.route('/import-key', methods=['POST'])
def import_key():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    if 'key_file' not in request.files:
        return redirect(url_for('hash_page'))
        
    file = request.files['key_file']
    if file.filename == '':
        return redirect(url_for('hash_page'))
        
    try:
        key_content = file.read().decode().strip()
        # Deactivate old key
        Key.query.filter_by(user_id=session['user_id'], active=True).update({"active": False})
        
        # Create new key entry
        new_key = Key(
            key_value=key_content,
            user_id=session['user_id'],
            active=True
        )
        db.session.add(new_key)
        db.session.commit()
        return redirect(url_for('hash_page'))
    except Exception as e:
        db.session.rollback()
        return f"Error importing key: {str(e)}", 500

@app.route('/pgp', methods=['GET'])
def pgp_page():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    content = """
    <form method="POST" action="/pgp/generate">
        <button type="submit">Generate New PGP Key Pair</button>
    </form>
    <hr>
    <form method="POST" action="/pgp/encrypt">
        <textarea name="message" placeholder="Enter message to encrypt"></textarea>
        <br>
        <input type="text" name="recipient_email" placeholder="Recipient's email">
        <button type="submit">Encrypt Message</button>
    </form>
    <hr>
    <form method="POST" action="/pgp/decrypt">
        <textarea name="encrypted_message" placeholder="Enter message to decrypt"></textarea>
        <br>
        <button type="submit">Decrypt Message</button>
    </form>
    """
    
    return render_template_string(APP_TEMPLATE, content=content)

@app.route('/pgp/generate', methods=['POST'])
def generate_pgp():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    try:
        private_key, public_key = generate_pgp_keypair()
        
        # Deactivate old keys
        PGPKey.query.filter_by(user_id=session['user_id'], active=True).update({"active": False})
        
        # Store new keys
        new_keys = PGPKey(
            public_key=public_key,
            private_key=private_key,
            user_id=session['user_id']
        )
        
        db.session.add(new_keys)
        db.session.commit()
        
        return redirect(url_for('pgp_page'))
    except Exception as e:
        return f"Error generating keys: {str(e)}", 500

@app.route('/pgp/encrypt', methods=['POST'])
def pgp_encrypt():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    message = request.form.get('message')
    recipient_email = request.form.get('recipient_email')
    
    try:
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            return "Recipient not found", 404
            
        recipient_key = PGPKey.query.filter_by(user_id=recipient.id, active=True).first()
        if not recipient_key:
            return "Recipient has no active PGP key", 400
            
        encrypted = pgp_encrypt_message(message, recipient_key.public_key)
        return render_template_string(APP_TEMPLATE,
            content="Encrypted message:<br><textarea readonly>%s</textarea>" % encrypted)
    except Exception as e:
        return f"Error encrypting message: {str(e)}", 500

@app.route('/pgp/decrypt', methods=['POST'])
def pgp_decrypt():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    encrypted_message = request.form.get('encrypted_message')
    
    try:
        user_key = PGPKey.query.filter_by(user_id=session['user_id'], active=True).first()
        if not user_key:
            return "No active PGP key found", 400
            
        decrypted = pgp_decrypt_message(encrypted_message, user_key.private_key)
        return render_template_string(APP_TEMPLATE,
            content="Decrypted message:<br><textarea readonly>%s</textarea>" % decrypted)
    except Exception as e:
        return f"Error decrypting message: {str(e)}", 500

#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
#* TRIFORCE ASCII ART BANNER FOR THE WEB-APP     <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
# #* ---------------------- | Triforce ASCII Art Banner | ---------------------- #
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
    print(f"{BOLD}Zencrypt Web-App{END} - Developed And Owned Entirely By Ryanshatch{END}\n")
    print(f"Zencrypt {BOLD}Whitepapers and Docs{END} - {BOLD}https://zencrypt.gitbook.io/zencrypt{END}")
    print(f"{BOLD}ePortfolio{END} - {BOLD}https://www.ryanshatch.com{END}\n")
    print(f"Thank you for using Zencrypt {BOLD}v5.3-A2{END}\n")
    print(f"{BOLD}The Web App is now successfully up and running: http://localhost:5000/{END}\n\n")

#* Main function to run the Flask application
if __name__ == '__main__':
    print_startup_banner()
    if os.getenv('FLASK_ENV') == 'production':
        initialize_key(1) # Initialize the encryption key for the user
        print_startup_banner() # Displays the Triforce, ePortfolio, and Zencrypt documentation in the console when the webapp is started
        app.run(host='0.0.0.0', port=5000)  # Let Nginx handle SSL
    else:
        app.run(host='127.0.0.1', port=5000, debug=True)