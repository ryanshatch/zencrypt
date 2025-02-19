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
        margin: 0;
        padding: 0;
        min-height: 100vh; 
        min-height: -webkit-fill-available;
        display: flex;
        flex-direction: column;
    }
    .container {
        width: 95%;
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
        flex: 1;
    }
    .form-container {
        width: 95%;
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        justify-content: center;
    }
    .form-container form {
        width: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
    }
    .form-container form > * {
        width: 100%;
    }
    .button-wrapper {
        width: 100%;
        display: flex;
        justify-content: center;
        margin-top: 10px;
    }
    textarea, input[type="text"], input[type="password"], input[type="email"] {
        width: 75%;
        padding: 15px;
        margin-bottom: 20px;
        font-size: 16px;
        border-radius: 5px;
        background-color: #2d2d2d;
        color: #ffffff;
        border: 1px solid #444;
        transition: border-color 0.3s ease;
    }
    textarea {
        height: 10vh;
        resize: vertical;
    }
    textarea:focus, input:focus {
        border-color: #0066ff;
        outline: none;
    }
    button {
        width: 100%;
        max-width: 300px;
        padding: 15px;
        font-size: 16px;
        border-radius: 5px;
        background-color: #0066ff;
        color: #ffffff;
        border: none;
        cursor: pointer;
        transition: background-color 0.3s ease;
    }
    button:hover {
        background-color: #0052cc;
    }
    .menu {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: center;
        margin: 20px 0;
    }
    .menu form {
        margin: 0;
        padding: 0;
    }
    .menu input[type="file"] {
        display: none;
    }
    .menu button {
        margin: 0;
        padding: 8px 16px;
        white-space: nowrap;
    }
    .auth-container {
        width: 90%;
        max-width: 400px;
        margin: 20px auto;
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
    }
    @media (max-width: 768px) {
        .container {
            width: 95%;
            padding: 10px;
        }
        .menu {
            flex-direction: column;
            align-items: stretch;
        }
        .menu button {
            width: 100%;
            margin: 5px 0;
        }
    }
    .navbar {
        background-color: #1e1e1e;
        border-bottom: 1px solid #444;
        padding: 1rem;
        position: fixed;
        width: 100%;
        top: 0;
        z-index: 1000;
    }
    .navbar-container {
        max-width: 1200px;
        margin: 0 auto;
    }
    .navbar-brand {
        font-size: 1.5rem;
        font-weight: bold;
        color: #ffffff;
        cursor: pointer;
        user-select: none;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .navbar-menu {
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.3s ease-out;
        position: absolute;
        top: 100%;
        left: 0;
        right: 0;
        background-color: #1e1e1e;
        border-bottom: 1px solid #444;
    }
    .navbar-menu.active {
        max-height: 500px;
    }
    .navbar-menu a {
        display: block;
        padding: 0.5rem 1rem;
        text-decoration: none;
        color: #ffffff;
    }
    .navbar-menu button {
        width: 100%;
        text-align: left;
        padding: 0.8rem;
        background: none;
        border: none;
        color: #ffffff;
        transition: background-color 0.2s;
    }
    .navbar-menu button:hover {
        background-color: #2d2d2d;
    }
    .navbar-divider {
        height: 1px;
        background-color: #444;
        margin: 0.5rem 0;
    }
    .main-content {
        margin-top: 70px; /* Adjust based on navbar height */
    }
"""

# Define header/banner separately as it's reused
HEADER_TEMPLATE = """
    <div class="header">
        <div style="text-align: center; font-family: 'Helvetica', sans-serif; color: #999;">
            <p style="font-size: 1.1em; margin: 0.5em 0;">
                <span style="font-family: 'Consolas', monospace;">© 2025</span> 
                All rights reserved by 
                <span style="font-family: 'Consolas', monospace; color: #0066ff;">Ryanshatch</span>
            </p>
        </div>
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
    <link rel="icon" href="{{ url_for('favicon') }}" type="image/vnd.microsoft.icon">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600&display=swap">
    <style>
        {STYLE_TEMPLATE}
    </style>
</head>
<body>
    <div class="main-content">
        {HEADER_TEMPLATE}
        
        {{% if session.get('user_id') %}}
            <nav class="navbar">
                <div class="navbar-container">
                    <div class="navbar-brand" onclick="toggleMenu()">
                        ☰ Zencrypt Web-App
                        <span style="font-size: 1.2rem;"></span>
                    </div>
                    <div class="navbar-menu" id="navMenu">
                        <a href="/"><button>Hash</button></a>
                        <a href="/encrypt"><button>Encrypt</button></a>
                        <a href="/decrypt"><button>Decrypt</button></a>
                        <div class="navbar-divider"></div>
                        <a href="/file"><button>Files</button></a>
                        <a href="/pgp"><button>PGP</button></a>
                        <div class="navbar-divider"></div>
                        <a href="/export-key"><button>Export Key</button></a>
                        <a href="/import-key"><button>Import Key</button></a>
                        <a href="/logout"><button>Logout</button></a>
                    </div>
                </div>
            </nav>
            <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
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
            <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
            <h1 style="text-align: center;">Zencrypt Web-App</h1>
            <div class="links">
                <h6 style="text-align: center;">
                <li><b>White Papers</b> - <a href="https://zencrypt.gitbook.io/zencrypt" target="_blank">https://zencrypt.gitbook.io/zencrypt</a></li>
                <li><b>ePortfolio</b> - <a href="https://www.ryanshatch.com" target="_blank">https://www.ryanshatch.com</a></li>
                </h6>
            </div>
            <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
        {{% endif %}}
    </div>
    <script>
        function toggleMenu() {{
            const menu = document.getElementById('navMenu');
            menu.classList.toggle('active');
        }}
        document.addEventListener('click', function(event) {{
            const menu = document.getElementById('navMenu');
            const brand = document.querySelector('.navbar-brand');
            if (!menu.contains(event.target) && !brand.contains(event.target)) {{
                menu.classList.remove('active');
            }}
        }});
        window.addEventListener('scroll', function() {{
            const menu = document.getElementById('navMenu');
            menu.classList.remove('active');
        }});
    </script>
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
    <div class="form-container">
        <form method="POST">
            <textarea name="text" placeholder="Enter text to hash"></textarea>
            <input type="text" name="salt" placeholder="Salt (optional)">
            <div class="button-wrapper">
                <button type="submit">Generate Hash</button>
            </div>
        </form>
    </div>
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
    <div class="form-container">
        <form method="POST">
            <textarea name="text" placeholder="Enter text to encrypt"></textarea>
            <div class="button-wrapper">
                <button type="submit">Encrypt</button>
            </div>
        </form>
    </div>
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
    <div class="form-container">
        <form method="POST">
            <textarea name="text" placeholder="Enter text to decrypt"></textarea>
            <div class="button-wrapper">
                <button type="submit">Decrypt</button>
            </div>
        </form>
    </div>
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
    <div class="form-container">
        <form method="POST" enctype="multipart/form-data" style="text-align: center;"><br>
            <input type="file" name="file" required style="display: inline-block;"><br>
            <input type="password" name="password" placeholder="Enter Password:" required>
            <select name="operation" style="width: 100%; padding: 15px; margin-bottom: 20px; background-color: #2d2d2d; color: #ffffff; border: 1px solid #444; border-radius: 5px;">
                <option value="encrypt">Encrypt</option>
                <option value="decrypt">Decrypt</option>
            </select>
            <div class="button-wrapper">
                <button type="submit">Process File</button>
            </div>
        </form>
    </div>
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
    <div class="form-container">
        <form method="POST" action="/pgp/generate">
            <div class="button-wrapper">
                <button type="submit">Generate Keys</button>
            </div>
        </form>
        <form method="POST" action="/pgp/encrypt">
            <textarea name="message" placeholder="Message:"></textarea>
            <input type="text" name="recipient_email" placeholder="Email of recipient" required>
            <div class="button-wrapper">
                <button type="submit">Encrypt</button>
            </div>
        </form>
        <form method="POST" action="/pgp/decrypt">
            <textarea name="encrypted_message" placeholder="Message:"></textarea>
            <div class="button-wrapper">
                <button type="submit">Decrypt</button>
            </div>
        </form>
    </div>
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

ASCII_BANNER = f"""

                           /\\
                          /__\\
                         /\\  /\\
                        /__\\/__\\
                       /\\      /\\
                      /__\\    /__\\
                     /\\  /\\  /\\  /\
                    /__\\/__\\/__\\/__\
                    
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
        app.run(host='0.0.0.0', port=5000)  # Let Nginx handle SSL
    else:
        app.run(host='127.0.0.1', port=5000, debug=True)