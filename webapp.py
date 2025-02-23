"""*****************************************************************************************
#* Title: Zencrypt WebApp           |*******************************************************
#* Developed by: Ryan Hatch         |*******************************************************
* Date: August 10th 2022            |*******************************************************
#* Last Updated: Febuary 20th 2025  |*******************************************************
* Version: 6.2.2-A                    |*****************************************************
********************************************************************************************
*****************************#*| Zencrypt v6.2.2-A |****************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
******************************#*| Description: |********************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
|              Zencrypt Web-App is a Flask application that can be used to:                |
|       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    |
|       - Encrypt text and files: using Fernet symmetric encryption algorithm.             |
|       - Encrypt/Decrypt files: with AES encryption and secure key management.            |
|       - Handle user authentication: with JWT tokens and secure session management.       |
|       - Store data securely: using SQLite with encrypted storage for sensitive data.     |
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
*****************************************************************************************"""

# Database models
from models import db, User, Hash, EncryptedText, Key, PGPKey

# Core imports for the web-app and Flask
from flask import Flask, request, render_template_string, redirect, send_from_directory, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# Cryptographic imports for encryption and hashing
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash, check_password_hash

# Standard library imports for file handling and hashing
import hashlib
import os
import base64
import secrets
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler

# Local imports for PGP and environment variables
from dotenv import load_dotenv
from utils import generate_pgp_keypair, pgp_encrypt_message, pgp_decrypt_message
from flask_migrate import Migrate

# #* ---------------------- | Database Configuration | ---------------------- #
# Load environment variables from .env file
load_dotenv()

# Flask Configuration and JWT Manager
app = Flask(__name__)

# SQLite Configuration
basedir = os.path.abspath(os.path.dirname(__file__)) # Get the base directory of the current file
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{basedir}/zencrypt.db') 
# Set the database URI to the SQLite database file in the base directory
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Disable modification tracking to suppress warnings and to reduce overhead on the database.

# Initialize database
db.init_app(app)            
migrate = Migrate(app, db)  # Track and manage database migrations

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# #* ---------------------- | Database Initialization | ---------------------- #
def init_db():
    #*Initialize database tables and perform first-time setup if needed
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            
            # Check if this is first-time setup
            if User.query.count() == 0:

                # If no users are returned from the database, the database will be initialized with a first-time setup
                print("Setting up the database for the first time")

            # If the database is already initialized, it will skip the first-time setup
            print("Database initialized successfully")
            
        # Catch any exceptions that occur during the database initialization
        except Exception as e:
            print(f"Database initialization error: {e}")
            raise
# Initialize the database
init_db()

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# #* ---------------------- | JWT Configuration | ---------------------- #
# Set secret key and token expiration time to 30 minutes
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialize JWT Manager
jwt = JWTManager(app)

# #* ---------------------- | Key Management | ---------------------- #
def initialize_key(user_id):
    #*Initialize or retrieve encryption key for a user
    key = Key.query.filter_by(user_id=user_id, active=True).first() # Check if an active key exists already for the user
    
    if key:
        # If an active key exists, return the key value as bytes
        return key.key_value.encode()
    
    # If there is no active key then generate a new key and parse it as new_key
    new_key = Fernet.generate_key()
    
    key_entry = Key( # Create a new key entry in the database
        key_value=new_key.decode(), # Decode the new key and store it in the database
        user_id=user_id # Store the user_id with the key
    )
    
    try:
        db.session.add(key_entry)           # Add the new key to the database as key_entry
        db.session.commit()                 # Commit the new key to the database
        return new_key                      # If the key is successfully added to the database, return new_key as the new key 
    except Exception as e:                  # Catch any exceptions that occur during the key initialization
        db.session.rollback()               # Rollback the database session if an exception occurs
        print(f"Error storing key: {e}")    # Print an error message if the key initialization fails
                                            # Fallback to temporary key if database storage fails
        return Fernet.generate_key()

def get_cipher_suite(user_id):
    #*Get the Fernet cipher suite for a user based on their encryption key
    key = initialize_key(user_id) # Initialize the key for the user and store it as key
    return Fernet(key)            # Return the Fernet cipher suite with the key

def rotate_key(user_id):
    #*Rotate encryption key for a user
    try:
        #* Deactivate old key
        old_key = Key.query.filter_by(user_id=user_id, active=True).first() # Check through the database for an active key assigned to the user id and store it as old_key
        if old_key:                 # If an active key is found already to be assigned to the user id
            old_key.active = False  # Deactivate the old key
            
        # Generate and store new key
        new_key = Fernet.generate_key() # Generate a new key and store it as new_key
        key_entry = Key(                # Create a new key entry in the database
            key_value=new_key.decode(), # Decode the new key and store it in the database
            user_id=user_id             # Store the user_id with the key
        )
        
        db.session.add(key_entry) # Add the new key to the database as key_entry
        db.session.commit()       # Commit the new key to the database as key_entry with a child relationship to the user_id 
        
        return new_key                       # Return the new key if the key rotation is successful
    except Exception as e:                   # Catch any exceptions that occur during the key rotation
        db.session.rollback()                # Rollback the database session if an exception occurs
        print(f"Error rotating key: {e}")    # Print an error message if the key rotation fails
        return None                          # Return None if the key rotation fails

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #* ---------------------- | Styling and HTML for the Web-App | ---------------------- #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

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

# #* ---------------------- | Header Template | ---------------------- #
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

# #* ---------------------- | Web-App Template | ---------------------- #
APP_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zencrypt Web-App</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600&display=swap">
    <style>
        {STYLE_TEMPLATE}
    </style>
    <script crossorigin src="https://unpkg.com/react@17/umd/react.development.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
</head>
<body>
    <div class="main-content">
        {HEADER_TEMPLATE}
        
        {{% if session.get('user_id') %}}
            <nav class="navbar">
                <div class="navbar-container">
                    <div class="navbar-brand" onclick="toggleMenu()">
                        ☰ Zencrypt Web-App
                        <span style="font-size: 0.6rem;"></span>
                    </div>
                    <div class="navbar-menu" id="navMenu">
                        <div class="navbar-divider"></div>
                        <a href="/logout"><button>Logout</button></a>
                        <div class="navbar-divider"></div>
                        <a href="/"><button>Hash</button></a>
                        <a href="/encrypt"><button>Encrypt</button></a>
                        <a href="/decrypt"><button>Decrypt</button></a>
                        <div class="navbar-divider"></div>
                        <a href="/file"><button>Files</button></a>
                        <a href="/pgp"><button>PGP</button></a>
                        <div class="navbar-divider"></div>
                        <a href="/export-key"><button>Export Key</button></a>
                        <a href="/import-key"><button>Import Key</button></a>
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
                    <input type="hidden" name="csrf_token" value="{{{{ csrf_token() }}}}">
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
    return send_from_directory(                      # Return the favicon.ico file from the static directory
        os.path.join(app.root_path, 'static'),       # Join the root path of the app with the static directory
        'favicon.ico',                               # Return the favicon.ico file
        mimetype='image/vnd.microsoft.icon'          # Set the mimetype of the file to image/vnd.microsoft.icon
    )

#* ---------------------- | Authentication Routes | ---------------------- #
#* Route to the login page of the web-app with the login function for user authentication

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "30 per hour"]
)
@app.route('/login', methods=['GET', 'POST'])      # Route to the login page of the web-app with the login function
@limiter.limit("10 per minute")                     # Limit the number of login attempts to 10 per minute
def login():
    if request.method == 'POST':                # Check if the request method is POST
        email = request.form.get('email')       # Get the email from the form input for the user
        password = request.form.get('password') # Get the password from the form input for the user
        
        # NOTE: 
        #*  Each email acts as a UID for the user, so the keys have a one-to-one relationship with the user
        user = User.query.filter_by(email=email).first() # Query the database for the user with the email and store it as user
        
        if user and check_password_hash(user.password_hash, password): 
            #* Check if the user exists and the password is correct
            session['user_id'] = user.id                         # Store the user id in the session as user_id
            access_token = create_access_token(identity=user.id) # Create an access token for the user with the user id
            session['access_token'] = access_token               # Store the access token in the session as access_token
            return redirect(url_for('hash_page'))                # Redirect to the hash page if the login is successful
        
        return render_template_string(APP_TEMPLATE, error="Invalid credentials")    # Catch invalid credentials and return an error message

    return render_template_string(APP_TEMPLATE) # Return the APP_TEMPLATE if the request method is not POST

#* ---------------------- | Registration Route | ---------------------- #

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST': # Check if the request method is POST
        email = request.form.get('email')   # Get the email from the form input for the user
        password = request.form.get('password') # Get the password from the form input for the user
        
        if not email or not password:   # Make sure that the email and password are not empty strings
            return render_template_string(APP_TEMPLATE,  
            # Catch empty email and password fields and return an error message
                error="Email and password are required")
            
        if User.query.filter_by(email=email).first(): # Check if the email already exists in the database
            return render_template_string(APP_TEMPLATE,  # Catch if the email already exists and return an error message
                error="Email already exists")
        
        try:
            user = User(    # Create a new user with the email and password
                email=email,    # Store the email in the user object
                password_hash=generate_password_hash(password)  # Store the hashed password in the database as the password_hash for the user
            )
            db.session.add(user)   # Add the new user to the database 
            db.session.commit()   # Commit the new user to the database

            initialize_key(user.id) # Initialize the key for the user with the user id
            return redirect(url_for('login')) # Redirect to the login page after registration is successful
        except Exception as e: # Catch any exceptions that occur during the registration process
            db.session.rollback() # Rollback the database session if an exception occurs
            return render_template_string(APP_TEMPLATE, 
                error=f"Registration failed: {str(e)}")
    
    return render_template_string(APP_TEMPLATE)

#* ---------------------- | Logout Route | ---------------------- #
#* Route to the logout page of the web-app with the logout function
@app.route('/logout')
def logout():
    user_id = session.get('user_id') # Get the user id from the session 
    if user_id: # Check if the user id exists
    #* ---------------------- | Deleting Logged Data | ---------------------- #
        #// try:
        #//     # Clean up user data
        #//     Hash.query.filter_by(user_id=user_id).delete()
        #//     EncryptedText.query.filter_by(user_id=user_id).delete()
        #//     # Deactivate user's keys
        #//     Key.query.filter_by(user_id=user_id, active=True).update({"active": False})
        #//     db.session.commit()
        #// except Exception as e:
        #//     db.session.rollback()
        #//     print(f"Error cleaning up user data: {e}")
        #* If the user id exists in the session, continue to the log out process
        pass
    
    session.clear() # Clear the session after the user logs out
    return redirect(url_for('login')) # After the user logs out, the user is redirected to the login page

#* ---------------------- | SHA256 Hash Route | ---------------------- #
#* Route to the hash page of the web-app with the hashing function
@app.route('/', methods=['GET', 'POST'])
def hash_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    content = """
    <div class="form-container">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="text" placeholder="Enter text to hash"></textarea>
            <input type="text" name="salt" placeholder="Salt (optional)">
            <div class="button-wrapper">
                <button type="submit">Generate Hash</button>
            </div>
        </form>
    </div>
    """
    
    if request.method == 'POST':    # Check if the request method is POST
        text = request.form.get('text', '') # Get the text from the form input for the user
        salt = request.form.get('salt', '') # Get the salt from the form input for the user
        if text:
            hash_value = hashlib.sha256((text + salt).encode()).hexdigest() # Generate the SHA256 hash value with the text and salt
            
            new_hash = Hash(   # Create a new hash entry in the database
                hash_value=hash_value, # Store the hash value in the database
                salt=salt,             # Store the salt in the database
                user_id=session['user_id'] # Store the user id with the hash
            )
            db.session.add(new_hash) # Add the new hash to the database as new_hash
            db.session.commit()     # Commit the new hash to the database as new_hash
            
            return render_template_string(APP_TEMPLATE, 
            # Return the APP_TEMPLATE with the html content and the sha256 hash value
                content=content,
                output=f"SHA256 Hash:\n{hash_value}")
    
    return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content

#* ---------------------- | Encrypt Text Route | ---------------------- #
#* Route to the encrypt text page of the web-app with the encryption function
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    content = """
    <div class="form-container">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="text" placeholder="Enter text to encrypt"></textarea>
            <div class="button-wrapper">
                <button type="submit">Encrypt</button>
            </div>
        </form>
    </div>
    """
    
    if request.method == 'POST': # Check if the request method is POST
        text = request.form.get('text', '') # Get the text from the form input for the user
        if text: # Check if the text is not an empty string
            try:
                cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
                encrypted = cipher_suite.encrypt(text.encode()) # Encrypt the text with the cipher suite and store it as encrypted
                
                #* Store in database
                new_encrypted = EncryptedText( # Create a new encrypted text entry in the database
                    encrypted_content=encrypted.decode(), # Decode the encrypted content and store it in the database
                    user_id=session['user_id'] # Store the user id with the encrypted content
                )
                db.session.add(new_encrypted) # Add the new encrypted text to the database as new_encrypted
                db.session.commit() # Commit the new encrypted text to the database
                
                return render_template_string(APP_TEMPLATE,
                # Return the APP_TEMPLATE with the html content and the encrypted text
                    content=content,
                    output=f"Encrypted Text:\n{encrypted.decode()}")
            # Catch any exceptions that occur during the encryption process
            except Exception as e:
                db.session.rollback() # Rollback the database session if an exception occurs
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Error: {str(e)}") # Return an error message if the encryption fails
    
    return render_template_string(APP_TEMPLATE, content=content)

#* ---------------------- | Decrypt Text Route | ---------------------- #
#* Route to the decrypt text page of the web-app with the decryption function
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    content = """
    <div class="form-container">
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="text" placeholder="Enter text to decrypt"></textarea>
            <div class="button-wrapper">
                <button type="submit">Decrypt</button>
            </div>
        </form>
    </div>
    """
    
    if request.method == 'POST': # Check if the request method is POST
        text = request.form.get('text', '') # Get the text from the form input for the user
        if text: # Check if the text is not an empty string
            try:
                cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
                decrypted = cipher_suite.decrypt(text.encode()) # Decrypt the text with the cipher suite and store it as decrypted
                return render_template_string(APP_TEMPLATE,
                # Return the APP_TEMPLATE with the html content and the decrypted text
                    content=content,
                    output=f"Decrypted Text:\n{decrypted.decode()}")
            # Catch any exceptions that occur during the decryption process
            except Exception as e:
                return render_template_string(APP_TEMPLATE,
                    content=content,
                    output=f"Error: {str(e)}") # Return an error message if the decryption fails
    
    return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is not POST

#* ---------------------- | File Operations Route | ---------------------- #
#* Route to the file operations page of the web-app with the file encryption/decryption function
@app.route('/file', methods=['GET', 'POST'])
def file_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    content = """
    <div class="form-container">
        <form method="POST" enctype="multipart/form-data" style="text-align: center;">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="file-upload-wrapper" style="margin: 20px 0;">
                <label for="file-upload" class="custom-file-upload" style="
                    display: inline-block;
                    padding: 10px 20px;
                    background: #2d2d2d;
                    color: #fff;
                    border: 1px solid #444;
                    border-radius: 5px;
                    cursor: pointer;
                    margin-bottom: 10px;">
                    Choose File
                </label>
                <input id="file-upload" type="file" name="file" required style="display: none;">
                <div id="file-name" style="margin-top: 5px; color: #999;"></div>
            </div>
            <input type="password" name="password" placeholder="Enter Password" required style="width: 75%;">
            <select name="operation" style="
                width: 75%;
                padding: 15px;
                margin: 20px 0;
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #444;
                border-radius: 5px;">
                <option value="encrypt">Encrypt File</option>
                <option value="decrypt">Decrypt File</option>
            </select>
            <div class="button-wrapper">
                <button type="submit">Process File</button>
            </div>
        </form>
    </div>
    <script>
        document.getElementById('file-upload').onchange = function() {
            document.getElementById('file-name').textContent = this.files[0] ? this.files[0].name : '';
        };
    </script>
    """
    
    if request.method == 'POST': # Check if the request method is POST
        if 'file' not in request.files: # Check if the file is not in the request files
            return render_template_string(APP_TEMPLATE,
            # Catch if the file is not selected and return an error message
                content=content,
                output="Please select a file to process")
            
        file = request.files['file'] # Get the file from the request files for the user
        if file.filename == '': # Check if the file name is an empty string
            return render_template_string(APP_TEMPLATE,
            # Catch if the file name is empty and return an error message
                content=content,
                output="No file selected") # Return an error message that no file was selected
            
        try:
            file_content = file.read() # Read the file content and store it as file_content
            password = request.form.get('password', '').encode() # Get the password from the form input for the user and encode it
            operation = request.form.get('operation') # Get the operation from the form input for the user
            
            if not password: # Check if the password is an empty string 
                return render_template_string(APP_TEMPLATE,
                # Catch if the password is empty and return an error message that the password is required
                    content=content,
                    output="Password is required")
            
            cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
            if operation == 'encrypt': # Check if the operation is to encrypt the file
                encrypted = cipher_suite.encrypt(file_content) # Encrypt the file content with the cipher suite and store it as encrypted
                return render_template_string(APP_TEMPLATE,
                # Return the APP_TEMPLATE with the html content and the encrypted file content
                    content=content,
                    output=f"File encrypted successfully!\nEncrypted content:\n{base64.b64encode(encrypted).decode()}")
            else: # If the operation is not set to encrypt, and is set to decrypt
                try: # Try to decrypt the file content with the cipher suite
                    decrypted = cipher_suite.decrypt(base64.b64decode(file_content)) # Decrypt the file content with the cipher suite and store it as decrypted
                    return render_template_string(APP_TEMPLATE, 
                    # Return the APP_TEMPLATE with the html content and the decrypted file content
                        content=content,
                        output=f"File decrypted successfully!\nDecrypted content:\n{decrypted.decode()}")
                except Exception:
                    # Catch any exceptions if the file is invalid or the password is incorrect
                    return render_template_string(APP_TEMPLATE,
                        content=content,
                        output="Invalid encrypted file or wrong password")
                
        except Exception as e: # Catch any exceptions that occur during the file processing
            return render_template_string(APP_TEMPLATE,
                content=content,
                # Return an error message if the file processing fails
                output=f"Error processing file: {str(e)}")
    
    return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is not POST

#* ---------------------- | Export/Import Key Routes | ---------------------- #
@app.route('/export-key')
def export_key():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    try:
        key = Key.query.filter_by(user_id=session['user_id'], active=True).first() # Get the key for the user based on the user id
        if key:
            key_name = request.args.get('key_name', 'zen_key')  # Default to 'zen_key' if no name provided
            response = app.response_class( # Create a response class with the key value as the key content
                key.key_value,  # Set the key value as the key content
                mimetype='application/octet-stream',    # Set the mimetype of the key to "application/octet-stream" to download the key
                headers={'Content-Disposition': f'attachment;filename={key_name}.key'} # Name the key file with the key_name provided when downloading
            )
            return response # If the key is found, download the key file with the key value as the content
        return "No active key found", 404 # Return an error 404 message if no active key is found
        # Catch any other exceptions that could occur during the process of exporting the key
    except Exception as e:
        return f"Error exporting key: {str(e)}", 500 # Return an error 500 message if the key export fails

@app.route('/import-key', methods=['GET', 'POST'])
def import_key():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    if request.method == 'GET': # Check if the request method is GET to show the file upload form
        #* Displays the file upload form for importing a key
        content = """
        <div class="form-container">
            <form method="POST" action="/import-key" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="file" name="key_file" style="display: none;" id="key_file" onchange="this.form.submit()">
                <button type="button" onclick="document.getElementById('key_file').click()">Import Key</button>
            </form>
        </div>
        """

        return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is GET
    
    #* Process the key file upload and import the key if the request method is POST
    if 'key_file' not in request.files: # Check if the key file is not in the request files
        return redirect(url_for('hash_page')) # If the key file is not in the request files, redirect to the hash page
        
    file = request.files['key_file'] # Get the key file from the request files for the user
    if file.filename == '': # Check if the key file name is an empty string
        return redirect(url_for('hash_page')) # If the key file name is an empty string, redirect to the hash page
        
    try: # Try to import the key file and store the key value in the database
        key_content = file.read().decode().strip() # Read the key file content and store it as key_content after decoding and stripping the whitespaces
        #* Deactivate any existing keys
        Key.query.filter_by(user_id=session['user_id'], active=True).update({"active": False}) # Deactivate any existing keys for the user and update the active status to False in the database
        
        #* Store the new key in the database
        new_key = Key(
            key_value=key_content, # Store the key content in the database
            user_id=session['user_id'], # Store the user id with the key content
            active=True # Set the key status to active in the database
        )
        db.session.add(new_key) # Add the new key to the database as new_key
        db.session.commit() # Commit the new key to the database
        return redirect(url_for('hash_page')) # Redirect to the hash page after the key is imported successfully
    
    except Exception as e:
        db.session.rollback() # Rollback the database session if an exception occurs during the key import process
        # Catch any exceptions that occur during the key import process and return an error message 500
        return f"Error importing key: {str(e)}", 500
    
#* ---------------------- | PGP Routes | ---------------------- #
@app.route('/pgp', methods=['GET'])
def pgp_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    content = """
    <div class="form-container">
        <form method="POST" action="/pgp/generate">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="button-wrapper">
                <button type="submit">Generate Keys</button>
            </div>
        </form>
        <form method="POST" action="/pgp/encrypt">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="message" placeholder="Message:"></textarea>
            <input type="text" name="recipient_email" placeholder="Email of recipient" required>
            <div class="button-wrapper">
                <button type="submit">Encrypt</button>
            </div>
        </form>
        <form method="POST" action="/pgp/decrypt">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <textarea name="encrypted_message" placeholder="Message:"></textarea>
            <div class="button-wrapper">
                <button type="submit">Decrypt</button>
            </div>
        </form>
    </div>
    """
    
    return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content for the PGP page

#* ---------------------- | PGP Key Generation  | ---------------------- #
@app.route('/pgp/generate', methods=['POST'])
def generate_pgp():
    if not session.get('user_id'):        # Check if the user id exists in the session
        return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
    try:
        # Generate a new PGP key pair and store the private and public keys in the database
        private_key, public_key = generate_pgp_keypair()
        
        # Deactivate existing keys for the user
        PGPKey.query.filter_by(user_id=session['user_id'], active=True).update({"active": False})
        
        # Store new keys
        new_keys = PGPKey(
            public_key=public_key,      # Store the public key in the database
            private_key=private_key,    # Store the private key in the database
            user_id=session['user_id']  # Store the user id and their keys in the database with a one-to-one relationship with the user
        )
        
        db.session.add(new_keys)        # Add the new keys to the database
        db.session.commit()             # Commit the new keys to the database after generating the PGP key pair
        
        return redirect(url_for('pgp_page'))
    # Redirect to the PGP page after generating the PGP key pair
    except Exception as e:  
        # Catch any exceptions that occur during the PGP key generation process and return an error message 500
        return f"Error generating keys: {str(e)}", 500

#* ---------------------- | PGP Encryption | ---------------------- #
@app.route('/pgp/encrypt', methods=['POST'])
def pgp_encrypt():
    if not session.get('user_id'):          # Check if the user id exists in the session
        return redirect(url_for('login'))   # If the user id does not exist, redirect to the login page
    
    message = request.form.get('message')   # Get the message from the form input for the user

    # Get the recipient email from the form input for the user
    recipient_email = request.form.get('recipient_email')
    
    try:
        # Query the database for the recipient based on the recipient email
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:                       # Check if the recipient exists
            return "Recipient not found", 404   # Return an error 404 message if the recipient is not found
            
        # Query the database for the recipient's PGP key based on the recipient id
        recipient_key = PGPKey.query.filter_by(user_id=recipient.id, active=True).first()
        if not recipient_key:                               # Check if the recipient has an active PGP key
            return "Recipient has no active PGP key", 400   # Return an error 400 message if the recipient has no active PGP key
            
        encrypted = pgp_encrypt_message(message, recipient_key.public_key)  # Encrypt the message with the recipient's public key
        return render_template_string(APP_TEMPLATE,
            # Return the APP_TEMPLATE with the html content and the encrypted message
            content="Encrypted message:<br><textarea readonly>%s</textarea>" % encrypted) # Display the encrypted message in a read only field
    except Exception as e:
        # Catch any exceptions that occur during the PGP encryption process and return an error message 500
        return f"Error encrypting message: {str(e)}", 500

#* ---------------------- | PGP Decryption | ---------------------- #
@app.route('/pgp/decrypt', methods=['POST'])
def pgp_decrypt():
    if not session.get('user_id'):          # Check if the user id exists in the session
        return redirect(url_for('login'))   # If the user id does not exist, redirect to the login page
    
    encrypted_message = request.form.get('encrypted_message') # Get the encrypted message from the form input for the user
    
    try:
        # Query the database for the user's active PGP key based on the user id
        user_key = PGPKey.query.filter_by(user_id=session['user_id'], active=True).first()
        if not user_key:                            # Check if the user has an active PGP key
            # Return an error 400 message if the user doesnt already have an active PGP key
            return "No active PGP key found", 400
            
        decrypted = pgp_decrypt_message(encrypted_message, user_key.private_key) 
        # Decrypt the message with the user's private key
        return render_template_string(APP_TEMPLATE,
            # Display the decrypted message in a read only field
            content="Decrypted message:<br><textarea readonly>%s</textarea>" % decrypted)
    except Exception as e:
        # Catch any exceptions that occur during the PGP decryption process and return an error message 500
        return f"Error decrypting message: {str(e)}", 500
    
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
                     /\\  /\\  /\\  /\\
                    /__\\/__\\/__\\/__\\
                    
"""
#* ---------------------- | Console Startup | ---------------------- #
from colorama import init, Style
init()
#* Function to print the Zencrypt banner in the console along with Zencrypt whitepapers and ePortfolio links to my website.
def print_startup_banner():
    print(ASCII_BANNER) # Print the Triforce
    print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>{Style.RESET_ALL}\n")
    print(f"{Style.BRIGHT}Zencrypt Web-App{Style.RESET_ALL} - Developed And Owned Entirely By Ryanshatch\n")
    print(f"{Style.BRIGHT}- Whitepapers and Docs{Style.RESET_ALL} - {Style.BRIGHT}https://zencrypt.gitbook.io/zencrypt{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}- ePortfolio{Style.RESET_ALL} - {Style.BRIGHT}https://www.ryanshatch.com{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}\nZencrypt version 6.2.2-alpha: Initializing... {Style.RESET_ALL}\n")
    print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>{Style.RESET_ALL}\n")


#* ---------------------- | Main Function to Run the Flask Application | ---------------------- #
# Main function to run the Flask application
if __name__ == '__main__':
    print_startup_banner() #* Print the Zencrypt banner in the console
    
    #* Initialize database first
    init_db()
    
    if os.getenv('FLASK_ENV') == 'production': 
        # Check if the Flask environment is set to "production mode"
        with app.app_context(): 
            # Sets context to Run the app and initialize the encryption key for the default user
            try:
                #* Initialize the encryption key for the default user
                default_user = User.query.first() 
                # Check if the default user exists in the database
                if default_user: 
                    # If the default user exists, initialize the encryption key for the default user
                    initialize_key(default_user.id)
                    print("\nThe encryption key has been initialized for the default user\n")
                    print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")

                else:
                    # Catch an exception if the default user is not found in the database
                    print("Warning: \nNo default user was found in the database\n\n")
                    print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")
            except Exception as e:
                # Catch an exception if the encryption key initialization fails for the key
                print(f"Error initializing key: {e}\n\n")
                print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")
        
        #* Run the Flask app in "production mode"
        app.run(host='0.0.0.0', port=5000)
    else:
        #* Run the Flask app in "development mode"
        print_startup_banner()
        init_db()
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

#* ---------------------- | End of Zencrypt | ------------------------ #
# """*******************************************************************
# #* Title: Zencrypt WebApp Copy      |*********************************
# #* ---------------------- | Web-App Imports | ---------------------- #

# # Database models
# from models import db, User, Hash, EncryptedText, Key, PGPKey

# # Core imports for the web-app and Flask
# from flask import Flask, request, render_template_string, redirect, send_from_directory, url_for, session, jsonify
# from flask_sqlalchemy import SQLAlchemy
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from flask_wtf.csrf import CSRFProtect

# # Cryptographic imports for encryption and hashing
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization
# from werkzeug.security import generate_password_hash, check_password_hash

# # Standard library imports for file handling and hashing
# import hashlib
# import os
# import base64
# import secrets
# from datetime import timedelta

# # Local imports for PGP and environment variables
# from dotenv import load_dotenv
# from utils import generate_pgp_keypair, pgp_encrypt_message, pgp_decrypt_message
# from flask_migrate import Migrate

# # #* ---------------------- | Database Configuration | ---------------------- #
# # Load environment variables from .env file
# load_dotenv()

# # Flask Configuration and JWT Manager
# app = Flask(__name__)

# # SQLite Configuration
# basedir = os.path.abspath(os.path.dirname(__file__)) # Get the base directory of the current file
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', f'sqlite:///{basedir}/zencrypt.db') 
# # Set the database URI to the SQLite database file in the base directory
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# # Disable modification tracking to suppress warnings and to reduce overhead on the database.

# # Initialize database
# db.init_app(app)            
# migrate = Migrate(app, db)  # Track and manage database migrations

# # #* ---------------------- | Database Initialization | ---------------------- #
# def init_db():
#     #*Initialize database tables and perform first-time setup if needed
#     with app.app_context():
#         try:
#             # Create tables if they don't exist
#             db.create_all()
            
#             # Check if this is first-time setup
#             if User.query.count() == 0:

#                 # If no users are returned from the database, the database will be initialized with a first-time setup
#                 print("Setting up the database for the first time")

#             # If the database is already initialized, it will skip the first-time setup
#             print("Database initialized successfully")
            
#         # Catch any exceptions that occur during the database initialization
#         except Exception as e:
#             print(f"Database initialization error: {e}")
#             raise
# # Initialize the database
# init_db()

# app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24)) # Set the secret key for the app to a random 24-byte string

# #* ---------------------- | CSRF Protection | ---------------------- #
# # Initialize CSRF Protection
# csrf = CSRFProtect(app)

# # #* ---------------------- | JWT Configuration | ---------------------- #
# # Set secret key and token expiration time to 30 minutes
# app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# # Initialize JWT Manager
# jwt = JWTManager(app)

# # #* ---------------------- | Key Management | ---------------------- #
# def initialize_key(user_id):
#     #*Initialize or retrieve encryption key for a user
#     key = Key.query.filter_by(user_id=user_id, active=True).first() # Check if an active key exists already for the user
    
#     if key:
#         # If an active key exists, return the key value as bytes
#         return key.key_value.encode()
    
#     # If there is no active key then generate a new key and parse it as new_key
#     new_key = Fernet.generate_key()
    
#     key_entry = Key( # Create a new key entry in the database
#         key_value=new_key.decode(), # Decode the new key and store it in the database
#         user_id=user_id # Store the user_id with the key
#     )
    
#     try:
#         db.session.add(key_entry)           # Add the new key to the database as key_entry
#         db.session.commit()                 # Commit the new key to the database
#         return new_key                      # If the key is successfully added to the database, return new_key as the new key 
#     except Exception as e:                  # Catch any exceptions that occur during the key initialization
#         db.session.rollback()               # Rollback the database session if an exception occurs
#         print(f"Error storing key: {e}")    # Print an error message if the key initialization fails
#                                             # Fallback to temporary key if database storage fails
#         return Fernet.generate_key()

# def get_cipher_suite(user_id):
#     #*Get the Fernet cipher suite for a user based on their encryption key
#     key = initialize_key(user_id) # Initialize the key for the user and store it as key
#     return Fernet(key)            # Return the Fernet cipher suite with the key

# def rotate_key(user_id):
#     #*Rotate encryption key for a user
#     try:
#         #* Deactivate old key
#         old_key = Key.query.filter_by(user_id=user_id, active=True).first() # Check through the database for an active key assigned to the user id and store it as old_key
#         if old_key:                 # If an active key is found already to be assigned to the user id
#             old_key.active = False  # Deactivate the old key
            
#         # Generate and store new key
#         new_key = Fernet.generate_key() # Generate a new key and store it as new_key
#         key_entry = Key(                # Create a new key entry in the database
#             key_value=new_key.decode(), # Decode the new key and store it in the database
#             user_id=user_id             # Store the user_id with the key
#         )
        
#         db.session.add(key_entry) # Add the new key to the database as key_entry
#         db.session.commit()       # Commit the new key to the database as key_entry with a child relationship to the user_id 
        
#         return new_key                       # Return the new key if the key rotation is successful
#     except Exception as e:                   # Catch any exceptions that occur during the key rotation
#         db.session.rollback()                # Rollback the database session if an exception occurs
#         print(f"Error rotating key: {e}")    # Print an error message if the key rotation fails
#         return None                          # Return None if the key rotation fails

# app.config['SESSION_COOKIE_SECURE'] = True       # Secure cookie policy for HTTPS
# app.config['SESSION_COOKIE_SAMESITE'] = 'Strict' # SameSite cookie policy for CSRF protection

# #* ---------------------- | Strict Transport Security | ---------------------- #
# @app.after_request
# def add_security_headers(response):
#     response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
#     return response

# #* ---------------------- | X-Content-Type-Options | ---------------------- #
# @app.after_request
# def add_security_headers(response):
#     response.headers['X-Content-Type-Options'] = 'nosniff'
#     return response

# #* ---------------------- | Content Security Policy | ---------------------- #
# @app.after_request
# def add_security_headers(response):
#     response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://fonts.googleapis.com"
#     return response

# #* ---------------------- | Anti-Clickjacking | ---------------------- #
# @app.after_request 
# def add_security_headers(response):
#     response.headers['X-Frame-Options'] = 'DENY'
#     return response

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # #* ---------------------- | Styling and HTML for the Web-App | ---------------------- #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# STYLE_TEMPLATE = """
#     body {
#         background-color: #1e1e1e;
#         color: #ffffff;
#         font-family: 'Nunito Sans', sans-serif;
#         line-height: 1.6;
#         margin: 0;
#         padding: 0;
#         min-height: 100vh; 
#         min-height: -webkit-fill-available;
#         display: flex;
#         flex-direction: column;
#     }
#     .container {
#         width: 95%;
#         max-width: 1200px;
#         margin: 0 auto;
#         padding: 20px;
#         flex: 1;
#     }
#     .form-container {
#         width: 95%;
#         max-width: 1200px;
#         margin: 0 auto;
#         display: flex;
#         justify-content: center;
#     }
#     .form-container form {
#         width: 100%;
#         display: flex;
#         flex-direction: column;
#         align-items: center;
#     }
#     .form-container form > * {
#         width: 100%;
#     }
#     .button-wrapper {
#         width: 100%;
#         display: flex;
#         justify-content: center;
#         margin-top: 10px;
#     }
#     textarea, input[type="text"], input[type="password"], input[type="email"] {
#         width: 75%;
#         padding: 15px;
#         margin-bottom: 20px;
#         font-size: 16px;
#         border-radius: 5px;
#         background-color: #2d2d2d;
#         color: #ffffff;
#         border: 1px solid #444;
#         transition: border-color 0.3s ease;
#     }
#     textarea {
#         height: 10vh;
#         resize: vertical;
#     }
#     textarea:focus, input:focus {
#         border-color: #0066ff;
#         outline: none;
#     }
#     button {
#         width: 100%;
#         max-width: 300px;
#         padding: 15px;
#         font-size: 16px;
#         border-radius: 5px;
#         background-color: #0066ff;
#         color: #ffffff;
#         border: none;
#         cursor: pointer;
#         transition: background-color 0.3s ease;
#     }
#     button:hover {
#         background-color: #0052cc;
#     }
#     .menu {
#         display: flex;
#         flex-wrap: wrap;
#         gap: 10px;
#         justify-content: center;
#         margin: 20px 0;
#     }
#     .menu form {
#         margin: 0;
#         padding: 0;
#     }
#     .menu input[type="file"] {
#         display: none;
#     }
#     .menu button {
#         margin: 0;
#         padding: 8px 16px;
#         white-space: nowrap;
#     }
#     .auth-container {
#         width: 90%;
#         max-width: 400px;
#         margin: 20px auto;
#         position: absolute;
#         top: 50%;
#         left: 50%;
#         transform: translate(-50%, -50%);
#     }
#     @media (max-width: 768px) {
#         .container {
#             width: 95%;
#             padding: 10px;
#         }
#         .menu {
#             flex-direction: column;
#             align-items: stretch;
#         }
#         .menu button {
#             width: 100%;
#             margin: 5px 0;
#         }
#     }
#     .navbar {
#         background-color: #1e1e1e;
#         border-bottom: 1px solid #444;
#         padding: 1rem;
#         position: fixed;
#         width: 100%;
#         top: 0;
#         z-index: 1000;
#     }
#     .navbar-container {
#         max-width: 1200px;
#         margin: 0 auto;
#     }
#     .navbar-brand {
#         font-size: 1.5rem;
#         font-weight: bold;
#         color: #ffffff;
#         cursor: pointer;
#         user-select: none;
#         display: flex;
#         justify-content: space-between;
#         align-items: center;
#     }
#     .navbar-menu {
#         max-height: 0;
#         overflow: hidden;
#         transition: max-height 0.3s ease-out;
#         position: absolute;
#         top: 100%;
#         left: 0;
#         right: 0;
#         background-color: #1e1e1e;
#         border-bottom: 1px solid #444;
#     }
#     .navbar-menu.active {
#         max-height: 500px;
#     }
#     .navbar-menu a {
#         display: block;
#         padding: 0.5rem 1rem;
#         text-decoration: none;
#         color: #ffffff;
#     }
#     .navbar-menu button {
#         width: 100%;
#         text-align: left;
#         padding: 0.8rem;
#         background: none;
#         border: none;
#         color: #ffffff;
#         transition: background-color 0.2s;
#     }
#     .navbar-menu button:hover {
#         background-color: #2d2d2d;
#     }
#     .navbar-divider {
#         height: 1px;
#         background-color: #444;
#         margin: 0.5rem 0;
#     }
#     .main-content {
#         margin-top: 70px; /* Adjust based on navbar height */
#     }
# """

# # #* ---------------------- | Header Template | ---------------------- #
# HEADER_TEMPLATE = """
#     <div class="header">
#         <div style="text-align: center; font-family: 'Helvetica', sans-serif; color: #999;">
#             <p style="font-size: 1.1em; margin: 0.5em 0;">
#                 <span style="font-family: 'Consolas', monospace;">© 2025</span> 
#                 All rights reserved by 
#                 <span style="font-family: 'Consolas', monospace; color: #0066ff;">Ryanshatch</span>
#             </p>
#         </div>
#     </div>
# """

# # #* ---------------------- | Web-App Template | ---------------------- #
# APP_TEMPLATE = f"""
# <!DOCTYPE html>
# <html lang="en">
# <head>
#     <meta charset="UTF-8">
#     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#     <title>Zencrypt Web-App</title>
#     <link rel="icon" type="image/x-icon" href="/favicon.ico">
#     <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600&display=swap">
#     <style>
#         {STYLE_TEMPLATE}
#     </style>
#     <script crossorigin src="https://unpkg.com/react@17/umd/react.development.js"></script>
#     <script crossorigin src="https://unpkg.com/react-dom@17/umd/react-dom.development.js"></script>
# </head>
# <body>
#     <div class="main-content">
#         {HEADER_TEMPLATE}
        
#         {{% if session.get('user_id') %}}
#             <nav class="navbar">
#                 <div class="navbar-container">
#                     <div class="navbar-brand" onclick="toggleMenu()">
#                         ☰ Zencrypt Web-App
#                         <span style="font-size: 0.6rem;"></span>
#                     </div>
#                     <div class="navbar-menu" id="navMenu">
#                         <div class="navbar-divider"></div>
#                         <a href="/logout"><button>Logout</button></a>
#                         <div class="navbar-divider"></div>
#                         <a href="/"><button>Hash</button></a>
#                         <a href="/encrypt"><button>Encrypt</button></a>
#                         <a href="/decrypt"><button>Decrypt</button></a>
#                         <div class="navbar-divider"></div>
#                         <a href="/file"><button>Files</button></a>
#                         <a href="/pgp"><button>PGP</button></a>
#                         <div class="navbar-divider"></div>
#                         <a href="/export-key"><button>Export Key</button></a>
#                         <a href="/import-key"><button>Import Key</button></a>
#                     </div>
#                 </div>
#             </nav>
#             <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
#             {{{{ content | safe }}}}
#             {{% if output %}}
#                 <div class="output">{{{{ output }}}}</div>
#             {{% endif %}}
#         {{% else %}}
#             <div class="auth-container">
#                 <h2>{{% if request.path == '/register' %}}Register{{% else %}}Login{{% endif %}}</h2>
#                 {{% if error %}}
#                     <div class="error-message">{{{{ error }}}}</div>
#                 {{% endif %}}
#                 <form method="POST" action="{{% if request.path == '/register' %}}/register{{% else %}}/login
#                 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#                 {{% endif %}}">
#                     <input type="email" name="email" placeholder="Email" required>
#                     <input type="password" name="password" placeholder="Password" required>
#                     <button type="submit">{{% if request.path == '/register' %}}Register{{% else %}}Login{{% endif %}}</button>
#                 </form>
#                 {{% if request.path == '/register' %}}
#                     <p>Already have an account? <a href="/login">Login</a></p>
#                 {{% else %}}
#                     <p>Don't have an account? <a href="/register">Register</a></p>
#                 {{% endif %}}
#             </div>
#             <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
#             <h1 style="text-align: center;">Zencrypt Web-App</h1>
#             <div class="links">
#                 <h6 style="text-align: center;">
#                 <li><b>White Papers</b> - <a href="https://zencrypt.gitbook.io/zencrypt" target="_blank">https://zencrypt.gitbook.io/zencrypt</a></li>
#                 <li><b>ePortfolio</b> - <a href="https://www.ryanshatch.com" target="_blank">https://www.ryanshatch.com</a></li>
#                 </h6>
#             </div>
#             <hr style="border: 0; height: 1px; background-image: linear-gradient(to right, rgba(0, 102, 255, 0), rgba(0, 102, 255, 0.75), rgba(0, 102, 255, 0));">
#         {{% endif %}}
#     </div>
#     <script>
#         function toggleMenu() {{
#             const menu = document.getElementById('navMenu');
#             menu.classList.toggle('active');
#         }}
#         document.addEventListener('click', function(event) {{
#             const menu = document.getElementById('navMenu');
#             const brand = document.querySelector('.navbar-brand');
#             if (!menu.contains(event.target) && !brand.contains(event.target)) {{
#                 menu.classList.remove('active');
#             }}
#         }});
#         window.addEventListener('scroll', function() {{
#             const menu = document.getElementById('navMenu');
#             menu.classList.remove('active');
#         }});
#     </script>
# </body>
# </html>
# """

# # * ---------------------- | Web-App Routes | ---------------------- #
# # * Checks if the database is connected and returns an error message if not connected when the webapp is started.
# def safe_db_operation(operation): 
#     if db is None:                                      # Check if the database is connected
#         return None, "Database not connected"           # Return an error message if the database is not connected
#     try:
#         result = operation()                            # Perform the database operation and store the result
#         return result, None                             # Return the result and no error message if the operation is successful
#     except Exception as e:                              # Catch any exceptions that occur during the database operation
#         print(f"Database operation error: {e}")         # Print an error message if the database operation fails
#         return None, str(e)                             # Return no result and an error message if the operation fails

# #* ---------------------- | Favicon Route | ---------------------- #
# @app.route('/favicon.ico')
# def favicon():
#     return send_from_directory(                      # Return the favicon.ico file from the static directory
#         os.path.join(app.root_path, 'static'),       # Join the root path of the app with the static directory
#         'favicon.ico',                               # Return the favicon.ico file
#         mimetype='image/vnd.microsoft.icon'          # Set the mimetype of the file to image/vnd.microsoft.icon
#     )

# #* ---------------------- | Authentication Routes | ---------------------- #
# #* Route to the login page of the web-app with the login function for user authentication
# @app.route('/login', methods=['GET', 'POST'])      # Route to the login page of the web-app with the login function
# def login():
#     if request.method == 'POST':                # Check if the request method is POST
#         email = request.form.get('email')    # Get the email from the form input for the user
#         password = request.form.get('password') # Get the password from the form input for the user
        
#         # NOTE: Each email acts as a UID for the user, so the keys have a one-to-one relationship with the user
#         user = User.query.filter_by(email=email).first() # Query the database for the user with the email and store it as user
        
#         if user and check_password_hash(user.password_hash, password): # Check if the user exists and the password is correct
#             session['user_id'] = user.id    # Store the user id in the session as user_id
#             access_token = create_access_token(identity=user.id) # Create an access token for the user with the user id
#             session['access_token'] = access_token # Store the access token in the session as access_token
#             return redirect(url_for('hash_page'))   # Redirect to the hash page if the login is successful
        
#         return render_template_string(APP_TEMPLATE, error="Invalid credentials")    # Catch invalid credentials and return an error message
#     # NOTE: For security reasons, the error message does not specify if the email or password is incorrect
#     return render_template_string(APP_TEMPLATE) # Return the APP_TEMPLATE if the request method is not POST

# #* ---------------------- | Registration Route | ---------------------- #

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST': # Check if the request method is POST
#         email = request.form.get('email')   # Get the email from the form input for the user
#         password = request.form.get('password') # Get the password from the form input for the user
        
#         if not email or not password:   # Make sure that the email and password are not empty strings
#             return render_template_string(APP_TEMPLATE,  
#             # Catch empty email and password fields and return an error message
#                 error="Email and password are required")
            
#         if User.query.filter_by(email=email).first(): # Check if the email already exists in the database
#             return render_template_string(APP_TEMPLATE,  # Catch if the email already exists and return an error message
#                 error="Email already exists")
        
#         try:
#             user = User(    # Create a new user with the email and password
#                 email=email,    # Store the email in the user object
#                 password_hash=generate_password_hash(password)  # Store the hashed password in the database as the password_hash for the user
#             )
#             db.session.add(user)   # Add the new user to the database 
#             db.session.commit()   # Commit the new user to the database

#             initialize_key(user.id) # Initialize the key for the user with the user id
#             return redirect(url_for('login')) # Redirect to the login page after registration is successful
#         except Exception as e: # Catch any exceptions that occur during the registration process
#             db.session.rollback() # Rollback the database session if an exception occurs
#             return render_template_string(APP_TEMPLATE, 
#                 error=f"Registration failed: {str(e)}")
    
#     return render_template_string(APP_TEMPLATE)

# #* ---------------------- | Logout Route | ---------------------- #
# #* Route to the logout page of the web-app with the logout function
# @app.route('/logout')
# def logout():
#     user_id = session.get('user_id') # Get the user id from the session 
#     if user_id: # Check if the user id exists
#     #* ---------------------- | Deleting Logged Data | ---------------------- #
#         #// try:
#         #//     # Clean up user data
#         #//     Hash.query.filter_by(user_id=user_id).delete()
#         #//     EncryptedText.query.filter_by(user_id=user_id).delete()
#         #//     # Deactivate user's keys
#         #//     Key.query.filter_by(user_id=user_id, active=True).update({"active": False})
#         #//     db.session.commit()
#         #// except Exception as e:
#         #//     db.session.rollback()
#         #//     print(f"Error cleaning up user data: {e}")
#         #* If the user id exists in the session, continue to the log out process
#         pass
    
#     session.clear() # Clear the session after the user logs out
#     return redirect(url_for('login')) # After the user logs out, the user is redirected to the login page

# #* ---------------------- | SHA256 Hash Route | ---------------------- #
# #* Route to the hash page of the web-app with the hashing function
# @app.route('/', methods=['GET', 'POST'])
# def hash_page():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     content = """
#     <div class="form-container">
#         <form method="POST">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <textarea name="text" placeholder="Enter text to hash"></textarea>
#             <input type="text" name="salt" placeholder="Salt (optional)">
#             <div class="button-wrapper">
#                 <button type="submit">Generate Hash</button>
#             </div>
#         </form>
#     </div>
#     """
    
#     if request.method == 'POST':    # Check if the request method is POST
#         text = request.form.get('text', '') # Get the text from the form input for the user
#         salt = request.form.get('salt', '') # Get the salt from the form input for the user
#         if text:
#             hash_value = hashlib.sha256((text + salt).encode()).hexdigest() # Generate the SHA256 hash value with the text and salt
            
#             new_hash = Hash(   # Create a new hash entry in the database
#                 hash_value=hash_value, # Store the hash value in the database
#                 salt=salt,             # Store the salt in the database
#                 user_id=session['user_id'] # Store the user id with the hash
#             )
#             db.session.add(new_hash) # Add the new hash to the database as new_hash
#             db.session.commit()     # Commit the new hash to the database as new_hash
            
#             return render_template_string(APP_TEMPLATE, 
#             # Return the APP_TEMPLATE with the html content and the sha256 hash value
#                 content=content,
#                 output=f"SHA256 Hash:\n{hash_value}")
    
#     return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content

# #* ---------------------- | Encrypt Text Route | ---------------------- #
# #* Route to the encrypt text page of the web-app with the encryption function
# @app.route('/encrypt', methods=['GET', 'POST'])
# def encrypt_page():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     content = """
#     <div class="form-container">
#         <form method="POST">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <textarea name="text" placeholder="Enter text to encrypt"></textarea>
#             <div class="button-wrapper">
#                 <button type="submit">Encrypt</button>
#             </div>
#         </form>
#     </div>
#     """
    
#     if request.method == 'POST': # Check if the request method is POST
#         text = request.form.get('text', '') # Get the text from the form input for the user
#         if text: # Check if the text is not an empty string
#             try:
#                 cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
#                 encrypted = cipher_suite.encrypt(text.encode()) # Encrypt the text with the cipher suite and store it as encrypted
                
#                 #* Store in database
#                 new_encrypted = EncryptedText( # Create a new encrypted text entry in the database
#                     encrypted_content=encrypted.decode(), # Decode the encrypted content and store it in the database
#                     user_id=session['user_id'] # Store the user id with the encrypted content
#                 )
#                 db.session.add(new_encrypted) # Add the new encrypted text to the database as new_encrypted
#                 db.session.commit() # Commit the new encrypted text to the database
                
#                 return render_template_string(APP_TEMPLATE,
#                 # Return the APP_TEMPLATE with the html content and the encrypted text
#                     content=content,
#                     output=f"Encrypted Text:\n{encrypted.decode()}")
#             # Catch any exceptions that occur during the encryption process
#             except Exception as e:
#                 db.session.rollback() # Rollback the database session if an exception occurs
#                 return render_template_string(APP_TEMPLATE,
#                     content=content,
#                     output=f"Error: {str(e)}") # Return an error message if the encryption fails
    
#     return render_template_string(APP_TEMPLATE, content=content)

# #* ---------------------- | Decrypt Text Route | ---------------------- #
# #* Route to the decrypt text page of the web-app with the decryption function
# @app.route('/decrypt', methods=['GET', 'POST'])
# def decrypt_page():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     content = """
#     <div class="form-container">
#         <form method="POST">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <textarea name="text" placeholder="Enter text to decrypt"></textarea>
#             <div class="button-wrapper">
#                 <button type="submit">Decrypt</button>
#             </div>
#         </form>
#     </div>
#     """
    
#     if request.method == 'POST': # Check if the request method is POST
#         text = request.form.get('text', '') # Get the text from the form input for the user
#         if text: # Check if the text is not an empty string
#             try:
#                 cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
#                 decrypted = cipher_suite.decrypt(text.encode()) # Decrypt the text with the cipher suite and store it as decrypted
#                 return render_template_string(APP_TEMPLATE,
#                 # Return the APP_TEMPLATE with the html content and the decrypted text
#                     content=content,
#                     output=f"Decrypted Text:\n{decrypted.decode()}")
#             # Catch any exceptions that occur during the decryption process
#             except Exception as e:
#                 return render_template_string(APP_TEMPLATE,
#                     content=content,
#                     output=f"Error: {str(e)}") # Return an error message if the decryption fails
    
#     return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is not POST

# #* ---------------------- | File Operations Route | ---------------------- #
# #* Route to the file operations page of the web-app with the file encryption/decryption function
# @app.route('/file', methods=['GET', 'POST'])
# def file_page():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     content = """
#     <div class="form-container">
#         <form method="POST" enctype="multipart/form-data" style="text-align: center;">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <div class="file-upload-wrapper" style="margin: 20px 0;">
#                 <label for="file-upload" class="custom-file-upload" style="
#                     display: inline-block;
#                     padding: 10px 20px;
#                     background: #2d2d2d;
#                     color: #fff;
#                     border: 1px solid #444;
#                     border-radius: 5px;
#                     cursor: pointer;
#                     margin-bottom: 10px;">
#                     Choose File
#                 </label>
#                 <input id="file-upload" type="file" name="file" required style="display: none;">
#                 <div id="file-name" style="margin-top: 5px; color: #999;"></div>
#             </div>
#             <input type="password" name="password" placeholder="Enter Password" required style="width: 75%;">
#             <select name="operation" style="
#                 width: 75%;
#                 padding: 15px;
#                 margin: 20px 0;
#                 background-color: #2d2d2d;
#                 color: #ffffff;
#                 border: 1px solid #444;
#                 border-radius: 5px;">
#                 <option value="encrypt">Encrypt File</option>
#                 <option value="decrypt">Decrypt File</option>
#             </select>
#             <div class="button-wrapper">
#                 <button type="submit">Process File</button>
#             </div>
#         </form>
#     </div>
#     <script>
#         document.getElementById('file-upload').onchange = function() {
#             document.getElementById('file-name').textContent = this.files[0] ? this.files[0].name : '';
#         };
#     </script>
#     """
    
#     if request.method == 'POST': # Check if the request method is POST
#         if 'file' not in request.files: # Check if the file is not in the request files
#             return render_template_string(APP_TEMPLATE,
#             # Catch if the file is not selected and return an error message
#                 content=content,
#                 output="Please select a file to process")
            
#         file = request.files['file'] # Get the file from the request files for the user
#         if file.filename == '': # Check if the file name is an empty string
#             return render_template_string(APP_TEMPLATE,
#             # Catch if the file name is empty and return an error message
#                 content=content,
#                 output="No file selected") # Return an error message that no file was selected
            
#         try:
#             file_content = file.read() # Read the file content and store it as file_content
#             password = request.form.get('password', '').encode() # Get the password from the form input for the user and encode it
#             operation = request.form.get('operation') # Get the operation from the form input for the user
            
#             if not password: # Check if the password is an empty string 
#                 return render_template_string(APP_TEMPLATE,
#                 # Catch if the password is empty and return an error message that the password is required
#                     content=content,
#                     output="Password is required")
            
#             cipher_suite = get_cipher_suite(session['user_id']) # Get the cipher suite for the user based on the user id
#             if operation == 'encrypt': # Check if the operation is to encrypt the file
#                 encrypted = cipher_suite.encrypt(file_content) # Encrypt the file content with the cipher suite and store it as encrypted
#                 return render_template_string(APP_TEMPLATE,
#                 # Return the APP_TEMPLATE with the html content and the encrypted file content
#                     content=content,
#                     output=f"File encrypted successfully!\nEncrypted content:\n{base64.b64encode(encrypted).decode()}")
#             else: # If the operation is not set to encrypt, and is set to decrypt
#                 try: # Try to decrypt the file content with the cipher suite
#                     decrypted = cipher_suite.decrypt(base64.b64decode(file_content)) # Decrypt the file content with the cipher suite and store it as decrypted
#                     return render_template_string(APP_TEMPLATE, 
#                     # Return the APP_TEMPLATE with the html content and the decrypted file content
#                         content=content,
#                         output=f"File decrypted successfully!\nDecrypted content:\n{decrypted.decode()}")
#                 except Exception:
#                     # Catch any exceptions if the file is invalid or the password is incorrect
#                     return render_template_string(APP_TEMPLATE,
#                         content=content,
#                         output="Invalid encrypted file or wrong password")
                
#         except Exception as e: # Catch any exceptions that occur during the file processing
#             return render_template_string(APP_TEMPLATE,
#                 content=content,
#                 # Return an error message if the file processing fails
#                 output=f"Error processing file: {str(e)}")
    
#     return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is not POST

# #* ---------------------- | Export/Import Key Routes | ---------------------- #
# @app.route('/export-key')
# def export_key():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     try:
#         key = Key.query.filter_by(user_id=session['user_id'], active=True).first() # Get the key for the user based on the user id
#         if key:
#             key_name = request.args.get('key_name', 'zen_key')  # Default to 'zen_key' if no name provided
#             response = app.response_class( # Create a response class with the key value as the key content
#                 key.key_value,  # Set the key value as the key content
#                 mimetype='application/octet-stream',    # Set the mimetype of the key to "application/octet-stream" to download the key
#                 headers={'Content-Disposition': f'attachment;filename={key_name}.key'} # Name the key file with the key_name provided when downloading
#             )
#             return response # If the key is found, download the key file with the key value as the content
#         return "No active key found", 404 # Return an error 404 message if no active key is found
#         # Catch any other exceptions that could occur during the process of exporting the key
#     except Exception as e:
#         return f"Error exporting key: {str(e)}", 500 # Return an error 500 message if the key export fails

# @app.route('/import-key', methods=['GET', 'POST'])
# def import_key():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     if request.method == 'GET': # Check if the request method is GET to show the file upload form
#         #* Displays the file upload form for importing a key
#         content = """
#         <div class="form-container">
#             <form method="POST" action="/import-key" enctype="multipart/form-data">
#                 <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#                 <input type="file" name="key_file" style="display: none;" id="key_file" onchange="this.form.submit()">
#                 <button type="button" onclick="document.getElementById('key_file').click()">Import Key</button>
#             </form>
#         </div>
#         """

#         return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content if the request method is GET
    
#     #* Process the key file upload and import the key if the request method is POST
#     if 'key_file' not in request.files: # Check if the key file is not in the request files
#         return redirect(url_for('hash_page')) # If the key file is not in the request files, redirect to the hash page
        
#     file = request.files['key_file'] # Get the key file from the request files for the user
#     if file.filename == '': # Check if the key file name is an empty string
#         return redirect(url_for('hash_page')) # If the key file name is an empty string, redirect to the hash page
        
#     try: # Try to import the key file and store the key value in the database
#         key_content = file.read().decode().strip() # Read the key file content and store it as key_content after decoding and stripping the whitespaces
#         #* Deactivate any existing keys
#         Key.query.filter_by(user_id=session['user_id'], active=True).update({"active": False}) # Deactivate any existing keys for the user and update the active status to False in the database
        
#         #* Store the new key in the database
#         new_key = Key(
#             key_value=key_content, # Store the key content in the database
#             user_id=session['user_id'], # Store the user id with the key content
#             active=True # Set the key status to active in the database
#         )
#         db.session.add(new_key) # Add the new key to the database as new_key
#         db.session.commit() # Commit the new key to the database
#         return redirect(url_for('hash_page')) # Redirect to the hash page after the key is imported successfully
    
#     except Exception as e:
#         db.session.rollback() # Rollback the database session if an exception occurs during the key import process
#         # Catch any exceptions that occur during the key import process and return an error message 500
#         return f"Error importing key: {str(e)}", 500
    
# #* ---------------------- | PGP Routes | ---------------------- #
# @app.route('/pgp', methods=['GET'])
# def pgp_page():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     content = """
#     <div class="form-container">
#         <form method="POST" action="/pgp/generate">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <div class="button-wrapper">
#                 <button type="submit">Generate Keys</button>
#             </div>
#         </form>
#         <form method="POST" action="/pgp/encrypt">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <textarea name="message" placeholder="Message:"></textarea>
#             <input type="text" name="recipient_email" placeholder="Email of recipient" required>
#             <div class="button-wrapper">
#                 <button type="submit">Encrypt</button>
#             </div>
#         </form>
#         <form method="POST" action="/pgp/decrypt">
#             <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
#             <textarea name="encrypted_message" placeholder="Message:"></textarea>
#             <div class="button-wrapper">
#                 <button type="submit">Decrypt</button>
#             </div>
#         </form>
#     </div>
#     """
    
#     return render_template_string(APP_TEMPLATE, content=content) # Return the APP_TEMPLATE with the html content for the PGP page

# #* ---------------------- | PGP Key Generation  | ---------------------- #
# @app.route('/pgp/generate', methods=['POST'])
# def generate_pgp():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     try:
#         private_key, public_key = generate_pgp_keypair() # Generate a new PGP key pair and store the private and public keys
        
#         # Deactivate existing keys for the user
#         PGPKey.query.filter_by(user_id=session['user_id'], active=True).update({"active": False})
        
#         # Store new keys
#         new_keys = PGPKey(
#             public_key=public_key, # Store the public key in the database
#             private_key=private_key, # Store the private key in the database
#             user_id=session['user_id'] # Store the user id and their keys in the database with a one-to-one relationship with the user
#         )
        
#         db.session.add(new_keys) # Add the new keys to the database
#         db.session.commit() # Commit the new keys to the database after generating the PGP key pair
        
#         return redirect(url_for('pgp_page')) # Redirect to the PGP page after generating the PGP key pair
#     except Exception as e:  
#         # Catch any exceptions that occur during the PGP key generation process and return an error message 500
#         return f"Error generating keys: {str(e)}", 500

# #* ---------------------- | PGP Encryption | ---------------------- #
# @app.route('/pgp/encrypt', methods=['POST'])
# def pgp_encrypt():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     message = request.form.get('message') # Get the message from the form input for the user
#     recipient_email = request.form.get('recipient_email') # Get the recipient email from the form input for the user
    
#     try:
#         recipient = User.query.filter_by(email=recipient_email).first() # Query the database for the recipient based on the recipient email
#         if not recipient:   # Check if the recipient exists
#             return "Recipient not found", 404 # Return an error 404 message if the recipient is not found
            
#         recipient_key = PGPKey.query.filter_by(user_id=recipient.id, active=True).first()   # Query the database for the recipient's PGP key
#         if not recipient_key:   # Check if the recipient has an active PGP key
#             return "Recipient has no active PGP key", 400   # Return an error 400 message if the recipient has no active PGP key
            
#         encrypted = pgp_encrypt_message(message, recipient_key.public_key)  # Encrypt the message with the recipient's public key
#         return render_template_string(APP_TEMPLATE,
#         # Return the APP_TEMPLATE with the html content and the encrypted message
#             content="Encrypted message:<br><textarea readonly>%s</textarea>" % encrypted) # Display the encrypted message in a read only field
#     except Exception as e:
#         # Catch any exceptions that occur during the PGP encryption process and return an error message 500
#         return f"Error encrypting message: {str(e)}", 500

# #* ---------------------- | PGP Decryption | ---------------------- #
# @app.route('/pgp/decrypt', methods=['POST'])
# def pgp_decrypt():
#     if not session.get('user_id'): # Check if the user id exists in the session
#         return redirect(url_for('login')) # If the user id does not exist, redirect to the login page
    
#     encrypted_message = request.form.get('encrypted_message') # Get the encrypted message from the form input for the user
    
#     try:
#         user_key = PGPKey.query.filter_by(user_id=session['user_id'], active=True).first() # Query the database for the user's active PGP key
#         if not user_key: # Check if the user has an active PGP key
#             return "No active PGP key found", 400 # Return an error 400 message if the user doesnt already have an active PGP key
            
#         decrypted = pgp_decrypt_message(encrypted_message, user_key.private_key) # Decrypt the message with the user's private key
#         return render_template_string(APP_TEMPLATE,
#             content="Decrypted message:<br><textarea readonly>%s</textarea>" % decrypted)   # Display the decrypted message in a read only field
#     except Exception as e:
#         # Catch any exceptions that occur during the PGP decryption process and return an error message 500
#         return f"Error decrypting message: {str(e)}", 500
    
# # #* ---------------------- | Triforce ASCII Art Banner | ---------------------- #
# BOLD = '\033[1m'
# END = '\033[0m'

# ASCII_BANNER = f"""

#                            /\\
#                           /__\\
#                          /\\  /\\
#                         /__\\/__\\
#                        /\\      /\\
#                       /__\\    /__\\
#                      /\\  /\\  /\\  /\\
#                     /__\\/__\\/__\\/__\\
                    
# """
# #* ---------------------- | Console Startup | ---------------------- #
# from colorama import init, Style
# init()
# #* Function to print the Zencrypt banner in the console along with Zencrypt whitepapers and ePortfolio links to my website.
# def print_startup_banner():
#     print(ASCII_BANNER) # Print the Triforce
#     print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>{Style.RESET_ALL}\n")
#     print(f"{Style.BRIGHT}Zencrypt Web-App{Style.RESET_ALL} - Developed And Owned Entirely By Ryanshatch\n")
#     print(f"{Style.BRIGHT}- Whitepapers and Docs{Style.RESET_ALL} - {Style.BRIGHT}https://zencrypt.gitbook.io/zencrypt{Style.RESET_ALL}")
#     print(f"{Style.BRIGHT}- ePortfolio{Style.RESET_ALL} - {Style.BRIGHT}https://www.ryanshatch.com{Style.RESET_ALL}")
#     print(f"{Style.BRIGHT}\nZencrypt version 6.2.2-alpha: Initializing... {Style.RESET_ALL}\n")
#     print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>{Style.RESET_ALL}\n")


# #* ---------------------- | Main Function to Run the Flask Application | ---------------------- #
# # Main function to run the Flask application
# if __name__ == '__main__':
#     print_startup_banner() #* Print the Zencrypt banner in the console
    
#     #* Initialize database first
#     init_db()
    
#     if os.getenv('FLASK_ENV') == 'production': # Check if the Flask environment is set to "production mode"
#         with app.app_context(): # Set up the app context to run the app and initialize the encryption key for the default user
#             try:
#                 #* Initialize the encryption key for the default user
#                 default_user = User.query.first() # Check if the default user exists in the database
#                 if default_user: 
#                     #* If the default user exists, initialize the encryption key for the default user
#                     initialize_key(default_user.id)
#                     print("\nThe encryption key has been initialized for the default user\n")
#                     print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")

#                 else:
#                     #* Catch an exception if the default user is not found in the database
#                     print("Warning: \nNo default user was found in the database\n\n")
#                     print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")
#             except Exception as e:
#                 #* Catch an exception if the encryption key initialization fails for the key
#                 print(f"Error initializing key: {e}\n\n")
#                 print(f"{Style.BRIGHT}<><><><><><><><><><><><><><><><><><><><><><><>\n\n{Style.RESET_ALL}")
        
#         #* Run the Flask app in "production mode"
#         app.run(host='0.0.0.0', port=5000)
#     else:
#         #* Run the Flask app in "development mode"
#         print_startup_banner()
#         init_db()
#         app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

# #* ---------------------- | End of Code | ---------------------- #
