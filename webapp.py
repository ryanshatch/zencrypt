"""
********************************************************************************************
* Title: Zencrypt WebApp           |********************************************************
* Developed by: Ryan Hatch         |********************************************************
* Date: August 10th 2022           |********************************************************
* Last Updated: January 31st 2025  |********************************************************
* Version: 5.3.3                   |********************************************************
********************************************************************************************
*****************************#* Zencrypt v5.3-A3 |******************************************
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
from models import db, User, Hash, EncryptedText, Key
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
from models import Key, db
from utils import generate_pgp_keys
from datetime import timedelta
from dotenv import load_dotenv

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
        input, textarea {
            width: 80%;
            margin: 10px 0;
            background-color: #1a1a1a;
            color: white;
            border: 1px solid #333;
            padding: 10px;
        }
        textarea {
            min-height: 100px;
        }
        button {
            background-color: #333;
            color: white;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            margin: 5px;
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
        .auth-container {
            max-width: 400px;
            margin: 20px auto;
            padding: 20px;
            background-color: #1a1a1a;
            border-radius: 5px;
        }
        .error-message {
            color: #ff4444;
            margin: 10px 0;
        }
        .triforce {
            text-align: center;
            font-weight: bold;
            white-space: pre;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Zencrypt WebApp v5.5-A5</h1>
        <p><i>The Zencrypt Web-Application is Developed And Owned Entirely By <code>Ryanshatch</code></i></p>
        <hr>
        
        {% if session.get('user_id') %}
            <h4>With this web-app you can:
            <br><li>Import or Export Keys to generate hash using SHA256 & salt, Encrypt & Decrypt text and files.</li>
            <div class="menu">
                <p><b>Account:</b></p>
                <a href="/export_keys"><button>Export</button></a>
                <a href="/import_keys"><button>Import</button></a>
                <a href="/logout"><button>Logout</button></a>
                <hr>
                <p><b>Cipher:</b></p>
                <a href="/"><button>Hash</button></a>
                <a href="/encrypt"><button>Encrypt</button></a>
                <a href="/decrypt"><button>Decrypt</button></a>
                <a href="/file"><button>Files</button></a>
            </div>
            <hr>
            {{ content | safe }}
            {% if output %}
                <div class="output">{{ output }}</div>
            {% endif %}
            <div class="triforce">
       /\       
      /  \      
     /____\     
    /\    /\    
   /  \  /  \   
  /____\/____\  
            </div>
        {% else %}
            <div class="auth-container">
                <h2>{% if request.path == '/register' %}Register{% else %}Login{% endif %}</h2>
                {% if error %}
                    <div class="error-message">{{ error }}</div>
                {% endif %}
                <form method="POST" action="{% if request.path == '/register' %}/register{% else %}/login{% endif %}">
                    <input type="email" name="email" placeholder="Email" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">{% if request.path == '/register' %}Register{% else %}Login{% endif %}</button>
                </form>
                {% if request.path == '/register' %}
                    <p>Already have an account? <a href="/login">Login</a></p>
                {% else %}
                    <p>Don't have an account? <a href="/register">Register</a></p>
                {% endif %}
            </div>
            <a>
                <li><b>White Papers</b> - <b>https://zencrypt.gitbook.io/zencrypt</b></li>
                <li><b>ePortfolio</b> - <i>https://www.ryanshatch.com</i></li>
            </a>
            <hr>
            <div class="triforce">
       /\       
      /  \      
     /____\     
    /\    /\    
   /  \  /  \   
  /____\/____\  
            </div>
        {% endif %}
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
@app.route('/favicon.ico') # Route to the favicon of the web-app to show my Y00t
def favicon():
    return send_from_directory( 
        os.path.join(app.root_path, 'static'), # Gets the icon from the static directory
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'   # Sets the icon format to ico because icons arent displayed in the browser without this mimetype.
    )

#* ---------------------- | Authentication Routes | ---------------------- #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':                # Check if the request method is POST
        email = request.form.get('email')       # If it is, get the email from the form
        password = request.form.get('password') # Get the password from the form
        
        user = User.query.filter_by(email=email).first() # Query the database for the user email
        
        if user and check_password_hash(user.password_hash, password): # Check if the user exists and the password is correct
            session['user_id'] = user.id # Set the user id in the session
            access_token = create_access_token(identity=user.id) # Create an access token for the user
            session['access_token'] = access_token # Set the access token in the session
            return redirect(url_for('hash_page')) # Redirect the user to the hash page
        
        return render_template_string(APP_TEMPLATE, error="Invalid credentials") # Return an error message if the credentials are invalid
    
    return render_template_string(APP_TEMPLATE) # Return the app template if the request method is not POST

#* ---------------------- | Registration Route | ---------------------- #
@app.route('/register', methods=['GET', 'POST'])    # Route to the registration page of the web-app
def register():
    if request.method == 'POST':                # Check if the request method is POST
        email = request.form.get('email')    # If it is, get the email from the form
        password = request.form.get('password') # Get the password from the form
        
        if not email or not password:        # Check if the email and password are empty
            return render_template_string(APP_TEMPLATE,     # Return an error message if the email and password are empty
                error="Email and password are required")    # Return an error message if the email and password are empty
            
        if User.query.filter_by(email=email).first():   # Check if the user email already exists in the database
            return render_template_string(APP_TEMPLATE,     # Return an error message if the email already exists
                error="Email already exists")             # Return an error message if the email already exists
        
        try:    # Try to create a new user with the email and password
            user = User(
                email=email,
                password_hash=generate_password_hash(password)  # Generate a password hash for the user
            )
            db.session.add(user)    # Add the user to the database
            db.session.commit()    # Commit the changes to the database
            return redirect(url_for('login'))   # Redirect the user to the login page
        except Exception as e:  # Catch any exceptions that occur during the registration process
            db.session.rollback()   # Rollback the database session if an exception occurs
            return render_template_string(APP_TEMPLATE,
                error=f"Registration failed: {str(e)}")    # Return an error message if the registration fails
    
    return render_template_string(APP_TEMPLATE) # Return the app template if the request method is not POST

#* ---------------------- | Logout Route | ---------------------- #
@app.route('/logout')   # Route to the logout page of the web-app
def logout():
    session.pop('user_id', None)        # Remove the user id from the session
    session.pop('access_token', None)   # Remove the access token from the session
    return redirect(url_for('login'))   # Redirect the user to the login page

#* --- | Logout - Old method for logout where the user data was deleted from the database | --- #
# @app.route('/logout')   # Route to the logout page of the web-app
# def logout():
#     user_id = session.get('user_id')    # Get the user id from the session
#     if user_id: # Check if the user id exists in the session
#     #* ---------------------- | Deleting Logged Data | ---------------------- #
#         try:
#             # Clean up user data
#             Hash.query.filter_by(user_id=user_id).delete()
#             EncryptedText.query.filter_by(user_id=user_id).delete()
#             # Deactivate user's keys
#             Key.query.filter_by(user_id=user_id, active=True).update({"active": False})
#             db.session.commit()
#         except Exception as e:
#             db.session.rollback()
#             print(f"Error cleaning up user data: {e}")
#         pass # Placeholder for the cleanup code
#     session.clear() # Clear the session data when the user logs out
#     return redirect(url_for('login'))   # Redirect the user to the login page

#* ---------------------- | Encryption & Decryption Routes | ---------------------- #
@app.route('/', methods=['GET', 'POST']) # Route to the hash page of the web-app with the hash function
def hash_page():
    if not session.get('user_id'): # Check if the user id exists in the session
        return redirect(url_for('login')) # Redirect the user to the login page if the user id does
    
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to hash"></textarea>
        <input type="text" name="salt" placeholder="Salt (optional)">
        <button type="submit">Generate Hash</button>
    </form>
    """
    
    if request.method == 'POST': # Check if the request method is POST
        text = request.form.get('text', '') # Get the text from the form and set it to an empty string if it is empty
        salt = request.form.get('salt', '') # Get the salt from the form and set it to an empty string if it is empty
        if text:
            hash_value = hashlib.sha256((text + salt).encode()).hexdigest() # Generate a SHA256 hash value for the text and salt
            
            #* Create a new hash entry in the database with the hash value, salt, and user id
            new_hash = Hash(
                hash_value=hash_value,
                salt=salt,
                user_id=session['user_id']
            )
            db.session.add(new_hash)
            db.session.commit()
            
            #* Return the webapp template with the content and the hash value
            return render_template_string(APP_TEMPLATE,
                content=content,
                output=f"SHA256 Hash:\n{hash_value}")
    
    return render_template_string(APP_TEMPLATE, content=content) # Return the webapp template with the content

#* ---------------------- | Encryption Route | ---------------------- #
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

#* ---------------------- | Decryption Route | ---------------------- #
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
        <input type="password" name="password" placeholder="Password" required>
        <br>
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

#* ---------------------- | Export Keys Route | ---------------------- #
@app.route('/export_keys', methods=['GET']) 
@jwt_required(optional=True) # Check if the user is logged in via JWT token
def export_keys():           # Check if the user is logged in via session
    if not session.get('user_id'): return redirect(url_for('login'))
    # Retrieve the active key for the user from the database
    key = Key.query.filter_by(user_id=session['user_id'], active=True).first()

    if key:
        output = f"Your active key is:\n{key.key_value}"
        return render_template_string(APP_TEMPLATE, content="", output=output)
    else:
        return render_template_string(APP_TEMPLATE, content="", output="No active key found.")
    
#* ---------------------- | Import Keys Route | ---------------------- #
@app.route('/import_keys', methods=['GET', 'POST'])
def import_keys():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    form_html = """
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="key_file" required>
        <button type="submit">Import Key</button>
    </form>
    """
    
    if request.method == 'POST':
        if 'key_file' not in request.files:
            return render_template_string(APP_TEMPLATE, content=form_html, output="No file uploaded.")
        
        file = request.files['key_file']
        if file.filename == "":
            return render_template_string(APP_TEMPLATE, content=form_html, output="No file selected.")
        
        try:
            key_data = file.read().strip()
            # Start by trying to decrypt the key data using the current active key for the user using Fernet.
            Fernet(key_data)
            
            # Deactivate any existing active key for the user.
            current_key = Key.query.filter_by(user_id=session['user_id'], active=True).first()
            if current_key:
                current_key.active = False
            
            # Save the imported key as the new active key.
            new_key_entry = Key(
                key_value=key_data.decode(),  # storing as string
                user_id=session['user_id']
            )
            db.session.add(new_key_entry)
            db.session.commit()
            message = "Key imported successfully and activated."
        except Exception as e:
            db.session.rollback()
            message = f"Error importing key: {e}"
        
        return render_template_string(APP_TEMPLATE, content=form_html, output=message)
    
    return render_template_string(APP_TEMPLATE, content=form_html)
# * Old method for exporting keys:
# @app.route('/export_keys', methods=['GET'])
# def export_keys():
#     if not session.get('user_id'):
#         return redirect(url_for('login'))
        
#     user_id = session['user_id']
#     key_record = Key.query.filter_by(user_id=user_id, active=True).first()
    
#     # If no key pair found or keys are missing, generate a new set
#     if not key_record or not key_record.public_key or not key_record.private_key:
#         private_key, public_key = generate_pgp_keys()
        
#         # Serialize keys to PEM format
#         private_pem = private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         ).decode()
        
#         public_pem = public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).decode()
        
#         if not key_record:
#             key_record = Key(
#                 key_value='',  # optional legacy field
#                 public_key=public_pem,
#                 private_key=private_pem,
#                 active=True,
#                 user_id=user_id
#             )
#             db.session.add(key_record)
#         else:
#             key_record.public_key = public_pem
#             key_record.private_key = private_pem
        
#         db.session.commit()
#     else:
#         public_pem = key_record.public_key
#         private_pem = key_record.private_key

#     content = f"""
#     <h2>Your RSA Key Pair</h2>
#     <h3>Public Key:</h3>
#     <pre>{public_pem}</pre>
#     <h3>Private Key:</h3>
#     <pre>{private_pem}</pre>
#     """
#     return render_template_string(APP_TEMPLATE, content=content)

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
    print_startup_banner()                           # Displays the Triforce, ePortfolio, and Zencrypt documentation in the console when the webapp is started
    app.run(debug=False, host='0.0.0.0', port=5000)  # Runs the Flask application on a local server with debug mode disabled