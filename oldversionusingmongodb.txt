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

#* Importing the required libraries for the webapp
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
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

# Load environment variables from .env file
load_dotenv()

# Flask Configuration and JWT Manager
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# JWT Configuration with secret key and token expiration time of 1 hour
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# MongoDB Configuration and Connection
mongo_client = None
db = None

# Initialize MongoDB connection to the zencrypt database and collections for users, hashes, and encrypted texts
def init_app():
    global mongo_client, db                                            # Use global variables for MongoDB client and database
    mongo_uri = os.environ.get('MONGO_URI')                            # Get MongoDB URI from environment variables
    if not mongo_uri:                                                  # Check if MongoDB URI is not found
        print("Warning: MONGO_URI not found in environment variables") # Catch warning if MongoDB URI is not found
        return False
        
    try:
        # Connect to MongoDB with a timeout of 5 seconds if the connection fails
        mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        mongo_client.server_info()               # Check if the MongoDB server is running
        db = mongo_client.zencrypt               # Connect to the zencrypt database in MongoDB
        print("MongoDB connected successfully")  # If the connection is successful, print a success message
        return True 
    except Exception as e:                       # Catch any exceptions that occur during the MongoDB connection
        print(f"MongoDB connection failed: {e}") # Print an error message if the connection fails
        return False

# Initialize MongoDB connection when the app starts
if not init_app(): 
    # If the MongoDB connection fails, print a warning message and continue without the database connection
    print("Warning: Starting without database connection")

# Safe database operation wrapper for key operations
KEY_FILE = "/etc/secrets/zen.key"                         # The private key is stored in a file called "zen.key"

def initialize_key(): # Initialize the private key for encryption and decryption
    if os.path.exists(KEY_FILE):                          # Check to see if the key file exists within the directory
        with open(KEY_FILE, "rb") as key_file:            # Open the key file in binary read mode if it exists
            return key_file.read()                        # Read the key from the file and parse the read contents.
    
    key = Fernet.generate_key() # Generate a new key if the key file does not exist
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True) # Create the directory for the key file if it does not exist
    with open(KEY_FILE, "wb") as key_file:                # Open the key file in binary write mode
        key_file.write(key)                               # Write the key to the file
    
    return key

cipher_suite = Fernet(initialize_key())                   # Initialize the cipher suite with the key for encryption and decryption


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
    </style>
</head>
<body>
    <div class="container">
        <h1>Zencrypt v5.3-A2</h1>
        <h5><i>The Zencrypt Web-Application is Developed And Owned Entirely By <code>Ryanshatch</code></i></h5>
        <hr>
        
        {% if session.get('user_id') %}
            <h4>With this web-app you can:
            <br><li>Hash text using SHA256, Encrypt text, Decrypt text.</li>
            <li>Handle Encrypting and Decrypting Uploaded Files securely and online.</li></h4>
            <div class="menu">
                <a href="/"><button>Hash</button></a>
                <a href="/encrypt"><button>Encrypt</button></a>
                <a href="/decrypt"><button>Decrypt</button></a>
                <a href="/file"><button>File Operations</button></a>
                <a href="/logout"><button>Logout</button></a>
            </div>
            <hr>
            {{ content | safe }}
            {% if output %}
                <div class="output">{{ output }}</div>
            {% endif %}
        {% else %}
            <div class="auth-container">
                <h2>{% if request.path == '/register' %}Register{% else %}Login{% endif %}</h2>
                {% if error %}
                    <div class="error-message">{{ error }}</div>
                {% endif %}
                <form method="POST" action="{% if request.path == '/register' %}/register{% else %}/login{% endif %}">
                    <input type="email" name="email" placeholder="Email" class="w-full max-w-xs p-2 border rounded" required>
                    <input type="password" name="password" placeholder="Password" class="w-full max-w-xs p-2 border rounded" required>
                    <button type="submit">{% if request.path == '/register' %}Register{% else %}Login{% endif %}</button>
                </form>
                {% if request.path == '/register' %}
                    <p>Already have an account? <a href="/login">Login</a></p>
                {% else %}
                    <p>Don't have an account? <a href="/register">Register</a></p>
                {% endif %}
            </div>
        <h4><li><b>White Papers</b> - <b>https://zencrypt.gitbook.io/zencrypt</b></li>
        <li><b>ePortfolio</b> - <i>https://www.ryanshatch.com</i></li></h4>
        <hr>

        {% endif %}
    </div>
</body>
</html>
"""

#* ---------------------- | Web-App Routes | ---------------------- #
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
@app.route('/login', methods=['GET', 'POST'])           # Route for user login
def login():
    if request.method == 'POST':                        # If the request method is POST, for example, when the form is submitted
        email = request.form.get('email')               # Get the email input from the form
        password = request.form.get('password')         # Get the password input from the form
        
        def find_user():                                # Define a function to find the user in the database
            return db.users.find_one({'email': email})  # Find the user in the database by email
        
        user, error = safe_db_operation(find_user)      # Perform the database operation to find the user
        
        if error:
            return render_template_string(APP_TEMPLATE, error=f"Database error: {error}") # Catch any database errors and display an error message
        
        if user and check_password_hash(user['password'], password):      # Check to see whether the user exists and if the password is correct
            session['user_id'] = str(user['_id'])                         # Set the user ID in the session
            access_token = create_access_token(identity=str(user['_id'])) # Create an access token for the user
            session['access_token'] = access_token                        # Set the access token in the session
            return redirect(url_for('hash_page'))                         # Redirect the user to the hash page after successful login
        
        return render_template_string(APP_TEMPLATE, error="Invalid credentials") # Display an error message for invalid credentials
    
    return render_template_string(APP_TEMPLATE)                           # Render the login template

@app.route('/register', methods=['GET', 'POST'])                          # Route for user registration
def register():
    if request.method == 'POST':                    # If the request method is POST, for example, when the form is submitted
        email = request.form.get('email')           # Get the email input from the form
        password = request.form.get('password')     # Get the password input from the form
        
        if not email or not password:               # Check if email and password are provided
            return render_template_string(APP_TEMPLATE, error="Email and password are required")
            
        user = db.users.find_one({'email': email})  # Check if the user already exists in the database
        if user:
                                                    # Return an error message if the user already exists
            return render_template_string(APP_TEMPLATE, error="Email already exists")
        
        try:
            hashed_password = generate_password_hash(password)  # Generate a hashed password for the user
            # Insert the user into the database
            db.users.insert_one({
                'email': email,
                'password': hashed_password
            })
            return redirect(url_for('login')) # Redirect the user to the login page after successful registration
        except Exception as e:
            return render_template_string(APP_TEMPLATE, error=f"Registration failed: {str(e)}") # Return an error message if registration fails
    
    return render_template_string(APP_TEMPLATE)

@app.route('/logout') # Route for user logout and clear the session
def logout():
    session.clear() # Clear the session
    return redirect(url_for('login')) # Redirect the user to the login page after logout

#* ---------------------- | Routes for Encryption and Decryption | ---------------------- #
@app.route('/', methods=['GET', 'POST']) # Route to the home page of the web-app with the hash function
def hash_page():
    if not session.get('user_id'): # Check if the user is logged in
        return redirect(url_for('login')) # Redirect the user to the login page if not logged in
    
    output = None # Initialize the output variable to None
    # HTML form for the hash page
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to hash"></textarea>
        <input type="text" name="salt" placeholder="Salt (optional)">
        <button type="submit">Generate Hash</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '') # Get the text input from the form
        salt = request.form.get('salt', '') # Get the salt input from the form
        if text:
            hash_input = (text + salt).encode() # Concatenate the text and salt and encode as bytes
            hash_output = hashlib.sha256(hash_input).hexdigest() # Generate the SHA256 hash from the input
            output = f"SHA256 Hash:\n{hash_output}" # Set the output to the hash output with a message
            
            def store_hash():
                return db.hashes.insert_one({ # Store the hash in the database with the user ID and salt
                    'userId': session['user_id'],
                    'hash': hash_output,
                    'salt': salt
                })
            
            _, error = safe_db_operation(store_hash) # Perform the database operation to store the hash
            if error:
                output += f"\n\nWarning: Hash not saved to database: {error}" # Display a warning message if the hash is not saved to the database
    
    return render_template_string(APP_TEMPLATE, content=content, output=output) # Render the template with the content and output variables

@app.route('/encrypt', methods=['GET', 'POST']) # Route to the encrypt text page of the web-app with the encryption function
def encrypt_page():
    if not session.get('user_id'):              # Check if the user is logged in
        return redirect(url_for('login'))       # Redirect the user to the login page if not logged in
    
    output = None                               # Initialize the output variable to None
    # HTML form for the encryption page
    content = """
    <form method="POST">
        <textarea name="text" placeholder="Enter text to encrypt"></textarea>
        <button type="submit">Encrypt</button>
    </form>
    """
    
    if request.method == 'POST':
        text = request.form.get('text', '')                         # Get the text input from the form
        if text:
            try:
                encrypted = cipher_suite.encrypt(text.encode())     # Encrypt the text input using the cipher suite
                output = f"Encrypted Text:\n{encrypted.decode()}"   # Set the output to the encrypted text with a message
                
                # Store the encrypted text in the database with the user ID and salt
                db.encrypted_texts.insert_one({
                    'userId': session['user_id'],
                    'encryptedText': encrypted.decode()
                })
            except Exception as e:                                              # Catch any exceptions that occur during encryption
                output = f"Error: {str(e)}"
    
    return render_template_string(APP_TEMPLATE, content=content, output=output) # Render the template with the content and the output variables

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
        text = request.form.get('text', '')                         # Get the text input from the form
        if text:
            try:
                decrypted = cipher_suite.decrypt(text.encode())     # Decrypt the text input using the cipher suite
                output = f"Decrypted Text:\n{decrypted.decode()}"   # Set the output to the decrypted text with a message
            except Exception as e:
                output = f"Error: {str(e)}"                                     # Catch any exceptions that occur during decryption and display an error message
    
    return render_template_string(APP_TEMPLATE, content=content, output=output) # Render the template with the content and output variables

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
        if 'file' not in request.files:                                                 # Check if a file is uploaded
            output = "No file uploaded"                                                 # Catch an error if no file is uploaded
            return render_template_string(APP_TEMPLATE, content=content, output=output) # Render the template with the content and output variables
            
        file = request.files['file']                         # Get the uploaded file from the form
        password = request.form.get('password', '').encode() # Get the password input from the form and encode as bytes
        operation = request.form.get('operation')            # Get the operation input from the form
        
        if file.filename == '':                                                         # Check if the file name is empty
            output = "No file selected"                                                 # Catch an error if no file is selected
            return render_template_string(APP_TEMPLATE, content=content, output=output) # Render the template with the content and output variables
            
        try:
            file_content = file.read()  # Read the content of the uploaded file
            salt = os.urandom(16)       # Generate a random salt for encryption
            
            if operation == 'encrypt':                                                           # Check if the operation is encryption
                encrypted = cipher_suite.encrypt(file_content)                                   # Encrypt the file content using the cipher suite
                output = f"File encrypted successfully:\n{base64.b64encode(encrypted).decode()}" # Set the output to the encrypted file content with a message
            else:
                decrypted = cipher_suite.decrypt(base64.b64decode(file_content)) # Decrypt the file content using the cipher suite
                output = f"File decrypted successfully:\n{decrypted.decode()}"   # Set the output to the decrypted file content with a message
        except Exception as e:
            output = f"Error processing file: {str(e)}"                          # Catch any exceptions that occur during file processing and display an error message
    
    return render_template_string(APP_TEMPLATE, content=content, output=output)  # Render the template with the content and output variables

#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
#* TRIFORCE ASCII ART BANNER FOR THE WEB-APP     <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>

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
    print_startup_banner()                          # Displays the Triforce, ePortfolio, and Zencrypt documentation in the console when the webapp is started
    app.run(debug=True, host='0.0.0.0', port=5000)  # Runs the Flask application on a local server with debug mode enabled