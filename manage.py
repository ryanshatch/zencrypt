from flask import Flask
from flask_migrate import Migrate
from models import db, User, Hash, EncryptedText, Key, PGPKey
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
from utils import generate_pgp_keypair, pgp_encrypt_message, pgp_decrypt_message, generate_hash, encrypt_text, decrypt_text, encrypt_file, decrypt_file

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zencrypt.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run()
