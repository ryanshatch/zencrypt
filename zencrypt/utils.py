from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import hashlib
import os
import base64

KEY_FILE = "private.key"

def initialize_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

cipher_suite = Fernet(initialize_key())

def generate_hash(text: str, salt: str = "") -> str:
    return hashlib.sha256((text + salt).encode()).hexdigest()

def encrypt_text(text: str) -> str:
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text: str) -> str:
    return cipher_suite.decrypt(encrypted_text.encode()).decode()

def generate_pgp_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def encrypt_file(input_file: str, output_file: str, password: bytes):
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

def decrypt_file(input_file: str, output_file: str, password: bytes):
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

def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)