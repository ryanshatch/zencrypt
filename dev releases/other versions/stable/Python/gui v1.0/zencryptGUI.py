# ****************************************************************************************
# Title: Hash Generator GUI        *******************************************************
# Developed by: Ryan Hatch         *******************************************************
# Date: October 11th 2023          *******************************************************
# Last Updated: October 12th 2023  *******************************************************
# Version: C1.5                    *******************************************************
# ****************************************************************************************

import hashlib
import os
import pyperclip
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import simpledialog, messagebox

KEY_FILE = "zencrypt_GUI.key"

# Functions:

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

def clear_clipboard():
    pyperclip.copy('')
    output_label.config(text="Clipboard cleared.")

def copy_to_clipboard():
    text_to_copy = output_label.cget("text").split(": ", 1)[-1]  # Split the text and get the part after ": "
    if text_to_copy:
        pyperclip.copy(text_to_copy)
        messagebox.showinfo("Info", "Output copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No output to copy!")

def encrypt_text():
    text_to_encrypt = text_entry.get()
    encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode()).decode()
    output_label.config(text=f"Encrypted Text: {encrypted_text}")

def decrypt_text():
    encrypted_text = text_entry.get()
    decrypted_text = cipher_suite.decrypt(encrypted_text.encode()).decode()
    output_label.config(text=f"Decrypted Text: {decrypted_text}")

def generate_hash():
    salt = simpledialog.askstring("Input", "Enter salt value:")
    sha256_hash = hashlib.sha256((text_entry.get() + salt).encode()).hexdigest()
    output_label.config(text=f"Hash: {sha256_hash}")

def verify_hash():
    input_hash = simpledialog.askstring("Input", "Enter the hash to verify:")
    original_text = simpledialog.askstring("Input", "Enter the original text to verify against the hash:")
    salt = simpledialog.askstring("Input", "Enter the salt value used during hashing:")
    computed_hash = hashlib.sha256((original_text + salt).encode()).hexdigest()
    if computed_hash == input_hash:
        output_label.config(text="Hash successfully verified.")
    else:
        output_label.config(text="Verification unsuccessful. Hash does not match.")

def on_key_press(event):
    # Check if the focus is on the text_entry widget
    if root.focus_get() == text_entry:
        return
    if event.keysym == '1':
        encrypt_text()
    elif event.keysym == '2':
        decrypt_text()
    elif event.keysym == '3':
        generate_hash()
    elif event.keysym in ['c', 'C']:
        copy_to_clipboard()
    elif event.keysym in ['v', 'V']:
        verify_hash()
    elif event.keysym in ['x', 'X']:
        clear_clipboard()
    elif event.keysym in ['q', 'Q']:
        root.destroy()

# GUI setup:

root = tk.Tk()
root.title("Hash Generator Lite with Encryption")
root.bind('<Key>', on_key_press)

# Widgets:

text_label = tk.Label(root, text="Enter Text:")
text_label.pack(pady=10)

text_entry = tk.Entry(root, width=50)
text_entry.pack(pady=10)

encrypt_button = tk.Button(root, text="1. Encrypt", command=encrypt_text)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="2. Decrypt", command=decrypt_text)
decrypt_button.pack(pady=10)

hash_button = tk.Button(root, text="3. Generate Hash", command=generate_hash)
hash_button.pack(pady=10)

verify_button = tk.Button(root, text="V. Verify Hash", command=verify_hash)
verify_button.pack(pady=10)

copy_button = tk.Button(root, text="C. Copy Output", command=copy_to_clipboard)
copy_button.pack(pady=10)

clear_button = tk.Button(root, text="x. Clear Clipboard", command=clear_clipboard)
clear_button.pack(pady=10)

quit_button = tk.Button(root, text="q. Quit", command=root.destroy)
quit_button.pack(pady=10)

output_label = tk.Label(root, text="")
output_label.pack(pady=10)

root.mainloop()
