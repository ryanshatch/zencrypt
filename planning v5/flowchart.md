## Flowchart for Zencrypt CLI:

```ps
Start
  │
  ├── Initialize Key File
  │      ├── IF KEY_FILE does not exist:
  │      │         ├── Generate new Fernet key
  │      │         └── save_key_to_file(key)
  │      └── ELSE:
  │            └── key = load_key_from_file()
  │
  ├── SET cipher_suite = Fernet(key)
  │
  ├── Print ASCII Art Banner
  │
  └── CALL main_menu()
          │
          ├── Loop Start (Main Menu)
          │      └── Display Main Menu Options:
          │                1 | Hash Manager
          │                2 | Encrypt Text
          │                3 | Encrypt Files
          │                4 | PGP Encryption
          │                5 | Clear Clipboard
          │                6 | Exit
          │      └── GET user choice
          │
          ├── SWITCH on Main Menu Choice:
          │
          ├── [Choice "1"]: 
          │      └── CALL main_loop()
          │             ├── SET counter = 0
          │             └── Loop Start (main_loop)
          │                    ├── Prompt "Enter text:" (using getpass)
          │                    ├── IF text == "exit": Break loop
          │                    ├── INCREMENT counter
          │                    ├── Prompt for salt
          │                    ├── Compute sha256_hash = SHA256(text + salt)
          │                    ├── Print sha256_hash
          │                    └── CALL print_menu(sha256_hash)
          │                            └── [Refer to Print Menu branch below]
          │
          ├── [Choice "2"]:
          │      └── CALL encryption_manager()
          │             └── Loop Start (encryption_manager)
          │                    ├── Display Encrypt Text Menu Options:
          │                    │         1 | Clear Clipboard
          │                    │         2 | Encrypt Text
          │                    │         3 | Decrypt Text
          │                    │         4 | Return to Hashing
          │                    ├── GET user choice
          │                    └── SWITCH:
          │                           ├── If "1": clear_clipboard()
          │                           ├── If "2": 
          │                           │         └── CALL encrypt_text()
          │                           │                 ├── Prompt for text to encrypt
          │                           │                 ├── Try to encrypt using cipher_suite
          │                           │                 ├── Print encrypted text
          │                           │                 └── RETURN encrypted_text
          │                           │         └── IF encrypted_text valid:
          │                           │                   copy_to_clipboard(encrypted_text)
          │                           ├── If "3": decrypt_text()
          │                           │         ├── Prompt for encrypted text
          │                           │         ├── Try to decrypt using cipher_suite
          │                           │         └── Print decrypted text/error
          │                           └── If "4": Break loop (Return to Main Menu)
          │
          ├── [Choice "3"]:
          │      └── CALL parse_files_menu()
          │             └── Loop Start (parse_files_menu)
          │                    ├── Display File Encryption Menu Options:
          │                    │         1 | Encrypt File
          │                    │         2 | Decrypt File
          │                    │         3 | Clear Clipboard
          │                    │         4 | Return To Hashing
          │                    ├── GET user choice
          │                    └── SWITCH:
          │                           ├── If "1": encrypt_file_menu()
          │                           │         ├── Prompt for input_file, output_file, password
          │                           │         ├── CALL encrypt_file(input_file, output_file, password)
          │                           │         └── Print "Encryption complete"/error
          │                           ├── If "2": decrypt_file_menu()
          │                           │         ├── Prompt for input_file, output_file, password
          │                           │         ├── CALL decrypt_file(input_file, output_file, password)
          │                           │         └── Print "Decryption complete"/error
          │                           ├── If "3": clear_clipboard()
          │                           └── If "4": Break loop (Return to Main Menu)
          │
          ├── [Choice "4"]:
          │      └── CALL pgp_encryption_menu()
          │             ├── (private_key, public_key) = generate_pgp_keys()
          │             ├── SET message = ""
          │             └── Loop Start (pgp_encryption_menu)
          │                    ├── Display PGP Menu Options:
          │                    │         1 | Encrypt Message
          │                    │         2 | Decrypt Message
          │                    │         3 | Export Public Key
          │                    │         4 | Import Public Key
          │                    │         5 | Copy to Clipboard
          │                    │         6 | Clear Clipboard
          │                    │         7 | Back to Main Menu
          │                    ├── GET user choice
          │                    └── SWITCH:
          │                           ├── If "1":
          │                           │         ├── Prompt for message
          │                           │         ├── CALL encrypt_pgp_message(message, public_key)
          │                           │         ├── BASE64 encode result, store in message
          │                           │         └── Print encrypted message
          │                           ├── If "2":
          │                           │         ├── Prompt for Base64 message
          │                           │         ├── TRY to BASE64 decode, then decrypt with private_key
          │                           │         └── Print decrypted message/error
          │                           ├── If "3":
          │                           │         ├── Prompt for filename
          │                           │         ├── export_public_key_to_file(public_key, filename)
          │                           │         └── Print confirmation
          │                           ├── If "4":
          │                           │         ├── Prompt for filename
          │                           │         ├── TRY import_public_key_from_file(filename) and update public_key
          │                           │         └── Print confirmation/error
          │                           ├── If "5":
          │                           │         ├── IF message not empty THEN copy_to_clipboard(message)
          │                           │         └── ELSE print "No message to copy."
          │                           ├── If "6": clear_clipboard()
          │                           └── If "7": Break loop (Return to Main Menu)
          │
          ├── [Choice "5"]:
          │      └── CALL clear_clipboard()
          │
          ├── [Choice "6"]:
          │      └── Break loop, exit program
          │
          └── DEFAULT:
                 └── Print "Invalid Input."
```

## Individual Flowchart For Main Loop and Verifying Hashes:

### Print Menu / main_loop():

```ps
print_menu(sha256_hash)
       ├── Display Hash Manager Options:
       │         1 | Generate Hash
       │         2 | Verify Hash
       │         3 | Clear Clipboard
       │         4 | Copy Output
       │         5 | Encrypt Text Menu
       │         6 | Encrypt File Menu
       │         7 | PGP Encryption
       │         8 | Close Zencrypt
       ├── GET user answer
       └── SWITCH:
                ├── If "1": CALL main_loop()
                ├── If "2": CALL verify_hash()
                ├── If "3": clear_clipboard()
                ├── If "4": copy_to_clipboard(sha256_hash)
                ├── If "5": encryption_manager()
                ├── If "6": parse_files_menu()
                ├── If "7": pgp_encryption_menu()
                ├── If "8": EXIT program
                └── DEFAULT: Print "Invalid Input."
```

### Verify SHA256 / verify_hash() Branch:

```ps
verify_hash()
   ├── Prompt for input_hash, original_text, salt
   ├── Compute computed_hash = SHA256(original_text + salt)
   ├── IF computed_hash == input_hash:
   │         └── Print "Hash successfully verified."
   └── ELSE:
             └── Print "Verification unsuccessful."
```