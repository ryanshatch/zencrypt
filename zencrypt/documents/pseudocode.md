## Pseudocode for Zencrypt:

```python
BEGIN
  IMPORT necessary modules and libraries
  SET KEY_FILE = "zencrypt_p.key"

  FUNCTION save_key_to_file(key):
      OPEN KEY_FILE in binary write mode
      WRITE key to file
      CLOSE file

  FUNCTION load_key_from_file():
      OPEN KEY_FILE in binary read mode
      READ key from file
      RETURN key

  // Key Initialization
  IF KEY_FILE does NOT exist THEN
      key = GENERATE new Fernet key
      CALL save_key_to_file(key)
  ELSE
      key = CALL load_key_from_file()

  SET cipher_suite = Fernet(key)

  FUNCTION clear_clipboard():
      COPY empty string to clipboard
      PRINT "Clipboard cleared."

  FUNCTION copy_to_clipboard(text):
      COPY text to clipboard
      PRINT "Output copied to clipboard."

  FUNCTION generate_key(password, salt):
      INITIALIZE PBKDF2HMAC with SHA256, length=32, provided salt, iterations=100000
      RETURN derived key from password

  FUNCTION decrypt_text():
      PROMPT user for encrypted text
      TRY:
          decrypted_text = DECRYPT input using cipher_suite
          PRINT decrypted_text
      CATCH exception:
          PRINT error message

  FUNCTION encrypt_text():
      PROMPT user for text to encrypt
      TRY:
          encrypted_text = ENCRYPT input using cipher_suite
          PRINT encrypted_text
          RETURN encrypted_text
      CATCH exception:
          PRINT error message
          RETURN null

  FUNCTION encrypt_file(input_file, output_file, password):
      salt = RANDOM 16 bytes
      iv = RANDOM 16 bytes
      key = CALL generate_key(password, salt)
      READ plaintext from input_file
      INITIALIZE AES cipher with key and iv in CFB mode
      ciphertext = ENCRYPT plaintext using cipher
      WRITE (salt + iv + ciphertext) to output_file

  FUNCTION decrypt_file(input_file, output_file, password):
      READ data from input_file
      EXTRACT salt (first 16 bytes), iv (next 16 bytes), ciphertext (remaining bytes)
      key = CALL generate_key(password, salt)
      INITIALIZE AES cipher with key and iv in CFB mode
      plaintext = DECRYPT ciphertext using cipher
      WRITE plaintext to output_file

  FUNCTION generate_pgp_keys():
      GENERATE RSA private_key and corresponding public_key
      RETURN (private_key, public_key)

  FUNCTION encrypt_pgp_message(message, public_key):
      ENCRYPT message using RSA public_key with OAEP padding
      RETURN encrypted_message

  FUNCTION decrypt_pgp_message(encrypted_message, private_key):
      DECRYPT encrypted_message using RSA private_key with OAEP padding
      RETURN decrypted string

  FUNCTION export_public_key_to_file(public_key, filename):
      SERIALIZE public_key in PEM format
      WRITE PEM data to filename

  FUNCTION import_public_key_from_file(filename):
      READ PEM data from filename
      LOAD and RETURN public_key from PEM data

  FUNCTION main_menu():
      WHILE True:
          DISPLAY main menu options (1 to 6)
          choice = GET user input
          SWITCH choice:
              CASE "1": CALL main_loop()               // Hash Manager
              CASE "2": CALL encryption_manager()     // Encrypt Text
              CASE "3": CALL parse_files_menu()      // Encrypt Files
              CASE "4": CALL pgp_encryption_menu()  // PGP Encryption
              CASE "5": CALL clear_clipboard()	   // clear clipboard
              CASE "6": BREAK loop (Exit program) // exit
              DEFAULT: PRINT "Invalid Input."

  FUNCTION pgp_encryption_menu():
      (private_key, public_key) = CALL generate_pgp_keys()
      SET message = ""
      WHILE True:
          DISPLAY PGP encryption menu options (1 to 7)
          choice = GET user input
          SWITCH choice:
              CASE "1":
                  PROMPT for message to encrypt
                  encrypted_message = CALL encrypt_pgp_message(message, public_key)
                  message = BASE64_ENCODE(encrypted_message)
                  PRINT "Encrypted Message:", message
              CASE "2":
                  PROMPT for Base64 message to decrypt
                  TRY:
                      decoded = BASE64_DECODE(input)
                      decrypted_message = CALL decrypt_pgp_message(decoded, private_key)
                      message = decrypted_message
                      PRINT "Decrypted Message:", decrypted_message
                  CATCH exception:
                      PRINT decryption error
              CASE "3":
                  PROMPT for filename to save public key
                  CALL export_public_key_to_file(public_key, filename)
                  PRINT export confirmation
              CASE "4":
                  PROMPT for filename to import public key
                  TRY:
                      public_key = CALL import_public_key_from_file(filename)
                      PRINT import confirmation
                  CATCH exception:
                      PRINT import error
              CASE "5":
                  IF message is not empty THEN
                      CALL copy_to_clipboard(message)
                  ELSE
                      PRINT "No message to copy."
              CASE "6": CALL clear_clipboard()
              CASE "7": BREAK loop (Return to main menu)
              DEFAULT: PRINT "Invalid Input."

  FUNCTION parse_files_menu():
      WHILE True:
          DISPLAY file encryption menu options (1 to 4)
          choice = GET user input
          SWITCH choice:
              CASE "1": CALL encrypt_file_menu()
              CASE "2": CALL decrypt_file_menu()
              CASE "3": CALL clear_clipboard()
              CASE "4": BREAK loop (Return to previous menu)
              DEFAULT: PRINT "Invalid Input."

  FUNCTION encrypt_file_menu():
      TRY:
          PROMPT for input_file, output_file, password
          CALL encrypt_file(input_file, output_file, password)
          PRINT "Encryption complete."
      CATCH exception:
          PRINT encryption error

  FUNCTION decrypt_file_menu():
      TRY:
          PROMPT for input_file, output_file, password
          CALL decrypt_file(input_file, output_file, password)
          PRINT "Decryption complete."
      CATCH exception:
          PRINT decryption error

  FUNCTION encryption_manager():
      WHILE True:
          DISPLAY encryption text menu options (1 to 4)
          choice = GET user input
          SWITCH choice:
              CASE "1": CALL clear_clipboard()
              CASE "2":
                  encrypted_text = CALL encrypt_text()
                  IF encrypted_text is not null THEN
                      CALL copy_to_clipboard(encrypted_text)
              CASE "3": CALL decrypt_text()
              CASE "4": BREAK loop (Return to previous menu)
              DEFAULT: PRINT "Invalid Input."

  FUNCTION print_menu(sha256_hash):
      DISPLAY hash manager menu options (1 to 8)
      answer = GET user input
      SWITCH answer:
          CASE "1": CALL main_loop()
          CASE "2": CALL verify_hash()
          CASE "3": CALL clear_clipboard()
          CASE "4": CALL copy_to_clipboard(sha256_hash)
          CASE "5": CALL encryption_manager()
          CASE "6": CALL parse_files_menu()
          CASE "7": CALL pgp_encryption_menu()
          CASE "8": EXIT program
          DEFAULT: PRINT "Invalid Input."

  FUNCTION verify_hash():
      TRY:
          PROMPT for input_hash, original_text, salt
          computed_hash = SHA256(original_text + salt)
          IF computed_hash equals input_hash THEN
              PRINT "Hash successfully verified."
          ELSE
              PRINT "Verification unsuccessful."
      CATCH exception:
          PRINT verification error

  FUNCTION main_loop():
      SET counter = 0
      WHILE True:
          text = PROMPT user securely "Enter text:" (using getpass)
          IF text equals "exit" THEN BREAK loop
          INCREMENT counter
          PROMPT for salt
          sha256_hash = SHA256(text + salt)
          PRINT sha256_hash
          CALL print_menu(sha256_hash)
      PROMPT "Press Enter To Exit."

  PRINT ASCII Art Banner
  CALL main_menu()
END
```