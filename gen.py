import secrets

csrf_key = secrets.token_hex(16)  # 16 bytes -> 32 hex characters
print(csrf_key)
