<p><img src="https://img.shields.io/badge/Author-Ryan%20S%20Hatch-0A2647?style=for-the-badge" alt="Project Author"> 
<img src="https://img.shields.io/badge/Started-January%202021-144272?style=for-the-badge" alt="Project Start Date"> 
<img src="https://img.shields.io/badge/Updated-Feb%2019%2C%202025-205295?style=for-the-badge" alt="Project Last Updated On">
<img src="https://img.shields.io/badge/Project-Zencrypt-0A2647?style=for-the-badge" alt="Project Name">
<img src="https://img.shields.io/badge/Version-v6.2.2--alpha-2C74B3?style=for-the-badge" alt="Project Version"></p>
<!-- <br>
<p><img src="https://img.shields.io/badge/Languages-Python%2C%20JavaScript%2C%20HTML%2C%20SQL-0A2647?style=for-the-badge" alt="Programming Languages"> <img src="https://img.shields.io/badge/Frameworks-Flask%2C%20React-144272?style=for-the-badge" alt="Frameworks"> <img src="https://img.shields.io/badge/Tools-SQLAlchemy-205295?style=for-the-badge" alt="Tools"></p>
<br>
<p><img src="https://img.shields.io/badge/Platform-Web%20Application-0A2647?style=for-the-badge" alt="Platform"> <img src="https://img.shields.io/badge/Deployment-Cloud%20Based-144272?style=for-the-badge" alt="Deployment Type"> <img src="https://img.shields.io/badge/Server-Gunicorn-205295?style=for-the-badge" alt="Hosting Service"></p> -->
<!-- <p><img src="https://img.shields.io/badge/Purpose-Encryption%20Platform-0A2647?style=for-the-badge" alt="Project Purpose"> <img src="https://img.shields.io/badge/Focus-Security%20Development-144272?style=for-the-badge" alt="Project Focus">  -->
<hr>

# Summary of Encryption Principles

After working with encryption for several years, I've learned that explaining these concepts doesn't need to be complex. Here's how I break down the core ideas behind Zencrypt's security approach.

## Basic Concepts

### What is Encryption?
Think of encryption like a lock on a safe. You put something inside (your data), lock it (encrypt it), and only someone with the right key can open it again. None the less, digital encryption is much stronger than any physical lock.

### Types of Keys I Use

#### Symmetric Keys (AES/Fernet)
I noticed this is easiest to understand as a single key that both locks and unlocks - like your house key. In Zencrypt, I use this for:
- Quick text encryption
- File encryption
- Session data

The challenge? You need a secure way to share this key with others.

#### Asymmetric Keys (PGP)
With that being said, sometimes you need something more sophisticated. PGP uses two keys:
- Public key: Like your address - safe to share with anyone
- Private key: Like your house key - keep it secret

Thus, anyone can encrypt messages using your public key, but only you can decrypt them with your private key.

## How I Keep Things Secure

### Hashing (SHA256)
I learned to explain hashing as a digital fingerprint. When Zencrypt creates a hash:
- It takes your input (text, password, file)
- Creates a unique fingerprint
- This fingerprint can't be reversed
- Even tiny changes create completely different fingerprints

### Salt Values
When working with passwords, I focused on adding "salt" - random data that makes each hash unique. This prevents attackers from using pre-computed tables to crack passwords.

### Key Storage
I designed Zencrypt to store keys securely by:
- Keeping them in a protected directory (/etc/secrets)
- Encrypting them in the database
- Never exposing them in logs or error messages

## Real-World Examples

### Text Encryption
When you encrypt a message in Zencrypt:
1. The system generates a strong random key
2. Your message gets locked with this key
3. Only someone with access to the key can read it

### File Encryption
For files, I implemented a more layered approach:
1. Your password creates a unique key
2. The file gets split into chunks
3. Each chunk is encrypted separately
4. A master key ties it all together

### PGP Communication
The most secure option works like this:
1. You generate your key pair
2. Share your public key with friends
3. They use it to send you encrypted messages
4. Only your private key can decode them

## Common Misconceptions

I've noticed these points often need clarification:

1. Encryption is not the same as hiding data
   - It makes data unreadable without the key
   - The encrypted data can be visible and still secure

2. Stronger passwords don't mean stronger encryption
   - The encryption strength stays the same
   - Passwords just control access to the keys

3. Speed vs. Security
   - Faster isn't always better
   - I made some operations slow on purpose to prevent attacks

## Best Practices

Through experience, I learned these key principles:

1. Key Management
   - Generate fresh keys for each session
   - Rotate keys regularly
   - Never reuse passwords across different systems

2. Data Protection
   - Encrypt data before storage
   - Use secure channels for transmission
   - Clear sensitive data from memory after use

3. Access Control
   - Limit key access to authorized users
   - Log all encryption operations
   - Monitor for unusual patterns

## Closing Thoughts

Security doesn't need to be complicated. What matters is understanding these basic principles and applying them consistently. None the less, it's crucial to stay updated with the latest security practices and continuously improve my apps implementation.

> Note: The goal isn't to make the security perfect but to make it strong enough that breaking it costs more than the protected data is worth.