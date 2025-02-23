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

# Zencrypt Quick Start Guide

## System Overview
Zencrypt is a Flask-based web application focused on encryption, hashing, and secure file operations. I designed it to provide a seamless transition from the CLI experience to a web interface while maintaining strong security foundations.

## Key Features
- SHA256 hashing with optional salt values
- Fernet symmetric encryption for text
- AES-based file encryption with password protection
- PGP asymmetric encryption with key management
- User authentication with JWT tokens
- Secure key storage in dedicated directory
- SQLite database with encrypted storage

## Getting Started

### Prerequisites
- Python 3.11.11 or higher
- Node.js for React components
- SQLite for database operations
- NPM for package management
- Git for version control
- Virtual environment for isolation
- Flask and React dependencies
- PIP for Python package management

### Installation Steps
1. Clone the repository:

   ```bash
   git clone https://github.com/ryanshatch/Zencrypt.git
   cd Zencrypt
   ```

2. Set up virtual environment:

   ```bash
   python -m venv zenven
   source zenven/bin/activate  # Linux / macOS
   zenven\Scripts\activate     # Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   npm install
   ```

4. Configure environment:
   - Create `.env` file in project root
   - Set required variables:

     ```env
     FLASK_ENV=development
     FLASK_APP=app.py
     SECRET_KEY=secret_key
     JWT_SECRET_KEY=some_secret_key
     SQLALCHEMY_DATABASE_URI=supported_database_uri
     ```

### Starting the Application

1. Initialize the database:

   ```bash
   flask db upgrade
   ```

2. Start the server:

   ```bash
   python webapp.py
   ```

   The application will be available at `http://localhost:5000`

## Core Operations

### Text Encryption

1. Log in to your account
2. Navigate to the Encrypt Text section
3. Enter your text
4. The encrypted output will be displayed below

### File Operations

1. Select File Operations from the navbar
2. Choose Encrypt or Decrypt
3. Upload your file
4. Enter a secure password
5. Download the processed file

### PGP Key Management

1. Access the PGP section
2. Generate your keypair
3. Export public key for sharing
4. Use recipient's public key for encryption

## Security Considerations

- Passwords are hashed with SHA256
- Encryption uses Fernet and PGP standards
- Keys are stored in dedicated directory
- Session management uses JWT tokens
- File operations use AES encryption
- Database is SQLite with encrypted storage
- Key rotation is available through settings

## Common Issues

- If database access fails, check the connection string for the correct permissions and path
- Double check that the environment variables are set correctly
- JWT token expiration is set to 1 hour
- Large files are processed in chunks for memory efficiency

## Next Steps

For detailed documentation and updates, visit:
- Documentation: https://zencrypt.gitbook.io/zencrypt
- Source Code: https://github.com/ryanshatch/zencrypt
- Web-App: https://zencrypt.app

For support or questions, contact: ryanshatch@gmail.com
