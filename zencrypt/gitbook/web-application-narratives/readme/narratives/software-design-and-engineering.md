---
icon: database
cover: ../../../.gitbook/assets/ec2 v6.2-a.JPG
coverY: 0
---

# Software Design and Engineering

## Software Design and Engineering

Software Design and EngineeringZencrypt is a Python-based cryptographic application originally developed in August 2022 as a command line interface (CLI) tool. The most recent enhancement was just added on the 21st of January 2025 in order to convert the CLI into a modern web app, while still maintaining the original CLI functionality from Zencrypt v4. This enhancement helps to showcase software engineering principles through implementing the CLI functionality using the Flask web framework and keeping the core cryptographic functionality separate.

### Software Development and Enhancement: <a href="#software-development-and-enhancement" id="software-development-and-enhancement"></a>

The original CLI version provided encryption, hashing, and key management through a text-based interface:

```python
def encrypt_text():
    text_to_encrypt = input("\nEnter the text to encrypt: ")
    encrypted_text = cipher_suite.encrypt(text_to_encrypt.encode()).decode()
    return encrypted_text
```

The enhanced version in v5 maintains this functionality while adding a web interface through Flask routes:

```
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_page():
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            try:
                encrypted = cipher_suite.encrypt(text.encode())
                output = f"Encrypted Text:\n{encrypted.decode()}"
                return render_template_string(APP_TEMPLATE, 
                    content=content, output=output)
```

### **Justification for Enhancement** - The enhancement helps to showcase several key software engineering principles:

* **Separation of Concerns:**

Core cryptographic functions were moved to utils.py which allows both interfaces to share the same secure implementations of functions:from cryptography.fernet import Fernetdef initialize\_key():if not os.path.exists(KEY\_FILE):key = Fernet.generate\_key()with open(KEY\_FILE, "wb") as key\_file:key\_file.write(key)

* **Security Considerations:**

The web implementation maintains the same level of security as the CLI v4 while adding new considerations for web-based threats. For example, for secure session handling:app.secret\_key = secrets.token\_hex(32)

### **Learning Outcomes and Challenges:**  <a href="#learning-outcomes-and-challenges" id="learning-outcomes-and-challenges"></a>

**The enhancement process provided helpful learning opportunities for several key areas:**

* **Web Security:** Implementing secure web practices while maintaining cryptographic integrity
* **Interface Design:** Creating a solid web UI/UX for complex cryptographic operations
* **Code Organization:** Structuring the project in a scalable and modular format in order to properly maintain a clear separation between the CLI and webapps components.

The main challenge was adapting the already existing v4’s CLI based operations to a stateless web-app environment, all done without compromising any of the user’s anonymity and security. This development process required careful consideration of how to begin developing the server to later include security methods like temporary sessions and secure handling and maintenance of databases.

### Future Improvements for the WebApp / Next enhancements: <a href="#future-improvements-for-the-webapp-next-enhancements" id="future-improvements-for-the-webapp-next-enhancements"></a>

* Adding Login and add logging and temporary sessions
* Implementing MongoDB or SQLite
* Utilizing .config, .env, or even a .docker file to be used for constants

#### References/ Links to my ePortfolio and Zencrypt: <a href="#references-links-to-my-eportfolio-and-zencrypt" id="references-links-to-my-eportfolio-and-zencrypt"></a>

ePortfolio - [www.ryanshatch.com](https://www.ryanshatch.com/)&#x20;

Web Application - [www.zencrypt.app](https://www.zencrypt.app/)&#x20;

Whitepapers - [https://zencrypt.gitbook.io/zencrypt](https://zencrypt.gitbook.io/zencrypt)
