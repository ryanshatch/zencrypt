<!--
********************************************************************************************
* Title: Zencrypt WebApp           |********************************************************
* Developed by: Ryan Hatch         |********************************************************
  Date: August 10th 2022           |********************************************************
  Last Updated: February 13th 2025 |********************************************************
  Version: 5.3.3                   |********************************************************
********************************************************************************************
*-****************************** Zencrypt v5.3-A3 |*****************************************
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
|              Zencrypt Web-App is a Flask application that can be used to:                |
|       - Generate hashes: using SHA256 hashing algorithm, with an optional salt value.    |
|       - Encrypt text and files: using Fernet symmetric encryption algorithm.             |
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
-->
<!DOCTYPE html>
<!DOCTYPE html>
<html>
  <body>
    <hr>
    <h1 align="center">Zencrypt</h1>
    <hr>
      <p align="center">
      <a href="https://www.dial.to/?action=solana-action:https://action.solscan.io/api/donate?receiver=777ePKXhcxMdJPMA22YeiR6pdMUTadnpT7AUyto2Y24N">
      <img src="https://img.shields.io/badge/tip me in $solana-black?style=for-the-badge&logo=solana&logoColor=blue" alt="solana" />
    </a>
    <br>
    <p align="center">
      <strong>Webapp Release - v6.2-alpha</strong>
<!--       <br>
      <strong>By: Ryan Hatch</strong> -->
      <br>
    </p>
    <p align="center">
      <a href="#table-of-contents">Table of Contents</a><br>
       <a href="#introduction">Introduction</a> • <a href="#features">Features</a> • <a href="#installation">Installation</a> • <a href="#usage">Usage</a> • <a href="#examples">Examples</a> • <a href="#contributing">Contributing</a> • <a href="#disclaimer">Disclaimer</a> • <a href="#license">License</a> • <a href="#contact">Contact</a>
    </p>
    <hr>
    <p align="center">
<!--       <br> -->
      <strong>Developed By: Ryan Hatch</strong>
    <p align="center"> &copy; 2025 Ryan Hatch <br> All Rights Reserved.<br><i><br>This software is proprietary and owned by Ryan Hatch. Unauthorized use, modification, or distribution is prohibited.</i> </p>
<p align="center"><img src="https://img.shields.io/badge/Name:-Zencrypt-0A2647?style=for-the-badge" alt="Project Name"><img src="https://img.shields.io/badge/Author-Ryan%20S%20Hatch-0A2647?style=for-the-badge" alt="Project Author"> <img src="https://img.shields.io/badge/Started-January%202021-144272?style=for-the-badge" alt="Project Start Date"> <img src="https://img.shields.io/badge/Updated-Feb%2019%2C%202025-205295?style=for-the-badge" alt="Project Last Updated On"></p>
<p align="center"><img src="https://img.shields.io/badge/Type:-Software%20Development-144272?style=for-the-badge" alt="Project Type"> <img src="https://img.shields.io/badge/Stage:-Production%20Ready-205295?style=for-the-badge" alt="Project Stage"> <img src="https://img.shields.io/badge/Version-v6.2.2--alpha-2C74B3?style=for-the-badge" alt="Project Version"></p>
<hr>
<div class="webapp">
  <h1>Webapp v6 and CLI v4.2</h1>
  <!-- <h2>Webapp v6</h2> -->
  <ul>
    <li><a href="README.md">What is Zencrypt</a></li>
    <li><a href="cipher/zencrypt-cli.md">Getting To Know About The Zencrypt CLI</a></li>
  </ul>
  <h2>Zencrypt Whitepapers</h2>
  <ul>
    <li>
      <a href="cipher-whitepapers/zencrypt-documentation/README.md">Zencrypt Documentation</a>
      <ul>
        <li>
          <a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/README.md">A Shorter Description About My Enhancement Plans for Zencrypt:</a>
          <ul>
            <li>
              <a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/software-engineering-and-design/README.md">Enhancing and Updating The Software Engineering and Design</a>
              <ul>
                <li><a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/software-engineering-and-design/explanation-of-key-flowchart.md">Key Flowchart Explanation</a></li>
              </ul>
            </li>
            <li>
              <a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/updating-zencrypt-algorithms-and-data-structures/README.md">Updating The Algorithms and Data Structures:</a>
              <ul>
                <li><a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/updating-zencrypt-algorithms-and-data-structures/flowchart-explanation.md">Flowchart Explanation</a></li>
              </ul>
            </li>
            <li>
              <a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/updating-zencrypt-databases/README.md">Enhancing the Database Management For Zencrypt</a>
              <ul>
                <li><a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/updating-zencrypt-databases/flowchart-explanation.md">Flowchart Explanation</a></li>
              </ul>
            </li>
            <li>
              <a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/skills-and-illustrated-outcomes/README.md">Skills and Illustrated Outcomes</a>
              <ul>
                <li><a href="cipher-whitepapers/zencrypt-documentation/a-shorter-description-about-my-enhancement-plan-for-zencrypt-cli/skills-and-illustrated-outcomes/eportfolio-in-current-state.md">ePortfolio</a></li>
              </ul>
            </li>
          </ul>
        </li>
      </ul>
    </li>
  </ul>
</div>
<hr>
<div class="table-of-contents">
  <h1 align="center">Zencrypt <code>v6-A2</code> Web Application:</h1>
<!-- <p align="center"><img src="https://img.shields.io/badge/Name:-Zencrypt-0A2647?style=for-the-badge" alt="Project Name"><img src="https://img.shields.io/badge/Author-Ryan%20S%20Hatch-0A2647?style=for-the-badge" alt="Project Author"> <img src="https://img.shields.io/badge/Started-January%202021-144272?style=for-the-badge" alt="Project Start Date"> <img src="https://img.shields.io/badge/Updated-Feb%2019%2C%202025-205295?style=for-the-badge" alt="Project Last Updated On"></p>
<p align="center"><img src="https://img.shields.io/badge/Type:-Software%20Development-144272?style=for-the-badge" alt="Project Type"> <img src="https://img.shields.io/badge/Stage:-Production%20Ready-205295?style=for-the-badge" alt="Project Stage"> <img src="https://img.shields.io/badge/Version-v6.2.2--alpha-2C74B3?style=for-the-badge" alt="Project Version"></p> -->
<hr>
<!-- <br>
<p><img src="https://img.shields.io/badge/Languages-Python%2C%20JavaScript%2C%20HTML%2C%20SQL-0A2647?style=for-the-badge" alt="Programming Languages"> <img src="https://img.shields.io/badge/Frameworks-Flask%2C%20React-144272?style=for-the-badge" alt="Frameworks"> <img src="https://img.shields.io/badge/Tools-SQLAlchemy-205295?style=for-the-badge" alt="Tools"></p>
<br>
<p><img src="https://img.shields.io/badge/Platform-Web%20Application-0A2647?style=for-the-badge" alt="Platform"> <img src="https://img.shields.io/badge/Deployment-Cloud%20Based-144272?style=for-the-badge" alt="Deployment Type"> <img src="https://img.shields.io/badge/Server-Gunicorn-205295?style=for-the-badge" alt="Hosting Service"></p> -->
  <p align="center"><img src="https://img.shields.io/badge/Purpose-Encryption%20Platform-0A2647?style=for-the-badge" alt="Project Purpose"> <img src="https://img.shields.io/badge/Focus-Security%20Development-144272?style=for-the-badge" alt="Project Focus"> <img src="https://img.shields.io/badge/Milestones-Merge%20CLI%20to Web%20App-205295?style=for-the-badge" alt="Project Milestones"></p>
  <p align="center"><img src="https://img.shields.io/badge/Testing Code:-Snyk-0A2647?style=for-the-badge" alt="Snyk Tests"> <img src="https://img.shields.io/badge/Testing App:-OWASP%20ZAP-144272?style=for-the-badge" alt="Testing"> <img src="https://img.shields.io/badge/Quality%20Assurance-8.5/10-205295?style=for-the-badge" alt="Quality Assurance">
  <img src="https://img.shields.io/badge/Status-Fully%20Complete-2C74B3?style=for-the-badge" alt="Project Status"></p>
<hr>

<h4 align="center"><code>
  <a href="#1-project-purpose-and-evolution">Project Purpose and Evolution</code></a> •
  <code><a href="#2-architecture--technology-stack">Architecture & Technology Stack</code></a> •
  <code><a href="#3-features-and-functionalities">Features and Functionalities</code></a>
  <br>
  <code><a href="#4-documentation-flowcharts-and-future-enhancements">Documentation, Flowcharts, and Future Enhancements</code></a> •
  <code><a href="#5-deployment-and-operational-considerations">Deployment and Operational Considerations</code></a> •
  <code><a href="#6-summary">Summary</a>
</code></h4>
<hr>

<h5>I started this project with a CLI script that used core encryption functions and was designed with the purpose of parsing sensitive information offline to be encrypted or decrypted.<br><br> This project was intended to merge the final CLI program into a full fledged webapp that has all of the same functions. In the end, with <code>version 6-alpha</code>, the webapp resulted in a full fledged cipher that handles everything from hashing, AES, RSA, and fully implemented PGP functionality.
<br><br>
I worked on hosting Zencrypt on different web platforms and building a clean, modular design where each part works independently. None the less, I made sure to keep the core security hardened while making it easier for others to use the system.</h5>
</p>
<h5>
I made sure to keep the technical foundation solid and chose Flask as the framework for the backend while implementing JWT authentication and proper key management in sub directories of the system. With that being said, the frontend needed to be just as thought out so I decided to use React to build my front end. To make the page UI/UX and navigation clean I created components for the webapp like <code>Navbar.js</code> and <code>auth.js</code> that would give users a clean UI for any device used to access the webapp.
<br><br>
I learned that separating the modules as utilities, database models, and web routes not only made the code cleaner but it made it much easier to use as a foundation to build off of in the future. In other words, keeping the code structured and clean made it more scalable in the end. I do still want to keep building on this project and adding more features and functionalities. For example, integrating ECC and Argon2 hashing while optimizing the way that large files are handled via parallel processing. Once I have <code>version 6</code> the way I like it, for <code>version 7</code> I plan on putting it on the blockchain and merging once again, but this time from web2 to web3 development.
</h5>

> For now, I'm satisfied with the ways that Zencrypt has evolved from a simple CLI tool into a scalable and modular web platform. Starting out as a hash generator, Zencrypt has become more than just an encryption suite, but more or less, it shows a genuine reflection of my commitment to strong and solid security practices along with clean software design and development. In order to make an app have complex and intricate back ends without compromising the UI/UX is to simply remember that the key to web development is to **`keep it simple.`**</p>

<hr>


### 1. **Project Purpose and Evolution**

- **Core Functionality:**  
I started Zencrypt as a simple command-line tool, focusing primarily on basic SHA-256 hash generation and verification. With that being said, I learned quite a bit while developing each version, steadily expanding its capabilities to include comprehensive file encryption and RSA-based PGP features that give users more control over their security needs. None the less, my work on version 4.2 marked a significant milestone - I noticed the need to restructure the entire system into distinct modules, making it easier to scale while maintaining solid security practices.

- **Evolutionary Path:**  
Throughout this journey, I focused on transforming Zencrypt from a single-file script into a full-fledged web service without compromising its core security principles. I made sure each component could stand independently, thus creating a more dependable foundation for future enhancements. With that experience, I've learned that good software isn't just about adding features - it's about building a structure that stays strong as it grows.

---

### 2. **Architecture & Technology Stack**

- **Backend Architecture:** I built the core application using *Flask*, focusing on creating secure *routes for authentication, encryption, and file handling*. None the less, I realized how important it was to have solid data management, so I implemented *SQLAlchemy ORM* for modeling users, hashes, and encryption keys into a dedicated module. None the less, I made sure to include `Flask-Migrate` and `Alembic` to properly be able to handle database changes or merges but still keeping it flexible and scalable for other systems. I used SQLite for development and production, but for this reason I made sure to keep the code modular to easily switch to another storage system or database, like MongoDB or MySQL.

- **Security Implementation:** I focused on implementing *JWT authentication* through `Flask-JWT-Extended`, making sure that only registered users can access the webapp. None the less, this project has helped teach me that proper key management plays a crucial role in keeping the foundations of the webapp secure. With that in mind, I decided to store all of the sensitive configurations in external environment files and keys in specific directories outisde of the user environment, to respect the users privaledges and rules, while still having dedicated functions for key rotation and management.

- **Cryptographic Foundation:** For encryption, I chose to use Fernet for handling text and AES (*in CFB mode*) for files, implementing a random salt for secure key derivation. In my webapp, I also noticed PGP encryption needed to be approached differently. To still get the functionality, I developed RSA functions for handling asymmetric encryption, along with generating keys and any file operations as well. This approach helped me understand that different encryption methods require different frameworks and implementations, but still can be achieved with a modular codebase and a solid foundation.

- **Frontend Development:** I designed a responsive UI using React to help the layout stand out by adding components like `Navbar.js`, which is a navigation feature that helps provide the user with a clean and simple way to access to all of the webapp's features. I also made sure that `auth.js` handled not just the user authentication but also was integrated with the system used to generate PGP keys. This was a big way to keep a solid structure in modularity, scalability, and security, while still keeping the UI/UX simple and easy to use. Each user is given a unique set of keys, which is used when encrypting using PGP, thus making it to where the users dont have to worry about managing or sharing keys, but still have the ability to export and import keys as needed. This is a small feature that I believe can be made as a good example of how something simple can be made complex and intricate without compromising the UI/UX.

- **CLI Integration:** I made sure that `version 6` of Zencrypt kept its CLI foundation while expanding into a web application. None the less, I noticed that keeping the core cryptographic functions in utils.py modular enough to serve both interfaces was important. This helped me learn how to keep the codebase clean and maintainable, while still being able to expand and add features without having to rewrite the entire system. Mind mapping the structure of the code and the way the user interacts with the system helped me understand that the key to web development is to keep it simple, and to make sure that the user can interact with the system in a way that is easy to understand and use.

---

### 3. **Features and Functionalities**

- **Hash Generation:**
  - Uses SHA256 with an optional salt.
  - Hashes can be stored in the database for parsing or later verification.

- **Text Encryption/Decryption:**
  - Implements encryption of text using Fernet.
  - Both encryption and decryption are supported.

- **File Encryption/Decryption:**
  - Encrypts files using AES with a random salt and initialization vector, and decrypts them using the same key.
  - Supports file `uploads`, `processing`, and `download` operations, depending on the user's input.

- **PGP Encryption:**
  - Generates RSA keys for the user and encrypts messages using the recipient's public key.
  - Allows users to encrypt messages using a recipients public key and decrypt messages using their own private key.
  - Features for exporting and importing public keys are optional but provided to enhance the security of key management.

- **User Authentication & Session Management:**
  - Secure registration and login routes, including password hashing and JWT-based authentication.
  - Session management ensures that users can access their data securely and efficiently.
  - User-specific encryption keys are generated and stored securely to ensure data privacy.

- **Database Operations:**
  - Models are defined for storing user information, encryption keys, logs of hashing or encryption events, and PGP keys.
  - SQLAlchemy ORM is used for database interactions, making it easy to manage and query data.
  - Database migrations are handled using Flask-Migrate and Alembic, ensuring that the database schema can be updated seamlessly.
  - The use of SQLite for development and production databases ensures a lightweight and scalable solution.
  - The modular code structure allows for easy switching to other database systems like MongoDB or MySQL.

- **UI/UX Enhancements:**
  - The React components help to create a responsive and intuitive user interface. Features like `Navbar.js` and `auth.js` provide easy navigation and user authentication.
  - The UI is designed to be clean, simple, and user-friendly, ensuring that users can easily access and utilize the encryption features.
  - The integration of PGP encryption features into the UI demonstrates a commitment to enhancing security while maintaining the UI/UX simplicity.
  - Zencrypt is still being developed in a format where eventually both, the CLI and    Web-Applciation can be merged into one and make it easier for user to access the system in a way that is easy to understand and use.

---

### 4. **Documentation, Flowcharts, and Future Enhancements**

**Extensive Documentation:** I focused on making all of the documentation on Zencrypt to be clear and purposeful and explain both the how and why behind my development and design choices. I made sure to include detailed diagrams that can be used to better visualize  database interactions and encryption workflows. This helped me as well, because the more that I was able to mind map the structure of the code and the way the user interacts with the system, the more detail I was able to put into the documentation, which in turn helps the users understand the system better. I used to struggle with organization and documentation, but I learned that the more that I was able to add into the details, the more the users were able to understand and expect from the system.

**Whitepapers:** With that being said, I created a few important documents like "A Shorter Description About My Enhancement Plan for Zencrypt CLI" to help explain what the goal of this project is and to track the project's progress during the merge to the webapp. I also found that using flowcharts inside of my documentation is a good way to help users to properly visualize the systems logic and the back end more effectively.

**Enhancement Plans:** I mapped out several enhancements that I still want to implement. For example, I plan to add ECC encryption and Argon2 hashing to the system, as well as optimize large file handling through parallel processing. I also plan to transition Zencrypt from web2 to web3, bringing its security features to the blockchain. These enhancements will help me to continue to grow and develop the system, while still keeping the core features and functionality of the system in place.

**Professional Skills and ePortfolio:** I've learned that building secure software is about more than just writing code, but is also about creating systems that grow thoughtfully. Looking back at the progress along the way, from a CLI tool to a web platform, I noticed how each change taught me something valuable about security and scalable design. 

With that being said, Im still planning on adding different methods of encryption and hashing along with optimizing the way that large files are currently handled, by using parallel processing. For version 7, Im hopeful to be able to transition this application yet again, but this time from web2 to web3 applications. None the less, Im still satisfied to see my work reflecting in both, solid security practices and in clean development principles.

---

### 5. **Deployment and Operational Considerations**

**Deployment Configuration:** I set up Zencrypt for cloud deployment using Gunicorn as my web server, configuring everything in render.yaml. With that being said, I learned that proper environment variable management was crucial for maintaining security in production. Thus, I made sure that my configuration system remained flexible yet secure across different deployment environments. I also made sure to keep the code modular, so that it could be easily deployed to different cloud services, like AWS or Azure, without having to rewrite the entire system.

**Testing and Quality Assurance:** I focused heavily on building a thorough testing process for Zencrypt. I started with unit tests in test_webapp.py to make sure that the database operations stayed solid. Then I ran security checks using Snyk for vulnerability scanning and OWASP ZAP to guard against common web attacks. With that being said, I made sure to maintain clean code practices, using Pylint and Flake8 to keep my codebase consistent. I also made sure to keep the code modular, so that it could be easily tested and maintained, without having to, once again, rewrite the entire system.

---

### 6. **Summary**

Looking back at Zencrypt's progress along the last few months, I have seen how the program grew from a simple offline and local CLI tool into something online, accessible, and more meaningful. I focused on merging traditional encryption methods with modern methods and technologies in order to create a platform that stays secure while still being easier to use. On another note, I was taught that good software design is about balancing simple and complex functionalities without breaking the UI/UX. In my case, I combined the reliability that Flask offers with React's clean UI, all while maintaining strong cryptographic foundations in the design.

I made sure every part of Zencrypt reflected showed that there was a thought process before and during the development, from the modular architecture that I used in my code to the length of my in depth documentation. In the end, my little hash generator CLI has been merged into something that can be looked at as more than just code and a website. Zencrypt has become a timestamped entry journal over the past several years that can be used to see how I approach software development with security in mind. Zencrypt is a testimony as to the way that I practice keeping a balance between security and usability, while still keeping the code clean and maintainabl

<hr>

<h2 id="table-of-contents">Table of Contents</h2>
<h2>Changelog:</h2>
<h3>Logs of Recent Updates:</h3>
<li>Jan 20 2025 - Updated comments and added a more simple structure for the changes to be made.</li>
<li>Jan 21st 2025 - Merged the CLI into a webapp using the Flask framework. The current version is being hosted at <a href="https://zencrypt.app">Zencrypt.app</a></li>
<li>Jan 22nd 2025 - Users can upload files for encryption and decryption.</li>
<li>Jan 26th 2025 - Allows users to manage sessions by creating an account and logging in.</li>
<li>Jan 27th 2025 - Fully merged MongoDB into the backend for user authentication and session management.</li>
<li>Jan 28th 2025 - Created new schemas for the database to store user information and session data.</li>
<hr>
<h2 id="introduction">Introduction</h2>
<p> Zencrypt is a webapp that allows users to hash, encrypt, and decrypt text and files. The webapp runs on the Flask framework and is hosted at <a href="https://zencrypt.app">Here.</a>
    <br>
    <p>The web app is built for simplicity and ease of use, allowing users to hash, encrypt, and decrypt text and files effortlessly. Future updates will include PGP encryption, fully integrating the CLI scripts capabilities into the web app. The backend uses MongoDB for user authentication, session management, and securely storing encrypted metadata while keeping user inputs in plain text.</p>
<h2 id="features">Features</h2>
<h2>System Overview</h2>
<p>Zencrypt is a Flask-based web application focused on encryption, hashing, and secure file operations. The project aims to provide a seamless transition from the CLI experience to a web interface while maintaining strong security foundations.</p>
<h2>Functions</h2>
<ul>
  <li>SHA256 hashing with optional salt values</li>
  <li>Fernet symmetric encryption for text</li>
  <li>AES-based file encryption with password protection</li>
  <li>PGP asymmetric encryption with key management</li>
  <li>User authentication with JWT tokens</li>
  <li>Secure key storage in dedicated directory</li>
  <li>SQLite database with encrypted storage</li>
</ul>
<h2 id="installation">Installation</h2>
<p> To install Zencrypt, you will need to follow these steps: </p>
<ol>
  <li>Clone the repository or download the source code with the command:<br><code>git clone https://github.com/ryanshatch/Zencrypt.git</code>. </li>
    <li>Navigate to the project directory with the command: <code>cd Zencrypt</code>. </li>
    <li>First, you will need to install Python 3.7 or higher. You can download Python from the official website: <a href="https://www.python.org/downloads/">https://www.python.org/downloads/</a>. </li>
        <li>Next, you will need to install pip, the Python package manager. You can install pip by following the instructions on the official website: <a href="https://pip.pypa.io/en/stable/installation/">https://pip.pypa.io/en/stable/installation/</a>. </li>
        <li>Once you have installed Python and pip, you can create a virtual environment with the command: <code>python -m venv venv</code>. </li>
        <li>Activate the virtual environment with the command: <code>source venv/bin/activate</code> on Linux or <code>venv\Scripts\activate</code> on Windows. </li>
  <li>Install the required dependencies with the command: <code>pip install -r requirements.txt</code>. </li>
</ol>
<h2 id="usage">How to Run Locally:</h2>
<p> To use the webapp, you will need to follow these steps: </p>
<ol>
  <li>Run the webapp with the command: <code>python webapp.py</code>. </li>
  <li>Open a web browser and navigate to <code>http://localhost:5000</code>. </li>
  <li>Use the webapp to hash, encrypt, and decrypt text and files. </li>
</ol>
<hr>
<p>PGP Functionality:
Users and how it ties with their email within the PGP functionality to lookup the public key of the recipient within the database for encryption/ decryption.

The process is:

User enters recipient's email
System looks up that user in the database
Gets that user's public PGP key
Uses that public key to encrypt the message
This follows the standard PGP encryption workflow where:

Messages are encrypted using the recipient's public key
Only the recipient can decrypt it using their private key
No actual emails are sent - it's just used as an identifier to find the right public key
Think of it like a mailbox system - you need someone's address (email) to look up their mailbox (public key) to send them an encrypted message.

In your code, the "Recipient's email" is not used for sending emails - it's used to look up the recipient's PGP public key in the database for encryption. Here's how it works:
</p>

```python
@app.route('/pgp/encrypt', methods=['POST'])
def pgp_encrypt():
    if not session.get('user_id'):
        return redirect(url_for('login'))

    message = request.form.get('message')
    recipient_email = request.form.get('recipient_email')
    
    try:
        # Right here it looks up the recipient user by their email
        recipient = User.query.filter_by(email=recipient_email).first()
        if not recipient:
            return "Recipient not found", 404
            
        # Get recipient's public key from database    
        recipient_key = PGPKey.query.filter_by(user_id=recipient.id, active=True).first()
        if not recipient_key:
            return "Recipient has no active PGP key", 400
            
        # Use recipient's public key to encrypt the message
        encrypted = pgp_encrypt_message(message, recipient_key.public_key)
        return render_template_string(APP_TEMPLATE,
            content="Encrypted message:<br><textarea readonly>%s</textarea>" % encrypted)
    except Exception as e:
        return f"Error encrypting message: {str(e)}", 500
```

The process I am using is:
1. The user will enter the recipients email enters recipient's email
2. The System looks for that user in the database using the email as the unique identifier
3. Gets that user's public PGP key from the database
4. Uses that public key stored in the database to encrypt the message

This follows the standard PGP encryption workflow where:
- Messages are encrypted using the recipient's public key
- Only the recipient can decrypt things using their private key
- No actual emails are sent, so the email is just used as an identifier to find the right public key
<br>
<hr>
    <h2 id="examples">Examples of CLI (v4.2-alpha) Functionality:</h2>
    <h3 align="center">Hashing:</h3>
    <center>
      <img alt="Hashing Example" src="https://github.com/ryanshatch/zencrypt/blob/v6.2.2-alpha/img/zencrypthash.png" style="width: 100%; height: 100%;" />
    </center>
    <h3 align="center">Cipher:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/zencrypt/blob/v6.2.2-alpha/img/zencrypt.PNG" style="width: 100%; height: 100%;" />
    </center>
    <h3 align="center">Encrypting Parsed Files:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/zencrypt/blob/v6.2.2-alpha/img/encrypt.PNG" style="width: 100%; height: 50%;" />
    </center>
        <h3 align="center">PGP Encryption:</h3>
    <center>
      <img alt="Cipher Example" src="https://github.com/ryanshatch/zencrypt/blob/v6.2.2-alpha/img/pgpencryption.PNG" style="width: 100%; height: 50%;" />
    </center>
    </p>
    <hr><br>
    <h1 align="center" id="disclaimer"><bold>DISCLAIMER!</bold></h1>
    <p align="center">
      <strong>
        <=>
          <=>
            <=>
              <=>
                <=>
                  <=>
                    <=>
                      <=>
                        <=>
                          <=>
                            <=>
                              <=>
                                <=>
                                  <=>
                                    <=>
                                      <=>
                                        <=>
                                          <=>
                                            <=>
                                              <=>
                                                <=>
                                                  <=>
                                                    <=>
                                                      <=>
                                                        <=>
                                                          <=>
                                                            <!-- <=><=><=><=> -->
      </strong>
      </br>
      <!-- <p align="center"><strong><=><=><=></strong></br></p> -->
    <p align="center">
      <strong>
        <code>This script is provided for educational and demonstration purposes only. <br>Use it responsibly and please adhere to all applicable laws and regulations. </code>
      </strong>
      </br>
    </p>
    <!-- <strong>This script is provided for educational and demonstration purposes only. Use it responsibly and adhere to all applicable laws and regulations.</strong></br></p> -->
    <p align="center">
      <strong>
        <code>I am absolutely immune from any responsibility in regaurds to any damages or loss of data caused by the <br>use, abuse, or misuse of this software. </code>
      </strong>
      </br>
      <!-- <p align="center"><strong><=><=><=></strong></br></p> -->
    <p align="center">
      <strong>
        <=>
          <=>
            <=>
              <=>
                <=>
                  <=>
                    <=>
                      <=>
                        <=>
                          <=>
                            <=>
                              <=>
                                <=>
                                  <=>
                                    <=>
                                      <=>
                                        <=>
                                          <=>
                                            <=>
                                              <=>
                                                <=>
                                                  <=>
                                                    <=>
                                                      <=>
                                                        <=>
                                                          <=>
                                                            <!-- <=><=><=><=> -->
      </strong>
      </br>
    </p><hr>
    <h2 align="center" id="liscense">Liscense</h2>
    <p> This software is the property of the copyright holder and is protected by copyright laws. All rights are reserved. The copyright holder grants no implied or express license for the use, copying, modification, distribution, or reproduction of this software, in whole or in part, without the prior written permission of the copyright holder. </p>
    <p> Any unauthorized use, copying, modification, distribution, or reproduction of this software, in whole or in part, is strictly prohibited and constitutes a violation of copyright law. Such unauthorized use may result in civil and/or criminal penalties, including but not limited to legal action and monetary damages. </p>
    <p> To obtain permission for any use, copying, modification, distribution, or reproduction of this software, please contact the copyright holder at the following address: <code>ryanshatch@gmail.com</code>
    </p>
    </p>
    <br>
    <p align="center">
      <strong>
        <code>By using this software, you acknowledge that you have read and understood the terms of this license and agree to comply with all applicable copyright laws. <br>Failure to abide by the terms of this license may subject you to legal consequences. </code>
      </strong>
    </p>
  </body>
</html><hr>
<h2 align="center" id="contact">Contact</h2>
<p align="center">For any inquiries or suggestions, please contact me at <a href="mailto:ryanshatch@gmail.com">ryanshatch@gmail.com</a>.
</body>
</html>
