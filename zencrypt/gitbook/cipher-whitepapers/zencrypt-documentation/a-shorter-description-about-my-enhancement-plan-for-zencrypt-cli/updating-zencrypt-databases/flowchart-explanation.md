# Flowchart Explanation

### Database Flowchart Explanation:

* **Load DB Config & Env. Vars**
  * Zencrypt reads database credentials (keys, username, password, host, port, etc.) from environment variables or a secure config file (for example, env, zencrypt.ini).
* **Initialize Database Connection**
  * The application attempts to connect to the chosen database system whether it is MySQL, MongoDB, PostgreSQL, etc.
  * Handles exceptions if the DB is unreachable or credentials are invalid.
* **Check/Perform User Authentication**
  * If the user is not already authenticated, Zencrypt prompts for login or signup.
  * Passwords are salted and hashed using PBKDF2 or Argon2 before checking against the stored hash in the DB.
  * On success, it either issues or validates a JWT/ JSON Web Token.
  * Retrieves user roles/ permissions from the Database (for example, “admin,” “basic\_user,” etc.).
* **Present DB-Related Actions**
  * Once authenticated, the user can select different database-related functions, such as:
    * **Store or retrieve** encryption keys from a secure table.
    * **Store or retrieve** encrypted data objects.
    * **Log usage**: Insert a record of encryption or decryption events like timestamps, user IDs, and file info.
    * **Insert access or audit records** for compliance.
    * **Check and handle key expiry** or rotation. For example, if a key is expired, deny usage or auto rotate.
* **Execute Chosen DB Operation**
  * The appropriate Zencrypt function runs. For example, store\_key(), retrieve\_key(), log\_event(), etc.
  * Zencrypt checks that the user has the correct **role/permission** for the action.
  * Success or error is returned.
* **Return Response / Results to Main App**
  * If a key was retrieved, Zencrypt can proceed to encrypt or decrypt data using that key.
  * If logs were stored, it confirms success.
  * If access is denied or an error occurs, Zencrypt handles it gracefully and logs it.
* **Continue Zencrypt Workflow or Exit**
  * The user can continue performing more database actions or return to other parts of Zencrypt (for example, navigating around the encryption manager, PGP, and all GUI/CLI menus).
  * Once finished, Zencrypt closes the database connection gracefully as part of its teardown function.
