# Explanation of Key Flowchart

### _Software Engineering and Design  - Explanation of Key Flowchart:_

* Read Config & Env. Variables
  * At startup, the application loads any config file and retrieves environment variables that might store secrets, database credentials, or user settings.
* Initialize Logging & Modular Architecture
  * The new version splits Zencrypt into multiple modules or files (for example, ui.py, cli.py, crypto\_ops.py) for better maintainability.
  * Logging is centrally configured to capture events from all modules.
* Check Interface Mode
  * Users (or a config setting) decide whether to run Zencrypt as a GUI application, as a web service with Flask/Django, or remain in CLI mode.
* Launch GUI or Web Service
  * GUI: Creates main window with Python’s Tkinter or PyQt. Buttons and menus call the same underlying crypto modules.
  * Web: Spawns a Flask or Django server, exposing REST endpoints for encryption, key management, etc.
* User Interactions
  * GUI mode: Buttons open dialogs for file encryption, text hashing, etc.
  * Web mode: Clients send requests to endpoints; server returns JSON or file responses.
* CLI Mode
  * The user is presented with your traditional command-line menu (just updated for the new modular design, logging, config usage, etc.).
* Exit/Shutdown
  * All modes converge into a final teardown sequence—closing files, saving logs, clearing secrets from memory, and gracefully exiting.
