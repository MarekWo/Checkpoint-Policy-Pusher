# How to Use the API Connection Tester Script
This script is designed to test your connection and authentication to the Checkpoint Management API based on the settings in app.conf. It performs a simple login and logout to verify that everything is configured correctly.
## Prerequisites
- Ensure `app.conf` is in the same directory as `test_api.py`.
- The `[Checkpoint]` section in app.conf must be filled out with the correct api_url, username, and credential_manager_target.
- The password for the API user must be stored in the Windows Credential Manager.
## Running the Script
Open a command line (cmd or PowerShell), navigate to the directory containing the script, and run the following command:
```
python test_api.py
```
### Example Output on Success
```
--- Checkpoint API Connection Tester ---
Reading configuration from [Checkpoint] section...
 - API URL: [https://192.168.1.1/web_api](https://192.168.1.1/web_api)
 - Username: api_user
 - Credential Target: checkpoint_api

Attempting to retrieve password from Windows Credential Manager...
Password retrieved successfully.

Attempting to log in to [https://192.168.1.1/web_api](https://192.168.1.1/web_api)...

--- Login SUCCESSFUL! ---
Obtained Session ID: abc123def...

Attempting to log out...
--- Logout SUCCESSFUL! ---

API connection test completed successfully.
```
### Example Output on Failure 
```
(Wrong Password)--- Checkpoint API Connection Tester ---
... (previous steps) ...

Attempting to log in to [https://192.168.1.1/web_api](https://192.168.1.1/web_api)...

--- Login FAILED: Authentication Error (401) ---
The username or password provided is incorrect.
Please verify the credentials in app.conf and Windows Credential Manager.
```