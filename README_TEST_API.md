# How to Use the API Connection Tester Script
This script is designed to test your connection and authentication to the Checkpoint Management API based on the settings in a configuration file. It performs a simple login and logout to verify that everything is configured correctly.

## Prerequisites
- The `[Checkpoint]` section in your configuration file must be filled out with the correct `api_url`, `username`, and `credential_manager_target`.
- The password for the API user must be stored in the Windows Credential Manager.

## Running the Script
Open a command line (like `cmd` or PowerShell), navigate to the directory containing the script, and run one of the following commands:

### 1. Using the default `app.conf` file:
```

python test_api.py

```

### 2. Specifying a different configuration file:
Use the `--config` flag to point to your file.
```

python test_api.py --config "path/to/your/config.conf"

```

### Example Output on Success
```

--- Checkpoint API Connection Tester ---
Using configuration file: 'app.conf'

Reading configuration from [Checkpoint] section...

  - API URL: [https://192.168.1.1/web_api](https://192.168.1.1/web_api)
  - Username: api_user
  - Credential Target: checkpoint_api
    ...
    --- Login SUCCESSFUL! ---
    Obtained Session ID: abc123def...

Attempting to log out...
--- Logout SUCCESSFUL! ---

API connection test completed successfully.

```

### Example Output on Failure
```

(Wrong Password)
--- Checkpoint API Connection Tester ---
...
--- Login FAILED: Authentication Error (401) ---
The username or password provided is incorrect.
Please verify the credentials in your config file and Windows Credential Manager.
```
