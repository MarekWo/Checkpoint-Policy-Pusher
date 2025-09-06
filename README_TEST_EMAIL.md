# How to Use the Email Tester Script

This script helps you verify that your email settings in app.conf are correct without running the main application.
Prerequisites

- Ensure app.conf is in the same directory as test_email.py.
- Your SMTP settings must be correctly configured in the [Email] section of app.conf.

## Running the Script

You can run the script in two ways from your command line (like cmd or PowerShell):

### 1. Send a test email to the default recipient:

This will send an email to the first address listed in the to_addresses field in your app.conf.

```
python test_email.py
```

### 2. Send a test email to a specific recipient:

This is useful for testing without notifying the entire distribution list. Provide the email address as an argument after the script name.

```
python test_email.py your-test-address@yourcompany.com
```
## Example Output on Success

```
--- Checkpoint Email Configuration Tester ---
Successfully read configuration from 'app.conf'.
No recipient provided. Using first address from config file: admin1@yourcompany.com

Connecting to SMTP server: smtp.yourcompany.com:587...
Sending test email from 'checkpoint-automation@yourcompany.com' to 'admin1@yourcompany.com'...

--- Test email sent successfully! ---
```