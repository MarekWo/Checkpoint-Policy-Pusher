# How to Use the Email Tester Script

This script helps you verify that your email settings in the configuration file are correct without running the main application.

## Prerequisites

- Your SMTP settings must be correctly configured in the `[Email]` section of your configuration file.

## Running the Script

You can run the script in several ways from your command line (like `cmd` or PowerShell):

### 1. Use the default config and first recipient
This will use `app.conf` and send an email to the first address listed in the `to_addresses` field.
```
python test_email.py

```

### 2. Specify a recipient
This uses the default `app.conf` but sends the email to a specific address.
```

python test_email.py your-test-address@yourcompany.com

```

### 3. Specify a configuration file
This uses your specified config file and sends an email to the first recipient listed in it.
```

python test_email.py --config "path/to/other.conf"

```

### 4. Specify both a config file and a recipient
This gives you full control over the test.
```

python test_email.py --config "path/to/other.conf" your-test-address@yourcompany.com

```

## Example Output on Success

```

--- Checkpoint Email Configuration Tester ---
Using configuration file: 'app.conf'

Successfully read configuration from 'app.conf'.
No recipient provided. Using first address from config file: admin1@yourcompany.com

Connecting to SMTP server: smtp.yourcompany.com:587...
Sending test email from 'checkpoint-automation@yourcompany.com' to 'admin1@yourcompany.com'...

--- Test email sent successfully! ---

```
