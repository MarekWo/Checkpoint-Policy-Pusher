# -*- coding: utf-8 -*-

"""
Email Configuration Tester for Checkpoint Policy Pusher

This script reads the [Email] section from the 'app.conf' file and sends a
test email to verify that the SMTP settings are correct.

It can be run with an optional command-line argument to specify a recipient,
otherwise, it will use the first email address from the 'to_addresses' list.
"""

import configparser
import smtplib
import ssl
import sys
import keyring

CONFIG_FILE = "app.conf"

def send_test_email(config, recipient):
    """Connects to the SMTP server and sends a test email."""
    try:
        # Read SMTP settings from the config file
        smtp_server = config.get("Email", "smtp_server")
        smtp_port = config.getint("Email", "smtp_port")
        from_address = config.get("Email", "from_address")
        # Read the global SSL verification setting
        verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)

        # Check for optional SMTP authentication settings
        smtp_user = config.get("Email", "smtp_user", fallback=None)
        smtp_password_key = config.get("Email", "smtp_password_key", fallback=None)
        smtp_password = None

        if smtp_user and smtp_password_key:
            print(f"Attempting to retrieve SMTP password from Credential Manager for user '{smtp_user}' with key '{smtp_password_key}'...")
            smtp_password = keyring.get_password(smtp_password_key, smtp_user)
            if not smtp_password:
                print(f"\nERROR: Could not find password for SMTP user '{smtp_user}' using target name '{smtp_password_key}'.")
                print("Please ensure the credential is stored correctly in Windows Credential Manager.")
                return
            print("SMTP password retrieved successfully.")

        # Construct the test email message
        subject = "Test Email from Checkpoint Script Configuration"
        body = (
            "Hello,\n\n"
            "This is a test email to verify that the SMTP settings in your app.conf file are correct.\n\n"
            "If you have received this message, the configuration is working properly.\n\n"
            "Regards,\n"
            "Email Test Utility"
        )
        message = f"Subject: {subject}\n\n{body}"

        # Connect to the server and send the email
        print(f"\nConnecting to SMTP server: {smtp_server}:{smtp_port}...")
        print(f"SSL Verification: {verify_ssl}")
        context_ssl = ssl.create_default_context()
        if not verify_ssl:
            # Disable hostname checking and certificate verification
            context_ssl.check_hostname = False
            context_ssl.verify_mode = ssl.CERT_NONE
            print("WARNING: SSL certificate verification is DISABLED.")
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context_ssl)
            if smtp_user and smtp_password:
                print(f"Authenticating with user '{smtp_user}'...")
                server.login(smtp_user, smtp_password)
                print("Authentication successful.")

            print(f"Sending test email from '{from_address}' to '{recipient}'...")
            server.sendmail(from_address, [recipient], message.encode("utf-8"))

        print("\n--- Test email sent successfully! ---")

    except configparser.NoSectionError:
        print(f"\nERROR: The [Email] section was not found in '{CONFIG_FILE}'.")
    except configparser.NoOptionError as e:
        print(f"\nERROR: A required configuration option is missing in the [Email] section: {e}")
    except smtplib.SMTPAuthenticationError as e:
        print(f"\n--- An SMTP Authentication Error occurred: ---")
        print(f"Error Code: {e.smtp_code}")
        print(f"Error Message: {e.smtp_error.decode()}")
        print("Please check the smtp_user and password configuration.")
    except Exception as e:
        print(f"\n--- An unexpected error occurred: ---")
        print(e)


def main():
    """Main entry point for the test script."""
    print("--- Checkpoint Email Configuration Tester ---")

    try:
        config = configparser.ConfigParser()
        if not config.read(CONFIG_FILE):
            print(f"ERROR: Could not find or read the configuration file: '{CONFIG_FILE}'.")
            return

        print(f"Successfully read configuration from '{CONFIG_FILE}'.")

        # Determine the recipient for the test email
        if len(sys.argv) > 1:
            recipient = sys.argv[1]
            print(f"Using recipient from command line argument: {recipient}")
        else:
            try:
                # Fallback to the first address in the config file
                recipient = config.get("Email", "to_addresses").split(',')[0].strip()
                print(f"No recipient provided. Using first address from config file: {recipient}")
            except (configparser.NoOptionError, IndexError):
                print("\nERROR: 'to_addresses' is not defined in the [Email] section or is empty.")
                return

        send_test_email(config, recipient)

    except Exception as e:
        print(f"A critical error occurred: {e}")


if __name__ == "__main__":
    main()

