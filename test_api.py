# -*- coding: utf-8 -*-

"""
Checkpoint API Connection Tester

This script reads the [Checkpoint] section from the 'app.conf' file to test
the API connectivity and credentials. It attempts to log in, and if successful,
immediately logs out.

This is a quick way to diagnose issues with API URLs, credentials, or network
connectivity without running the main policy pusher script.
"""

import configparser
import keyring
import requests
from urllib3.exceptions import InsecureRequestWarning

CONFIG_FILE = "app.conf"

def test_api_connection(config):
    """Performs the login/logout test against the Checkpoint API."""
    session_id = None
    try:
        # 1. Read configuration from the [Checkpoint] section
        print("Reading configuration from [Checkpoint] section...")
        cp_url = config.get("Checkpoint", "api_url")
        username = config.get("Checkpoint", "username")
        credential_target = config.get("Checkpoint", "credential_manager_target")
        
        # Read the global SSL verification setting
        verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)
        
        print(f" - API URL: {cp_url}")
        print(f" - Username: {username}")
        print(f" - Credential Target: {credential_target}")
        print(f" - SSL Verification: {verify_ssl}")

        # 2. Retrieve the password from Windows Credential Manager
        print("\nAttempting to retrieve password from Windows Credential Manager...")
        password = keyring.get_password(credential_target, username)
        if not password:
            print("\n--- ERROR: Password not found! ---")
            print(f"Could not find a password for user '{username}' with target name '{credential_target}'.")
            print("Please ensure you have stored the credential correctly using cmdkey or the Control Panel.")
            return

        print("Password retrieved successfully.")

        # 3. Attempt to log in to the Checkpoint API
        print(f"\nAttempting to log in to {cp_url}...")
        if not verify_ssl:
            print("WARNING: SSL certificate verification is DISABLED.")
        headers = {'Content-Type': 'application/json'}
        payload = {'user': username, 'password': password}
        
        # Disable SSL verification for lab environments. 
        # In production, use verify='/path/to/ca.pem'
        response = requests.post(f"{cp_url}/login", headers=headers, json=payload, verify=verify_ssl)

        # 4. Analyze the login response
        if response.status_code == 200:
            session_id = response.json().get('sid')
            print("\n--- Login SUCCESSFUL! ---")
            print(f"Obtained Session ID: {session_id[:8]}...") # Show only first 8 chars
        elif response.status_code == 401:
            print("\n--- Login FAILED: Authentication Error (401) ---")
            print("The username or password provided is incorrect.")
            print("Please verify the credentials in app.conf and Windows Credential Manager.")
        else:
            print(f"\n--- Login FAILED with Status Code: {response.status_code} ---")
            print("Response Body:")
            print(response.text)

    except configparser.NoOptionError as e:
        print(f"\nERROR: A required configuration option is missing in the [Checkpoint] section: {e}")
    except requests.exceptions.RequestException as e:
        print("\n--- ERROR: A network-related error occurred. ---")
        print("This could be due to a wrong API URL, a firewall blocking the connection, or the server being down.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"\n--- An unexpected error occurred: ---")
        print(e)

    finally:
        # 5. Log out if a session was successfully created
        if session_id:
            try:
                print("\nAttempting to log out...")
                verify_ssl = config.getboolean("Checkpoint", "ssl_verify", fallback=True)
                logout_response = requests.post(f"{cp_url}/logout", headers={'Content-Type': 'application/json', 'X-chkp-sid': session_id}, json={}, verify=verify_ssl)
                if logout_response.status_code == 200:
                    print("--- Logout SUCCESSFUL! ---")
                    print("\nAPI connection test completed successfully.")
                else:
                    print(f"Warning: Logout failed with status code {logout_response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"An error occurred during logout: {e}")


def main():
    """Main entry point for the API test script."""
    print("--- Checkpoint API Connection Tester ---")

    try:
        config = configparser.ConfigParser()
        if not config.read(CONFIG_FILE):
            print(f"ERROR: Could not find or read the configuration file: '{CONFIG_FILE}'.")
            return
        
        # Suppress only the single warning from urllib3 about insecure requests
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        test_api_connection(config)

    except Exception as e:
        print(f"A critical error occurred: {e}")


if __name__ == "__main__":
    main()

