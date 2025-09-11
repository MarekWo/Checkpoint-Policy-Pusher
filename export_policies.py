# -*- coding: utf-8 -*-

"""
Checkpoint Policy Exporter

This script connects to the Checkpoint Management API to fetch all policy
packages and their installation targets. The output is formatted to be
easily copied into the 'app.conf' file for the Checkpoint Policy Pusher.
"""

import argparse
import configparser
import keyring
import requests
from urllib3.exceptions import InsecureRequestWarning

def get_policy_list(config):
    """
    Connects to the Checkpoint API, fetches all policy packages,
    and formats them for the app.conf file.
    """
    session_id = None
    try:
        # 1. Read configuration from the [Checkpoint] section
        print("--- Checkpoint Policy Exporter ---")
        print("\nReading configuration from [Checkpoint] section...")
        cp_url = config.get("Checkpoint", "api_url")
        username = config.get("Checkpoint", "username")
        credential_target = config.get("Checkpoint", "credential_manager_target")
        verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)

        # 2. Retrieve the password from Windows Credential Manager
        print("Attempting to retrieve password from Windows Credential Manager...")
        password = keyring.get_password(credential_target, username)
        if not password:
            print("\n--- ERROR: Password not found! ---")
            print(f"Could not find a password for user '{username}' with target '{credential_target}'.")
            return
        print("Password retrieved successfully.")

        # 3. Log in to the Checkpoint API
        print(f"Attempting to log in to {cp_url}...")
        if not verify_ssl:
            print("WARNING: SSL certificate verification is DISABLED.")
        
        login_headers = {'Content-Type': 'application/json'}
        login_payload = {'user': username, 'password': password}
        response = requests.post(f"{cp_url}/login", headers=login_headers, json=login_payload, verify=verify_ssl)

        if response.status_code != 200:
            print(f"\n--- Login FAILED with Status Code: {response.status_code} ---")
            print(response.text)
            return

        session_id = response.json().get('sid')
        print("Login successful.")

        # 4. Fetch all policy packages
        print("\nFetching all policy packages...")
        api_headers = {'Content-Type': 'application/json', 'X-chkp-sid': session_id}
        packages_payload = {"details-level": "full"}
        packages_response = requests.post(f"{cp_url}/show-packages", headers=api_headers, json=packages_payload, verify=verify_ssl)
        
        if packages_response.status_code != 200:
            print(f"--- FAILED to fetch policy packages: {packages_response.status_code} ---")
            print(packages_response.text)
            return
        
        packages = packages_response.json().get('packages', [])
        print(f"Found {len(packages)} policy packages. Generating config entries...\n")
        
        # 5. Generate and print the configuration for each policy
        print("# --- Copy the policy definitions below and paste into your app.conf ---")
        for pkg in packages:
            try:
                policy_name = pkg.get('name')
                targets = pkg.get('installation-targets', [])
                
                target_names = []
                # ### CHANGE ###: Handle both strings and dictionaries in the targets list
                for t in targets:
                    if isinstance(t, dict):
                        target_names.append(t.get('name'))
                    elif isinstance(t, str):
                        target_names.append(t)
                
                target_string = ", ".join(filter(None, target_names))
                
                print(f"\n[Policy:{policy_name}]")
                print("status = false")
                print("schedules = Monday:0100")
                if target_string:
                    print(f"# Targets automatically discovered: {target_string}")
                    print(f"target_name = {target_string}")
                else:
                    print("# No specific installation targets found for this policy.")
                    print("# The policy will be installed on targets defined within the package itself.")
                    print("# target_name =")
            except Exception as e:
                policy_name = pkg.get('name', 'Unknown')
                print(f"\n--- ERROR processing policy '{policy_name}': {e} ---")


    except Exception as e:
        print(f"\n--- An unexpected error occurred: ---")
        print(e)
    finally:
        # 6. Log out
        if session_id:
            print("\nAttempting to log out...")
            requests.post(f"{cp_url}/logout", headers={'Content-Type': 'application/json', 'X-chkp-sid': session_id}, json={}, verify=verify_ssl)
            print("Logout successful.")
            print("\n--- Script finished ---")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Checkpoint Policy Exporter script.")
    parser.add_argument(
        "--config",
        default="app.conf",
        help="Path to the configuration file (default: app.conf)"
    )
    args = parser.parse_args()
    
    config_file = args.config
    print(f"--- Using configuration file: {config_file} ---")

    try:
        config = configparser.ConfigParser()
        if not config.read(config_file, encoding='utf-8'):
            print(f"ERROR: Configuration file '{config_file}' is empty or could not be read.")
            return
        
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        get_policy_list(config)

    except Exception as e:
        print(f"A critical error occurred: {e}")

if __name__ == "__main__":
    main()