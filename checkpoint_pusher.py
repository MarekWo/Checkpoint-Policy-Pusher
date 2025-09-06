# -*- coding: utf-8 -*-

"""
Checkpoint Policy Pusher

This script automates the process of installing Checkpoint policies based on a schedule
defined in an external configuration file (app.conf). It reads the configuration,
checks if any policies are scheduled to be installed at the current time, and
uses the Checkpoint Management API to perform the installation.

The script is designed to be run as a scheduled task (e.g., every 5 minutes).

version 1.0.0
"""

import configparser
import logging
import smtplib
import ssl
from datetime import datetime
import keyring
import requests

# --- Constants ---
# Time window in minutes to check for scheduled tasks.
# E.g., if set to 2, a task at 08:00 will run if the script executes between 07:58 and 08:02.
SCHEDULE_TOLERANCE_MINUTES = 2
LOG_FILE = "checkpoint_pusher.log"
CONFIG_FILE = "app.conf"

# --- Main Functions ---

def setup_logging():
    """Configures the logging format and destination."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

def send_notification(config, subject_template, body_template, context):
    """Sends an email notification."""
    try:
        smtp_server = config.get("Email", "smtp_server")
        smtp_port = config.getint("Email", "smtp_port")
        from_address = config.get("Email", "from_address")
        to_addresses = config.get("Email", "to_addresses").split(',')

        subject = subject_template.format(**context)
        body = body_template.format(**context)

        message = f"Subject: {subject}\n\n{body}"

        context_ssl = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context_ssl)
            # server.login(smtp_user, smtp_password) # Add if authentication is needed
            server.sendmail(from_address, to_addresses, message.encode("utf-8"))
        logging.info("Successfully sent notification email.")

    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")


def install_policy(cp_url, session_id, policy_name, targets=None):
    """
    Calls the Checkpoint API to install a policy.
    If targets are provided, they are included in the payload.
    Otherwise, the API uses the installation targets defined in the policy package.
    """
    headers = {
        'Content-Type': 'application/json',
        'X-chkp-sid': session_id
    }
    
    payload = {
        "policy-package": policy_name
    }

    if targets:
        target_list = [t.strip() for t in targets.split(',')]
        # Checkpoint API expects a single string for one target, or a list for multiple
        api_targets = target_list[0] if len(target_list) == 1 else target_list
        payload["targets"] = api_targets
        logging.info(f"Sending install-policy request for policy '{policy_name}' on explicit target(s): {targets}")
    else:
        logging.info(f"Sending install-policy request for policy '{policy_name}'. Targets will be determined by the policy package settings.")

    # In a production environment, you should use a valid certificate, not verify=False
    response = requests.post(f"{cp_url}/install-policy", headers=headers, json=payload, verify=False)
    
    if response.status_code == 200:
        logging.info(f"API call successful for policy '{policy_name}'. Task started.")
        return True, response.json()
    else:
        logging.error(f"API call failed for policy '{policy_name}'. Status: {response.status_code}, Response: {response.text}")
        return False, response.json()


def login_to_checkpoint(cp_url, username, password):
    """Logs into the Checkpoint API and returns a session ID."""
    headers = {'Content-Type': 'application/json'}
    payload = {'user': username, 'password': password}
    
    logging.info("Attempting to log into Checkpoint API.")
    
    try:
        response = requests.post(f"{cp_url}/login", headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            session_id = response.json().get('sid')
            logging.info("Login successful. Session ID obtained.")
            return session_id
        else:
            logging.error(f"Login failed. Status: {response.status_code}, Response: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while connecting to the Checkpoint API: {e}")
        return None


def process_policies(config):
    """
    Main logic to process policies from the configuration file.
    """
    now = datetime.now()
    current_day = now.strftime('%A')
    current_time = now.strftime('%H%M')

    logging.info(f"Starting policy check for {current_day} at {current_time}.")

    try:
        cp_user = config.get("Checkpoint", "username")
        cp_credential_target = config.get("Checkpoint", "credential_manager_target")
        cp_password = keyring.get_password(cp_credential_target, cp_user)
        if not cp_password:
            logging.error(f"Could not find password for user '{cp_user}' in Credential Manager with target '{cp_credential_target}'.")
            return
        cp_url = config.get("Checkpoint", "api_url")
    except configparser.NoOptionError as e:
        logging.error(f"Configuration error in [Checkpoint] section: {e}")
        return

    session_id = None

    for section in config.sections():
        if section.startswith("Policy:"):
            try:
                policy_name = section.split(":", 1)[1]
                is_active = config.getboolean(section, "status")
                schedules = config.get(section, "schedules").split(',')
                # Read target_name for this specific policy; it's optional (fallback=None).
                policy_targets = config.get(section, "target_name", fallback=None)

                if not is_active:
                    logging.info(f"Policy '{policy_name}' is disabled. Skipping.")
                    continue

                for schedule in schedules:
                    day, time = schedule.strip().split(':')
                    time_diff = abs(int(current_time) - int(time))
                    
                    if day.strip() == current_day and time_diff <= SCHEDULE_TOLERANCE_MINUTES:
                        logging.info(f"Scheduled policy '{policy_name}' found for execution.")
                        
                        if not session_id:
                            session_id = login_to_checkpoint(cp_url, cp_user, cp_password)
                            if not session_id:
                                logging.error("Cannot proceed without a valid session.")
                                email_context = {
                                    'policy_name': "N/A - Login Failed",
                                    'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                                    'error_message': "Could not log into Checkpoint API.",
                                    'target_name': "N/A"
                                }
                                send_notification(config, config.get("EmailTemplates", "failure_subject"), config.get("EmailTemplates", "failure_body"), email_context)
                                return

                        success, result = install_policy(cp_url, session_id, policy_name, policy_targets)
                        
                        email_context = {
                            'policy_name': policy_name,
                            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                            'message': result,
                            'error_message': result if not success else "N/A",
                            'target_name': policy_targets or "Defined in Policy Package"
                        }

                        if success:
                            send_notification(config, config.get("EmailTemplates", "success_subject"), config.get("EmailTemplates", "success_body"), email_context)
                        else:
                            send_notification(config, config.get("EmailTemplates", "failure_subject"), config.get("EmailTemplates", "failure_body"), email_context)
                        break
            
            except (configparser.NoOptionError, ValueError) as e:
                logging.error(f"Configuration error in section '{section}': {e}. Skipping.")
                continue

    if session_id:
        try:
            requests.post(f"{cp_url}/logout", headers={'Content-Type': 'application/json', 'X-chkp-sid': session_id}, json={}, verify=False)
            logging.info("Session logged out successfully.")
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred during logout: {e}")


def main():
    """Main entry point of the script."""
    setup_logging()
    logging.info("--- Script execution started ---")
    try:
        config = configparser.ConfigParser()
        # Use utf-8 encoding to handle special characters if any
        config.read(CONFIG_FILE, encoding='utf-8')
        process_policies(config)
    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}", exc_info=True)
    logging.info("--- Script execution finished ---")


if __name__ == "__main__":
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    main()

