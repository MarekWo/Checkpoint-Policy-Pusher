# -*- coding: utf-8 -*-

"""
Checkpoint Policy Pusher

This script automates the process of installing Checkpoint policies based on a schedule
defined in an external configuration file (app.conf). It reads the configuration,
checks if any policies are scheduled to be installed at the current time, and
uses the Checkpoint Management API to perform the installation and monitor its status.
"""

import configparser
import logging
import smtplib
import ssl
import time
from datetime import datetime
import keyring
import requests
from urllib3.exceptions import InsecureRequestWarning

# --- Constants ---
SCHEDULE_TOLERANCE_MINUTES = 2
POLLING_INTERVAL_SECONDS = 10
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
        verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)

        subject = subject_template.format(**context)
        body = body_template.format(**context)

        message = f"Subject: {subject}\n\n{body}"

        context_ssl = ssl.create_default_context()
        if not verify_ssl:
            context_ssl.check_hostname = False
            context_ssl.verify_mode = ssl.CERT_NONE
            logging.warning("Email SSL certificate verification is DISABLED.")

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=context_ssl)
            server.sendmail(from_address, to_addresses, message.encode("utf-8"))
        logging.info("Successfully sent notification email.")

    except (configparser.NoOptionError, ValueError) as e:
        logging.error(f"Configuration error in [Email] section: {e}")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")


### CHANGE ###: New function to format the verbose task details into a readable summary.
def format_task_details(task_info):
    """Formats the detailed task JSON into a human-readable string."""
    if not isinstance(task_info, dict):
        return str(task_info) # Return as-is if not a dictionary

    summary_lines = []

    # Main summary comment
    summary_comment = task_info.get('comments')
    if summary_comment:
        summary_lines.append(f"Summary: {summary_comment}")

    # Start and end times
    start_time = task_info.get('start-time', {}).get('iso-8601', 'N/A')
    end_time = task_info.get('last-update-time', {}).get('iso-8601', 'N/A')
    summary_lines.append(f"Started: {start_time}, Finished: {end_time}")

    # Per-target status details
    task_details = task_info.get('task-details')
    if isinstance(task_details, list) and task_details:
        summary_lines.append("\nPer-Target Status:")
        processed_gateways = set()
        for detail in task_details:
            gateway_name = detail.get('gatewayName')
            status_desc = detail.get('statusDescription')
            if gateway_name and gateway_name not in processed_gateways:
                summary_lines.append(f"- {gateway_name}: {status_desc}")
                processed_gateways.add(gateway_name)

    return "\n".join(summary_lines)


def monitor_task(cp_url, session_id, task_id, timeout_seconds, verify_ssl=True):
    """Polls the 'show-task' API endpoint until the task is complete or times out."""
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        headers = {
            'Content-Type': 'application/json',
            'X-chkp-sid': session_id
        }
        payload = {'task-id': task_id, 'details-level': 'full'}
        
        try:
            response = requests.post(f"{cp_url}/show-task", headers=headers, json=payload, verify=verify_ssl)
            response.raise_for_status()
            
            task_info = response.json().get('tasks', [{}])[0]
            status = task_info.get('status')
            
            logging.info(f"Task '{task_id}' status: {status}")

            if status not in ['in progress', 'queued']:
                return status, task_info
            
            time.sleep(POLLING_INTERVAL_SECONDS)

        except requests.exceptions.RequestException as e:
            logging.error(f"Error while polling task status for task '{task_id}': {e}")
            return "api_error", {"message": str(e)}

    logging.warning(f"Task '{task_id}' timed out after {timeout_seconds} seconds.")
    return "timed_out", {"message": f"Task did not complete within the {timeout_seconds / 60:.0f}-minute timeout."}


def install_policy(cp_url, session_id, policy_name, targets, timeout_seconds, verify_ssl=True):
    """Calls the Checkpoint API to install a policy and monitors the task."""
    headers = {
        'Content-Type': 'application/json',
        'X-chkp-sid': session_id
    }
    
    payload = {"policy-package": policy_name}
    if targets:
        target_list = [t.strip() for t in targets.split(',')]
        api_targets = target_list[0] if len(target_list) == 1 else target_list
        payload["targets"] = api_targets
    
    if not verify_ssl:
        logging.warning("API SSL certificate verification is DISABLED.")

    try:
        response = requests.post(f"{cp_url}/install-policy", headers=headers, json=payload, verify=verify_ssl)
        
        if response.status_code != 200:
            logging.error(f"Failed to initiate policy install for '{policy_name}'. Status: {response.status_code}, Response: {response.text}")
            return "failed_to_start", response.json()
        
        task_id = response.json().get('task-id')
        if not task_id:
            logging.error(f"API call for '{policy_name}' succeeded but did not return a task-id.")
            return "no_task_id", response.json()

        logging.info(f"Policy install for '{policy_name}' initiated. Task ID: {task_id}. Monitoring status...")
        return monitor_task(cp_url, session_id, task_id, timeout_seconds, verify_ssl)

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while calling install-policy API: {e}")
        return "api_error", {"message": str(e)}


def login_to_checkpoint(cp_url, username, password, verify_ssl=True):
    """Logs into the Checkpoint API and returns a session ID."""
    headers = {'Content-Type': 'application/json'}
    payload = {'user': username, 'password': password}
    
    logging.info("Attempting to log into Checkpoint API.")
    
    if not verify_ssl:
        logging.warning("API SSL certificate verification is DISABLED.")

    try:
        response = requests.post(f"{cp_url}/login", headers=headers, json=payload, verify=verify_ssl)
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
    """Main logic to process policies from the configuration file."""
    now = datetime.now()
    current_day = now.strftime('%A')
    current_time = now.strftime('%H%M')

    logging.info(f"Starting policy check for {current_day} at {current_time}.")

    try:
        global_verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)
        cp_user = config.get("Checkpoint", "username")
        cp_credential_target = config.get("Checkpoint", "credential_manager_target")
        cp_password = keyring.get_password(cp_credential_target, cp_user)
        if not cp_password:
            logging.error(f"Could not find password for user '{cp_user}' in Windows Credential Manager.")
            return
        cp_url = config.get("Checkpoint", "api_url")
        task_timeout_minutes = config.getint("Checkpoint", "task_timeout_minutes", fallback=2)
        task_timeout_seconds = task_timeout_minutes * 60
    except (configparser.NoOptionError, ValueError) as e:
        logging.error(f"Configuration error: {e}")
        return

    session_id = None

    for section in config.sections():
        if section.startswith("Policy:"):
            try:
                policy_name = section.split(":", 1)[1]
                is_active = config.getboolean(section, "status")
                schedules = config.get(section, "schedules").split(',')
                policy_targets = config.get(section, "target_name", fallback=None)

                if not is_active:
                    logging.info(f"Policy '{policy_name}' is disabled. Skipping.")
                    continue

                for schedule in schedules:
                    day, time_str = schedule.strip().split(':')
                    
                    time_diff = abs(int(current_time) - int(time_str))
                    
                    if day.strip() == current_day and time_diff <= SCHEDULE_TOLERANCE_MINUTES:
                        logging.info(f"Scheduled policy '{policy_name}' found for execution.")
                        
                        if not session_id:
                            session_id = login_to_checkpoint(cp_url, cp_user, cp_password, global_verify_ssl)
                            if not session_id:
                                logging.error("Cannot proceed without a valid session.")
                                email_context = {
                                    'policy_name': policy_name,
                                    'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                                    'error_message': "Could not log into Checkpoint API.",
                                    'target_name': policy_targets or "Defined in Policy",
                                    'message': "N/A"
                                }
                                send_notification(config, config.get("EmailTemplates", "failure_subject"), config.get("EmailTemplates", "failure_body"), email_context)
                                return

                        final_status, result_details = install_policy(cp_url, session_id, policy_name, policy_targets, task_timeout_seconds, global_verify_ssl)
                        
                        # ### CHANGE ###: Use the new formatting function for email content.
                        formatted_details = format_task_details(result_details)

                        email_context = {
                            'policy_name': policy_name,
                            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
                            'message': f"Final status: {final_status}\n\n{formatted_details}",
                            'error_message': formatted_details if final_status != 'succeeded' else "N/A",
                            'target_name': policy_targets or "Defined in Policy"
                        }

                        if final_status == 'succeeded':
                            logging.info(f"Policy '{policy_name}' installed successfully.")
                            send_notification(config, config.get("EmailTemplates", "success_subject"), config.get("EmailTemplates", "success_body"), email_context)
                        else:
                            logging.error(f"Policy '{policy_name}' installation failed with status: {final_status}.")
                            send_notification(config, config.get("EmailTemplates", "failure_subject"), config.get("EmailTemplates", "failure_body"), email_context)
                        break
            
            except (configparser.NoOptionError, ValueError) as e:
                logging.error(f"Configuration error in section '{section}': {e}. Skipping.")
                continue

    if session_id:
        try:
            cp_url = config.get("Checkpoint", "api_url")
            global_verify_ssl = config.getboolean("General", "ssl_verify", fallback=True)
            requests.post(f"{cp_url}/logout", headers={'Content-Type': 'application/json', 'X-chkp-sid': session_id}, json={}, verify=global_verify_ssl)
            logging.info("Session logged out successfully.")
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred during logout: {e}")


def main():
    """Main entry point of the script."""
    setup_logging()
    logging.info("--- Script execution started ---")
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE, encoding='utf-8')
        if not config.sections():
            logging.error(f"Configuration file '{CONFIG_FILE}' is empty or could not be read.")
            return
        process_policies(config)
    except Exception as e:
        logging.critical(f"An unhandled exception occurred: {e}", exc_info=True)
    logging.info("--- Script execution finished ---")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    main()