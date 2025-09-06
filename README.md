# Checkpoint Policy Pusher

## Overview

This script provides a safe and reliable way to automate the final step of the Checkpoint policy deployment process: **installing an already configured and saved policy package onto its designated gateways.**

The primary goal is to eliminate the need for manual, after-hours work by scheduling policy installations for specific times (e.g., on a Friday evening or during a weekend maintenance window).

**Important Safety Information:** This script **DOES NOT** create, modify, or delete any firewall rules, objects, or security policies. Its sole function is to invoke the "Install Policy" command via the official Checkpoint Management API. It is the programmatic equivalent of a firewall administrator manually clicking the "Install Policy" button in the SmartConsole for changes that have already been made and saved by the security team. The script operates on a read-only basis concerning the policy's content, simply triggering its activation.

## How It Works

The script is designed to be run by the Windows Task Scheduler at regular intervals (e.g., every 5 minutes). On each run, it performs the following steps:
- **Read Configuration:** It parses the `app.conf` file to load the API details, email settings, and the list of all defined policy jobs.
- **Check Schedule:** It checks the current day and time against the schedule defined for each active policy.
- **Execute Task:** If a policy's scheduled time matches the current time (within a small tolerance window), the script proceeds.
- **Authenticate:** It securely retrieves the API user's password from the Windows Credential Manager and logs into the Checkpoint Management API to obtain a session ID. It will only log in if there is a scheduled task to perform.
- **Install Policy:** It sends the `install-policy` command to the API for the specified policy package. It can either install the policy on explicitly defined targets or let the policy package's own settings determine the targets.
- **Send Notification:** It sends a detailed email notification indicating the success or failure of the operation.
- **Logout:** It properly logs out of the API session.

## Features

- **Flexible Scheduling:** Define multiple installation times for each policy on specific days of the week.
- **Per-Policy Configuration:** Manage multiple, independent policy installation jobs from a single configuration file.
- **Enable/Disable Jobs:** Easily enable or disable policy jobs without removing their configuration.
- **Explicit & Implicit Targeting:** Choose to specify installation targets in the config for extra safety, or let the policy package's settings control the installation (the default, safer method).
- **Secure Credential Management:** Passwords are not stored in the script or configuration files. The script integrates with the native Windows Credential Manager.
- **Email Notifications:** Get immediate feedback on the status of each installation attempt.
- **Detailed Logging:** All actions are logged to a local file (`checkpoint_pusher.log`) for easy troubleshooting.

## Prerequisites

Python 3.6+

The following Python packages: `requests`, `keyring`

You can install the required packages using pip:

```plaintext
pip install requests keyring
```

## Configuration (`app.conf`)

The script's behavior is controlled entirely by the `app.conf` file.

### `[Checkpoint]` Section

- `api_url`: The full URL to your Checkpoint Management Server's web API. (e.g., `https://<your-mgmt-server>/web_api`)
- `username`: The username for the API account.
- `credential_manager_target`: The "Target name" used to store the password in Windows Credential Manager. This is an arbitrary label, but it must be consistent.

### `[Email]` Section

- `smtp_server`: Your organization's SMTP server address.
- `smtp_port`: The port for the SMTP server (usually 587 for STARTTLS).
- `from_address`: The email address from which notifications will be sent.
- `to_addresses`: A comma-separated list of recipient email addresses.

### `[EmailTemplates]` Section

This section allows you to customize the content of the notification emails using placeholders.

### `[Policy:*]` Sections

You can define multiple policy jobs. Each must have a unique section name that starts with `Policy:` followed by the exact name of the policy package in Checkpoint.

- `status`: Set to `true` to enable the job or `false` to disable it.
- `schedules`: A comma-separated list of schedules in `Day:HHMM` format (e.g., `Monday:0800, Friday:1730`).
- `target_name` (Optional): A comma-separated list of gateways or clusters to install this policy on. If this line is commented out or removed, the script will install the policy on all targets defined within the policy package in SmartConsole.

## Setup and Usage

**Step 1: Configure** `**app.conf**` Fill in the `app.conf` file with your environment's specific details (API URL, usernames, policy names, schedules, etc.).

**Step 2: Store Password in Windows Credential Manager** Store the password for the API user in the Windows Credential Manager. You can do this from the command line. **Ensure the** `**targetname**` **matches the** `**credential_manager_target**` **value in** `**app.conf**`.

Open `cmd` and run the following command, replacing the values with your own:

```plaintext
cmdkey /add:checkpoint_api /user:api_user /pass
```

The system will then prompt you to enter the password securely.

**Step 3: Set up Windows Scheduled Task**

- Open **Task Scheduler**.
- Click **Create Task...** in the "Actions" pane.

**General Tab:**

- Give the task a name (e.g., "Checkpoint Policy Pusher").
- Select "Run whether user is logged on or not".

**Triggers Tab:**

- Click **New...**.
- Set the trigger to run the task at a desired frequency. For this script, running **every 5 minutes** is a good starting point.
- Ensure the trigger is **Enabled**.
- 
**Actions Tab:**

- Click **New...**.
- **Action:** "Start a program".
- **Program/script:** Provide the full path to your Python executable (e.g., `C:\Python39\python.exe`).
- **Add arguments (optional):** Provide the full path to your script (e.g., `C:\Scripts\checkpoint_pusher.py`).
- **Start in (optional):** Provide the directory where your script and `app.conf` are located (e.g., `C:\Scripts\`). This is important so the script can find its files.
- Click **OK** to save the task. You will be prompted for the password of the user account the task will run as.