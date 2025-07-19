import requests
import json
import uuid
import winreg
import argparse
import os
from dotenv import load_dotenv
import subprocess
import psutil
import time

# --- Configuration ---
load_dotenv()
SERVER_URL = os.getenv('SERVER_URL', 'http://127.0.0.1:8080')  # Default to localhost
SESSION_FILE = 'session.json'
LAST_USER_FILE = 'last_user.json'

# --- Anti-Debug ---

class AntiDebug:
    def __init__(self):
        self.blacklisted_processes = {
            "processhacker", "netstat", "tcpview", "wireshark", "fiddler", "ollydbg",
            "x32dbg", "x64dbg", "idapro", "ghidra", "dnspy", "megadumper", "charles"
        }

    def check_processes(self):
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in self.blacklisted_processes:
                print(f"Blacklisted process found: {proc.info['name']}")
                return True
        return False

    def run_all_checks(self):
        if self.check_processes():
            return True
        # Add more checks here if needed
        return False

# --- Helper Functions ---

def get_ip_address():
    try:
        return requests.get('https://api.ipify.org').text
    except requests.RequestException:
        return "Unknown"

def get_hwid():
    """Get hardware ID using Windows Machine GUID from registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
        machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return machine_guid
    except Exception as e:
        print(f"Error getting HWID: {e}")
        return "HWID-DETECTION-FAILED"

def save_session(token):
    with open(SESSION_FILE, 'w') as f:
        json.dump({'session_token': token}, f)

def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, 'r') as f:
        try:
            data = json.load(f)
            return data.get('session_token')
        except json.JSONDecodeError:
            return None

def get_windows_version():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        return winreg.QueryValueEx(key, "ProductName")[0]
    except OSError:
        return "Unknown"

def save_last_user(user_id):
    with open(LAST_USER_FILE, 'w') as f:
        json.dump({'last_user_id': user_id}, f)

def get_last_user():
    if os.path.exists(LAST_USER_FILE):
        with open(LAST_USER_FILE, 'r') as f:
            return json.load(f).get('last_user_id')
    return None

# --- Core Logic ---

def send_2fa_request(user_id):
    ip_address = get_ip_address()
    hwid = get_hwid()
    
    payload = {
        'user_id': str(user_id),
        'ip_address': ip_address,
        'hwid': hwid
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/2fa_request", json=payload)
        
        if response.status_code == 200:
            return response.json(), ip_address, hwid
        else:
            print(f"Error from server: {response.status_code} - {response.text}")
            return None, None, None
            
    except requests.RequestException as e:
        print(f"Error connecting to the server: {e}")
        return None, None, None

def main():
    parser = argparse.ArgumentParser(description="Client for Discord Authentication System")
    parser.add_argument("--get-hwid", action="store_true", help="Get the HWID of this machine")
    args = parser.parse_args()

    if args.get_hwid:
        print(f"Your HWID is: {get_hwid()}")
        return

    # Anti-debug check
    anti_debug = AntiDebug()
    if anti_debug.run_all_checks():
        print("A security tool was detected. Please close it and try again.")
        return

    # TODO: Implement auto-updater logic here
# def check_for_updates():
#     try:
#         response = requests.get(f"{SERVER_URL}/version")
#         latest_version = response.json()['version']
#         if latest_version != CLIENT_VERSION:
#             print("New version available! Please update.")
#             # Trigger update process
#     except Exception as e:
#         print(f"Could not check for updates: {e}")

    last_user = get_last_user()
    if last_user:
        print(f"Welcome back! Using saved User ID: {last_user}")
        print("Welcome to the Discord Authentication System")

    user_id = input("Please enter your Discord User ID: ")

    session_token = load_session()
    if session_token:
        print("\nAttempting to log in with saved session...")
        try:
            # Get current IP address for blacklist checking
            ip_address = get_ip_address()
            
            response = requests.post(f"{SERVER_URL}/login_with_token", json={
                'user_id': user_id, 
                'session_token': session_token,
                'ip_address': ip_address
            }, timeout=5)
            
            if response.status_code == 200 and response.json().get('success'):
                print("Auto-login successful!")
                print(f"  IP Address: {ip_address}")
                # --- Main application logic starts here ---
                print("\n--- Protected Area ---")
                print("Application is running...")
                time.sleep(10) # Placeholder for application activity
                print("Application finished.")
                return # Exit after successful auto-login
            else:
                print(f"Auto-login failed: {response.json().get('message')}. Proceeding with manual login.")
        except requests.RequestException as e:
            print(f"Error during auto-login: {e}. Proceeding with manual login.")

    # Fallback to 2FA if auto-login fails or no token exists
    print("\nPlease proceed with 2FA verification.")

    data, ip_address, hwid = send_2fa_request(user_id)
    
    if not data or not data.get('success'):
        print(f"Authentication failed: {data.get('message', 'Unknown error') if data else 'No response'}")
        return

    print("A 2FA code has been sent to your Discord DMs.")
    user_input = input("Enter the 2FA code: ")
    if user_input == data.get('message'):
        print("\nLogin successful!")
        print(f"  IP Address: {ip_address}")
        if 'session_token' in data:
            save_session(data['session_token'])
            print("Session saved for future auto-login.")
        print("\n--- Protected Area ---")
        print("Application is running...")
        time.sleep(10)  # Placeholder for application activity
        print("Application finished.")
    else:
        print("Invalid 2FA code. Access denied.")

if __name__ == "__main__":
    main()