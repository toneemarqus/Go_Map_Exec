import os
import sys

def check_winrm(host, username, password):
    try:
        # Construct the Evil WinRM command
        command = f"evil-winrm -i {host} -u {username} -p {password}"
        
        # Execute the command using os.system
        os.system(command)
        
    except Exception as e:
        # Handle any errors that occur
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python winrm_check.py <host> <username> <password>")
        sys.exit(1)

    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    check_winrm(host, username, password)
