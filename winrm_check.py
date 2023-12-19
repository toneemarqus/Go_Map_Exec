import subprocess
import sys
import time

def run_evil_winrm(host, username, secret, use_hash):
    # Construct the command based on whether a hash is used
    if use_hash:
        cmd_args = ["evil-winrm", "-i", host, "-u", username, "-H", secret]
    else:
        cmd_args = ["evil-winrm", "-i", host, "-u", username, "-p", secret]

    # Debug: Print the command to be executed
    print(f"Running command: {' '.join(cmd_args)}")

    # Start the process
    process = subprocess.Popen(cmd_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for a moment to establish connection
    time.sleep(5)

    # Send the 'exit' command to Evil-WinRM
    process.stdin.write(b'exit\n')
    process.stdin.flush()

    # Give it a moment to process and terminate
    time.sleep(2)

    # Terminate the process if it's still running
    if process.poll() is None:
        process.terminate()

    # Capture the output
    stdout, stderr = process.communicate()
    output = stdout.decode() + stderr.decode()

    # Debug: Print the output received
    print("Received output:")
    print(output)

    # Check if the connection was successful
    if "Exiting with code 1" in output or "SignalException" in output:
        return "Connection Failed"
    elif "Evil-WinRM shell" in output:
        return "Connection Success"
    else:
        return "Connection Status Unknown"

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python winrm_check.py <host> <username> <-password/-hash> <secret>")
        sys.exit(1)

    host = sys.argv[1]
    username = sys.argv[2]
    secret_type = sys.argv[3]
    secret = sys.argv[4]

    use_hash = secret_type.lower() == "-hash"
    result = run_evil_winrm(host, username, secret, use_hash)
    print(f"Result: {result}")
