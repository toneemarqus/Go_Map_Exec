package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec" // Only one import for os/exec
	"strconv" // This is needed for strconv.Atoi in expandHostRange
	"strings"
	"sync"
	"time"
)

var (
	consoleMutex sync.Mutex
)

func checkSMB(username string, secret string, host string, domain string, passwordCounter string, useHash bool) bool {
	// Construct the smbmap command
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-u", username)
	cmdArgs = append(cmdArgs, "-H", host) // Host flag

	// Conditionally include the domain if it's provided
	if domain != "" {
		cmdArgs = append(cmdArgs, "-d", domain)
	}

	// Append the password or hash to the command arguments
	if useHash {
		// Prepend the empty LM hash part to the NTLM hash
		cmdArgs = append(cmdArgs, "-p", "00000000000000000000000000000000:"+secret)
	} else {
		cmdArgs = append(cmdArgs, "-p", secret) // Use password
	}

	cmd := exec.Command("smbmap", cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the smbmap command
	err := cmd.Run()
	outputStr := out.String()

	consoleMutex.Lock()
	defer consoleMutex.Unlock()

	if err != nil {
		fmt.Printf("Failed to run SMBMap command on %s with %s/%s: %s\n", host, username, secret, outputStr)
		return false
	}

	// Use the output to extract the result
	smbResult := extractSMBMapResult(outputStr)
	if strings.Contains(smbResult, "Authentication failed") || strings.Contains(outputStr, "STATUS_LOGON_FAILURE") {
		fmt.Printf("\033[31mSMB Authentication failed for user #%s with %s using %s on %s\033[0m\n", passwordCounter, username, secret, host)
		return false
	} else if strings.Contains(smbResult, "READ,WRITE") || strings.Contains(smbResult, "READ ONLY") {
		fmt.Printf("\033[34mSMB Successfully authenticated #%s with %s on %s \033[0m\n", passwordCounter, username, host)
		fmt.Println("SMBMap Result:\n" + smbResult) // Print the full smbmap result
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

func checkFTP(username, password, host string) bool {
	// Prepare the FTP command sequence
	ftpCmd := fmt.Sprintf("open %s\nuser %s %s\nbye\n", host, username, password)
	cmd := exec.Command("ftp")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Pipe the commands into the FTP client
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Printf("Failed to open stdin to ftp command: %s\n", err)
		return false
	}

	// Start the FTP client
	if err := cmd.Start(); err != nil {
		fmt.Printf("Failed to start ftp command: %s\n", err)
		return false
	}

	// Send the commands to the FTP client
	_, err = stdin.Write([]byte(ftpCmd))
	if err != nil {
		fmt.Printf("Failed to write to stdin: %s\n", err)
		return false
	}
	stdin.Close()

	// Wait for the FTP client to finish
	err = cmd.Wait()

	if err != nil {
		fmt.Printf("FTP login failed on %s with %s/%s: %s\n", host, username, password, out.String())
		return false
	}

	fmt.Printf("\033[34mSuccess FTP on %s with %s/%s\033[0m\n", host, username, password)
	return true
}

func checkSSH(username, password, host string) bool {
	// Using sshpass for simplicity; replace with appropriate SSH handling logic
	cmd := exec.Command("sshpass", "-p", password, "ssh", fmt.Sprintf("%s@%s", username, host), "exit")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()

	if err != nil {
		fmt.Printf("Failed SSH on %s with %s/%s: %s\n", host, username, password, out.String())
		return false
	}

	fmt.Printf("\033[34mSuccess SSH on %s with %s/%s\033[0m\n", host, username, password)
	return true
}

func checkWinRM(username, secret, host string, useHash bool) bool {
	// Construct the command to run the Python script
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "python", "winrm_check.py", host, username)

	// Append the password or hash to the command arguments
	if useHash {
		cmdArgs = append(cmdArgs, "-hash", secret)
	} else {
		cmdArgs = append(cmdArgs, "-password", secret)
	}

	// Execute the Python script
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		fmt.Printf("Failed WinRM on %s with %s/%s: %s\n", host, username, secret, outputStr)
		return false
	}

	// Interpret the output from the Python script
	if strings.Contains(outputStr, "Connection Success") {
		fmt.Printf("\033[34mWINRM Success: Authentication succeeded on %s with %s/%s\033[0m\n", host, username, secret)
		return true
	} else if strings.Contains(outputStr, "Connection Failed") {
		fmt.Printf("\033[31mWINRM Connection failed: Authentication failed on %s with %s/%s\033[0m\n", host, username, secret)
		return false
	}

	// Handle unknown or unexpected output
	fmt.Printf("\033[33mWINRM Connection status unknown on %s with %s/%s: %s\033[0m\n", host, username, secret, outputStr)
	return false
}

func checkRDP(username, password, host string) bool {
	cmd := exec.Command("xfreerdp", fmt.Sprintf("/u:%s", username), fmt.Sprintf("/p:%s", password), fmt.Sprintf("/v:%s", host))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()

	if err != nil {
		fmt.Printf("Failed on %s with %s/%s: %s\n", host, username, password, out.String())
		return false
	}

	fmt.Printf("Success on %s with %s/%s\n", host, username, password)
	return true
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
		// Single host, not a range
		return []string{hostRange}, nil
	} else if len(parts) == 2 {
		// It's a range
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
	fmt.Println("\n\n▄▄ •           • ▌ ▄ ·.  ▄▄▄·  ▄▄▄·    ▄▄▄ .▐▄• ▄ ▄▄▄ . ▄▄·\n\t▐█ ▀ ▪▪         ·██ ▐███▪▐█ ▀█ ▐█ ▄█    ▀▄.▀· █▌█▌▪▀▄.▀·▐█ ▌▪\n\t▄█ ▀█▄ ▄█▀▄     ▐█ ▌▐▌▐█·▄█▀▀█  ██▀·    ▐▀▀▪▄ ·██· ▐▀▀▪▄██ ▄▄\n\t▐█▄▪▐█▐█▌.▐▌    ██ ██▌▐█▌▐█ ▪▐▌▐█▪·•    ▐█▄▄▌▪▐█·█▌▐█▄▄▌▐███▌\n\t·▀▀▀▀  ▀█▄▀▪    ▀▀  █▪▀▀▀ ▀  ▀ .▀        ▀▀▀ •▀▀ ▀▀ ▀▀▀ ·▀▀▀\n\t·\n\t·By: TONEE MARQUS :)")

	var singleUsername, singlePassword string
	flag.StringVar(&singleUsername, "u", "", "Single username")
	flag.StringVar(&singlePassword, "p", "", "Single password")
	var domain string
	flag.StringVar(&domain, "d", "", "Domain")
	usernameFile := flag.String("uf", "", "Username file")
	passwordFile := flag.String("pf", "", "Password file")
	var singleHash string
	flag.StringVar(&singleHash, "H", "", "NTLM hash")

	passwordCounter := 0
	flag.Parse()

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

	if *usernameFile != "" {
		usernames, err = readLines(*usernameFile)
		if err != nil {
			fmt.Printf("Error reading username file: %v\n", err)
			return
		}
	} else {
		usernames = []string{singleUsername}
	}

	if *passwordFile != "" {
		passwords, err = readLines(*passwordFile)
		if err != nil {
			fmt.Printf("Error reading password file: %v\n", err)
			return
		}
	} else {
		passwords = []string{singlePassword}
	}

	for hostIndex, host := range allHosts {
		// Display a yellow message when starting to scan a host
		fmt.Printf("\033[33mScanning host %d/%d (%s)...\033[0m\n", hostIndex+1, len(allHosts), host)

		if isPortOpen(host, "3389", 3*time.Second) { // Check for RDP port
			for _, username := range usernames {
				for _, password := range passwords {
					checkRDP(username, password, host)
				}
			}
		} else {
			fmt.Printf("RDP port is closed on %s, skipping RDP check.\n", host)
		}

		if isPortOpen(host, "445", 3*time.Second) {
			for _, username := range usernames {
				for _, password := range passwords {
					passwordCounter++
					useHash := singleHash != "" // Determine if we're using a hash
					secret := password          // Use the iterated password
					if useHash {
						secret = singleHash // Use the hash
					}

					// Call checkSMB with the determined secret and useHash flag
					checkSMB(username, secret, host, domain, strconv.Itoa(passwordCounter), useHash)
				}
			}
		} else {
			fmt.Printf("SMB port is closed on %s, skipping SMB check.\n", host)
		}

		if isPortOpen(host, "21", 3*time.Second) {
			for _, username := range usernames {
				for _, password := range passwords {
					checkFTP(username, password, host)
				}
			}
		} else {
			fmt.Printf("FTP port is closed on %s, skipping FTP check.\n", host)
		}

		if isPortOpen(host, "22", 3*time.Second) {
			for _, username := range usernames {
				for _, password := range passwords {
					checkSSH(username, password, host)
				}
			}
		} else {
			fmt.Printf("SSH port is closed on %s, skipping SSH check.\n", host)
		}

		// Check for WinRM
		// Check for WinRM
		if isPortOpen(host, "5985", 3*time.Second) {
			for _, username := range usernames {
				for _, password := range passwords {
					useHash := singleHash != "" // Determine if we're using a hash
					secret := password          // Use the iterated password
					if useHash {
						secret = singleHash // Use the hash
					}
					checkWinRM(username, secret, host, useHash)
				}
			}
		} else {
			fmt.Printf("WinRM port is closed on %s, skipping WinRM check.\n", host)
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
