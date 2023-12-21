# Go Map Exec
# Description
Go Map Exec is a versatile network password spraying tool designed to check various network services (RDP, SMB, SSH, WinRM) for authentication using provided credentials. Developed by Tonee Marqus, this tool is implemented in Go and is ideal for penetration testers and network administrators who require a reliable utility for authentication checks.
# ![image](https://github.com/toneemarqus/Go_Map_Exec/assets/85018947/a8c8fecc-5337-44bf-bdcc-35767678cdb2)
This screenshot is from Explotion machine from HackTheBox!
# ![image](https://github.com/toneemarqus/Go_Map_Exec/assets/85018947/b39a38fc-234c-4b30-9ff5-0c185c68041d)
# Features
- Supports multiple protocols: RDP, SMB, SSH, WinRM.
- Flexible input options for single or multiple usernames, passwords, and hosts.
- Ability to specify protocols for targeted scanning.
- Automated installation checks for necessary dependencies.
# Installation
IF you are on kali latest verion:
```
Just download the binary and run it :)
```
If you are anywhere else and having errors, clone the repo and build it yourself to match your system tool versions:
```
git clone https://github.com/toneemarqus/Go_Map_Exec
cd Go_Map_Exec/
go build go_map_exec.go
```

# Usage
```
Run the tool with the required flags. Below are some of the common flags and usage examples:
-u: Specify a single username for the scan.
-p: Specify a single password for the scan.
-d: (OPTIONAL) Specify the domain for the scan.
-uf: (OPTIONAL) Specify a file containing a list of usernames.
-pf: (OPTIONAL) Specify a file containing a list of passwords.
-H: (OPTIONAL) Specify an NTLM hash for the scan.
-pr: (OPTIONAL) Specify protocols to check (all(Default), rdp, smb, ssh, winrm).
```
# Example Commands
Scan all protocols with a Single Username and Password:
```
./go_map_exec -u username -p password 10.10.10.1
```
Scan customized Protocols:
```
./go_map_exec -pr 'ssh winrm' -u username -p password 10.10.10.1
```
Using a Username and Password File:
```
./go_map_exec -uf users.txt -pf passwords.txt 10.10.10.1
```
Scan a range of IP addresses.
```
./go_map_exec -u admin -p password123 192.168.1.100 192.168.1.101 192.168.1.102
or
./go_map_exec -u admin -p password123 192.168.1.100-3
```
Scan using an NTLM hash instead of a password.
```
./go_map_exec -u admin -H AAD3B435B51404EEAAD3B435B51404EE 192.168.1.100
```
Scan with domain credentials.
```
./go_map_exec -u admin -p password123 -d mydomain 192.168.1.100
```
# Contributing to Go Map Exec

I welcome contributions from everyone! Here are some ways you can contribute:

1. **Reporting Bugs**: If you find a bug, please use the Issues tab to report it, providing as much detail as possible.

2. **Feature Suggestions**: Have an idea to improve Go Map Exec? We'd love to hear it! Submit your suggestions through the Issues tab.

3. **Pull Requests**: Want to directly contribute to the code? Great! Please submit a pull request with a clear description of your changes and any necessary tests or documentation.
Thank you for your interest in improving Go Map Exec!

# Disclaimer
Go Map Exec is intended for legal purposes only. Users are responsible for complying with applicable laws. The developer is not liable for misuse or damage caused by this tool.
