# TryHackMe: h4cked - Forensics & Exploitation Challenge

## Challenge Overview

**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Digital Forensics, Network Security, Penetration Testing  
**Completed:** 2024

**Challenge Description:**  
A unique two-phase challenge that combines blue team forensics with red team exploitation. First, analyze packet capture files to determine how a system was compromised. Then, use the same techniques to hack back into the machine. This challenge bridges defensive analysis with offensive security skills.

## Objectives

**Phase 1 - Blue Team (Forensics):**
- Analyze network traffic capture (PCAP) files
- Identify attacker's IP address and techniques used
- Determine what services were compromised
- Discover what malicious tools were installed
- Reconstruct the attack timeline

**Phase 2 - Red Team (Exploitation):**
- Use discovered credentials and techniques to gain access
- Exploit the same vulnerabilities identified in forensics phase
- Establish persistence on the compromised system
- Retrieve flags proving successful compromise

## Skills Demonstrated

- Network traffic analysis and PCAP forensics
- Protocol analysis (FTP, HTTP, SSH)
- Credential extraction from network captures
- Brute force attack execution
- Web shell deployment and usage
- Reverse shell establishment
- Post-exploitation techniques
- Incident reconstruction and timeline analysis

## Tools Used

- **Wireshark** - Network protocol analyzer and PCAP examination
- **Hydra** - Password brute forcing tool
- **FTP Client** - File Transfer Protocol access
- **SSH Client** - Secure shell remote access
- **Web Shell** - Remote command execution via web interface
- **Netcat** - Network listener for reverse shells

## Phase 1: Forensic Analysis (Blue Team)

### Objective: Determine How the Attack Occurred

**Initial Analysis:**
- Loaded PCAP file into Wireshark for examination
- Filtered traffic by protocol to identify suspicious activity
- Analyzed connection patterns and data transfers
- Identified attacker source IP and target services

### Attack Reconstruction

**Step 1: FTP Brute Force Attack**
- **Discovery:** Analyzed FTP traffic showing multiple authentication attempts
- **Finding:** Identified successful brute force attack against FTP service
- **Evidence:** Captured plaintext FTP credentials in packet capture
- **Takeaway:** FTP transmits credentials in cleartext, making them visible in network captures

**Step 2: Malicious File Upload**
- **Discovery:** Examined FTP data streams following successful authentication
- **Finding:** Attacker uploaded a web shell (PHP backdoor) to the web server directory
- **Evidence:** Captured file transfer containing malicious PHP code
- **Takeaway:** Compromised FTP often leads to web server compromise if directories overlap

**Step 3: Web Shell Access**
- **Discovery:** Analyzed HTTP traffic to the uploaded web shell
- **Finding:** Attacker executed system commands through the backdoor
- **Evidence:** HTTP POST requests with command parameters and responses
- **Takeaway:** Web shells provide persistent access and command execution capabilities

**Step 4: Privilege Escalation & Persistence**
- **Discovery:** Examined commands executed through web shell
- **Finding:** Attacker attempted privilege escalation and established additional backdoors
- **Evidence:** Commands for user enumeration, service manipulation, and persistence mechanisms
- **Takeaway:** Initial access is just the beginning - attackers establish multiple access methods

### Forensic Findings Summary

**Attack Timeline:**
1. Network reconnaissance (implied, not captured)
2. FTP brute force attack - successful credential compromise
3. Web shell upload via compromised FTP
4. Command execution through web shell
5. Enumeration and privilege escalation attempts
6. Establishment of persistent access mechanisms

**Indicators of Compromise (IOCs):**
- Multiple failed FTP authentication attempts followed by success
- File upload to web directory immediately after FTP compromise
- Suspicious HTTP POST requests to recently uploaded PHP file
- System commands being executed from web application context
- Unusual process creation and network connections

**Key Learning:**
This is exactly what a SOC analyst would investigate during an incident response. The PCAP file contained the complete attack chain, demonstrating why network monitoring and packet capture are critical for forensic investigations.

## Phase 2: Exploitation (Red Team)

### Objective: Replicate the Attack

Using the information gathered from forensic analysis, I replicated the attacker's techniques:

**Step 1: FTP Brute Force**
- Used credentials discovered in PCAP analysis
- Alternatively, could use Hydra to brute force if credentials weren't visible
- Successfully authenticated to FTP service
- Confirmed write access to web directory

**Step 2: Web Shell Deployment**
- Uploaded PHP web shell to web-accessible directory
- Verified web shell accessibility via browser
- Confirmed command execution capability

**Step 3: Remote Access**
- Executed commands through web shell interface
- Established reverse shell connection for interactive access
- Set up netcat listener to catch reverse connection
- Gained interactive shell on target system

**Step 4: Post-Exploitation**
- Enumerated system for sensitive information
- Located user and root flags
- Documented access methods for persistence

## Real-World Applications

### For Security Operations (Blue Team)

**Incident Response:**
- PCAP analysis is critical for understanding attack vectors
- Network traffic often contains evidence not available in endpoint logs
- Protocol analysis reveals credential theft and lateral movement
- Timeline reconstruction helps scope incidents

**Detection Opportunities:**
- Multiple failed authentication attempts (brute force indicator)
- Successful login after many failures (compromised credentials)
- Unusual file uploads to web directories
- HTTP requests to recently created PHP files
- Outbound connections from web server processes

**SIEM Alert Scenarios:**
- FTP brute force: >10 failed auth in 5 minutes
- Web shell indicator: New .php file created in web directory
- Suspicious web activity: POST requests to uncommon PHP files
- Reverse shell: Outbound connection from web server to uncommon port

### For Penetration Testing (Red Team)

**Attack Chain Validation:**
- Demonstrates how initial access (FTP) leads to deeper compromise
- Shows importance of testing credential reuse
- Highlights value of maintaining multiple access methods
- Proves why defense-in-depth matters

## Key Takeaways

### Blue Team Perspective
1. **Network visibility is essential** - Without packet captures, this entire attack chain would be harder to reconstruct
2. **Protocol matters** - Cleartext protocols (FTP, HTTP) expose sensitive data in transit
3. **Log correlation** - Network traffic + web server logs + system logs = complete picture
4. **Detection requires context** - Individual events seem benign; the pattern reveals the attack

### Red Team Perspective
1. **Credential access = kingdom** - FTP credentials provided foothold for deeper compromise
2. **Defense layers compound** - Each missing control made next step easier
3. **Persistence matters** - Single access point isn't enough; attackers establish multiple backdoors
4. **Cleartext protocols = easy wins** - Modern systems should use encrypted alternatives (SFTP, HTTPS)

### Purple Team Integration
This challenge perfectly demonstrates why red and blue teams need shared understanding:
- Red team techniques inform blue team detection strategies
- Blue team analysis reveals what attackers actually did (not just what they could do)
- Both perspectives are necessary for comprehensive security

## Defensive Recommendations

Based on this attack simulation:

**Network Security:**
- Replace FTP with SFTP/FTPS (encrypted file transfer)
- Implement network segmentation to limit lateral movement
- Deploy IDS/IPS to detect brute force and exploitation attempts
- Enable full packet capture for forensic analysis

**Access Controls:**
- Enforce strong password policies to resist brute force
- Implement account lockout after failed authentication
- Use multi-factor authentication for remote access
- Apply principle of least privilege for service accounts

**Web Application Security:**
- Separate web content directory from FTP upload directory
- Implement web application firewall (WAF) rules
- Monitor for file uploads to web directories
- Restrict execution permissions on upload directories

**Monitoring & Detection:**
- Alert on FTP brute force patterns
- Monitor for new PHP/executable files in web directories
- Detect unusual outbound connections from web servers
- Correlate authentication events with file modifications

## Skills for SOC Analysts

This challenge developed skills directly applicable to security operations:

**Forensic Analysis:**
- PCAP examination and protocol analysis
- Attack timeline reconstruction
- Evidence extraction from network traffic
- IOC identification and documentation

**Threat Understanding:**
- Recognition of common attack patterns
- Understanding attacker methodology
- Knowledge of post-exploitation techniques
- Familiarity with common exploitation tools

**Incident Response:**
- Determining initial compromise vector
- Identifying scope of compromise
- Documenting attacker actions
- Creating actionable remediation recommendations

---

**Challenge Completed:** Successfully analyzed the initial compromise through forensic investigation, then replicated the attack to demonstrate understanding of both offensive and defensive perspectives.

*This challenge demonstrates the critical connection between blue team forensics and red team exploitation - both skill sets are necessary for comprehensive cybersecurity operations.*
