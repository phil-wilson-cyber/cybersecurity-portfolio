# TryHackMe: Brute It - CTF Challenge

## Challenge Overview

**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Penetration Testing, Web Application Security  
**Completed:** 2024

**Challenge Description:**  
A beginner-friendly CTF focused on brute force attack techniques, hash cracking, and Linux privilege escalation. This challenge simulates common real-world scenarios where weak credentials and misconfigurations can lead to complete system compromise.

## Objectives

- Perform network reconnaissance to identify open services
- Discover hidden web directories and login portals
- Execute brute force attacks against authentication mechanisms
- Crack password hashes to gain access
- Escalate privileges to root level access

## Skills Demonstrated

- Network enumeration and service discovery
- Web directory discovery and fuzzing
- Brute force attack techniques
- Password hash identification and cracking
- Linux privilege escalation
- SSH key analysis
- Post-exploitation enumeration

## Tools Used

- **Nmap** - Network scanning and service enumeration
- **Dirbuster** - Web directory and file discovery
- **SSH** - Secure shell access and authentication
- **John the Ripper** - Password hash cracking
- **Hydra** - Brute force authentication (alternative approach)

## Methodology

### Phase 1: Reconnaissance

**Objective:** Identify open ports, running services, and potential attack vectors.

**Approach:**
- Performed comprehensive port scan to identify all open services
- Enumerated service versions to identify potential vulnerabilities
- Discovered web server running on target machine
- Identified SSH service for potential authentication attacks

**Key Findings:**
- Multiple services exposed to network
- Web application with potential login portal
- SSH service available for remote access

### Phase 2: Web Application Enumeration

**Objective:** Discover hidden directories and authentication portals.

**Approach:**
- Used Dirbuster to perform directory brute forcing against web server
- Identified hidden admin login page not linked from main site
- Analyzed login form for potential vulnerabilities
- Examined page source for information disclosure

**Key Findings:**
- Hidden administrative login portal discovered
- No rate limiting on login attempts (vulnerable to brute force)
- Username enumeration possible through error messages

### Phase 3: Brute Force Attack

**Objective:** Gain access to administrative panel through credential brute forcing.

**Approach:**
- Identified valid username through reconnaissance
- Used common password wordlists for brute force attack
- Leveraged Hydra/Burp Suite for automated authentication attempts
- Successfully obtained valid credentials

**Key Learning:**
- Understanding how brute force attacks work in practice
- Importance of rate limiting and account lockout policies
- How attackers enumerate valid usernames before targeting passwords
- Real-world effectiveness of common password lists

### Phase 4: Hash Cracking

**Objective:** Crack password hashes to escalate access.

**Approach:**
- Located password hashes stored on compromised system
- Identified hash type through format analysis
- Used John the Ripper with wordlist to crack hashes
- Successfully recovered plaintext passwords

**Key Learning:**
- How to identify different hash formats (MD5, SHA, bcrypt, etc.)
- Understanding hash cracking methodology and wordlist attacks
- Importance of strong password hashing algorithms (bcrypt vs MD5)
- Why proper salting is critical for password security

### Phase 5: SSH Access & Privilege Escalation

**Objective:** Gain shell access and escalate to root privileges.

**Approach:**
- Used cracked credentials to establish SSH connection
- Performed post-exploitation enumeration (sudo privileges, SUID binaries, cron jobs)
- Identified privilege escalation vector
- Successfully escalated to root access

**Key Learning:**
- Standard Linux post-exploitation enumeration techniques
- Common privilege escalation vectors (sudo misconfigurations, SUID abuse)
- Importance of principle of least privilege
- How attackers move from initial access to full system compromise

## Real-World Applications

This challenge demonstrates techniques commonly seen in real penetration tests and security incidents:

**Brute Force Attacks:**
- Still effective against systems without proper controls
- Automated tools make these attacks trivial to execute
- Highlights importance of MFA and rate limiting

**Weak Password Hashing:**
- Many legacy systems still use outdated hashing algorithms
- Demonstrates why password security policies matter
- Shows the gap between compliance and actual security

**Privilege Escalation:**
- Initial access rarely provides full system control
- Attackers systematically search for escalation paths
- Common misconfigurations are frequently exploitable

**Detection Opportunities:**
- Multiple failed login attempts (brute force indicators)
- Unusual SSH connections from new IPs
- Privilege escalation attempts in system logs
- Abnormal user behavior post-compromise

## Key Takeaways

1. **Defense in Depth:** Multiple weak security controls compounded to allow full compromise
2. **Password Security:** Strong passwords + proper hashing + MFA are all necessary
3. **Monitoring Matters:** Each attack phase generated detectable indicators
4. **Privilege Management:** Proper sudo configuration prevents easy escalation
5. **Attacker Mindset:** Understanding how attacks chain together helps with defense

## Defensive Recommendations

Based on this challenge, organizations should implement:

- **Account lockout policies** after failed login attempts
- **Rate limiting** on authentication endpoints
- **Multi-factor authentication** for administrative access
- **Strong password hashing** (bcrypt, Argon2) instead of MD5/SHA1
- **Principle of least privilege** for user sudo permissions
- **Security monitoring** for brute force patterns and privilege escalation attempts
- **Regular security audits** of exposed services and configurations

## Skills for SOC Analysts

This challenge helped develop skills directly applicable to SOC operations:

- **Attack Recognition:** Understanding how brute force attacks appear in logs
- **IOC Identification:** Recognizing patterns of credential stuffing and password spraying
- **Incident Investigation:** Tracing attacker activity from initial access to privilege escalation
- **Alert Tuning:** Knowing what thresholds trigger meaningful brute force alerts

---

**CTF Completed:** Successfully obtained both user and root flags through systematic enumeration, exploitation, and privilege escalation.

*This writeup demonstrates practical penetration testing methodology and understanding of common attack vectors relevant to security operations and incident response.*
