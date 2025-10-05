# Academic Cybersecurity Projects

## Overview

Professional security projects completed during **Cybersecurity Analyst Diploma Program** (2-year program). These projects demonstrate foundational knowledge in digital forensics, incident response, penetration testing, vulnerability assessment, and security operations.

All projects were completed to professional standards with comprehensive documentation including technical reports, presentations, and hands-on lab work.

---

## Professional Penetration Testing Engagement: "Relevant" Machine

### Project Overview

**Type:** Full-Scope Penetration Test (Group Project)  
**Client:** Simulated engagement for "EvilCorp"  
**Team:** 4-person security team (Cyber Genuis INC)  
**Team Members:** Josh Veinotte, John Mulumba, Philip Wilson, Mathura Mangaleswarren  
**Completed:** December 2022  
**Methodology:** NIST Cybersecurity Framework  
**Model:** Black Box Testing  
**Deliverable:** Professional penetration testing report

[**📄 View Full Penetration Testing Report (PDF)**](./EthicalHackingGroupProject_Finished.pdf)

**Objective:**  
Conduct comprehensive penetration test with minimal prior knowledge to identify vulnerabilities, exploit systems, and document findings in professional client-deliverable format.

### Executive Summary

Successfully identified and exploited multiple critical vulnerabilities leading to complete system compromise:

**Attack Chain:**
1. Network reconnaissance revealing exposed SMB share and web server
2. Unauthenticated SMB access (null session vulnerability)
3. Credential exposure through unsecured password file
4. Web server exploitation via reverse shell deployment
5. Privilege escalation using SeImpersonatePrivilege
6. Full administrative access achieved (SYSTEM level)

**Critical Findings:**
- **Null session enabled** on SMB share (no authentication required)
- **Credentials stored in plaintext** on publicly accessible share
- **SeImpersonatePrivilege enabled** on Windows IIS Server
- **No network segmentation** between services

**Impact:** Complete system compromise with administrative control

### Technical Methodology

#### Phase 1: Reconnaissance & Enumeration

**Port Scanning:**
- Tool: Threader3000 + Nmap
- Discovered 8 open ports: 135, 80, 139, 445, 3389, 49663, 49666, 49668
- Identified Windows system with SMB and IIS web server
- Enumerated NetBIOS information and computer name

**Service Enumeration:**
- SMB share "nt4wrksv" discovered without authentication
- Web server confirmed on port 49663
- Directory enumeration using GoBuster revealed accessible paths

**Key Finding:** SMB share accessible without credentials (null session attack)

#### Phase 2: Vulnerability Analysis

**Critical Vulnerabilities Identified:**

1. **Null Session on SMB (CVE-level severity)**
   - No authentication required to access SMB share
   - Read and write permissions available to anonymous users
   - Allows arbitrary file upload/download

2. **Credential Exposure**
   - passwords.txt file stored in publicly accessible SMB share
   - Base64-encoded credentials (weak obfuscation)
   - Multiple user accounts exposed

3. **SeImpersonatePrivilege Enabled**
   - Windows privilege escalation vector
   - Exploitable via PrintSpoofer and similar tools
   - Leads directly to SYSTEM-level access

4. **Lack of Network Segmentation**
   - Web server and file share on same network segment
   - No isolation between services
   - Single point of failure

#### Phase 3: Exploitation

**Step 1: Initial Access**
- Tool: smbclient
- Method: Null session authentication
- Result: Read/write access to nt4wrksv share
- Evidence: Successfully retrieved passwords.txt

**Step 2: Credential Recovery**
- Method: Base64 decoding of password hashes
- Users discovered: Bob, Administrator
- Passwords: Plaintext recovery successful

**Step 3: Web Shell Deployment**
- Tool: msfvenom
- Payload: windows/x64/shell_reverse_tcp
- Format: .aspx (IIS web server compatible)
- Delivery: Uploaded via SMB share, accessed via web server
- Result: Reverse shell established

**Step 4: Privilege Escalation**
- Tool: PrintSpoofer.exe
- Vulnerability: SeImpersonatePrivilege enabled
- Method: Token impersonation exploit
- Result: Elevated to NT AUTHORITY\SYSTEM

**Step 5: Post-Exploitation**
- Access achieved: Full system administrative control
- Flags captured: User flag (Bob's directory) + Administrator flag
- Persistence: Multiple backdoors available for continued access

### Tools & Techniques Used

**Reconnaissance:**
- Threader3000 - Port discovery
- Nmap - Service enumeration and OS fingerprinting
- GoBuster - Directory/file enumeration
- smbclient - SMB share enumeration

**Exploitation:**
- msfvenom - Reverse shell payload generation
- Netcat - Reverse shell listener
- PrintSpoofer - Privilege escalation
- Base64 decoding - Credential recovery

**Frameworks:**
- NIST Cybersecurity Framework
- Kill Chain methodology
- MITRE ATT&CK mapping

### Forensics & Detection Perspective

**As a forensic investigator, this engagement taught:**

**Attack Indicators (IOCs):**
- Unusual SMB connections without authentication
- Anonymous SMB access patterns
- New .aspx file creation in web directories
- Reverse shell network connections (unusual outbound traffic)
- Privilege escalation attempts in Windows Event Logs
- Execution of PrintSpoofer.exe or similar tools

**Evidence Locations:**
- SMB server logs (connection attempts, file transfers)
- IIS web server logs (suspicious .aspx requests)
- Windows Security Event Logs (Event ID 4672 - privilege escalation)
- Network traffic (reverse shell connections)
- File system artifacts (uploaded malicious files)
- Process creation logs (Sysmon Event ID 1)

**Timeline Reconstruction:**

For incident response, this attack would appear as:
1. Multiple SMB connection attempts
2. File download from SMB share (passwords.txt)
3. File upload to SMB share (rev.aspx)
4. HTTP request to newly created .aspx file
5. Outbound network connection established
6. Privilege escalation event (SeImpersonatePrivilege used)
7. Access to sensitive directories

### Professional Deliverable

**Report Components Created:**
- Executive Summary for non-technical stakeholders
- Technical findings with evidence screenshots
- Attack narrative documenting methodology
- Risk assessment and severity ratings
- Remediation recommendations with prioritization
- Compliance framework alignment (NIST, PCI DSS, PIPEDA, Bill-26 CCSPA, ITSG-33)

**Professional Standards:**
- Client-ready formatting and presentation
- Clear communication of technical concepts
- Actionable remediation steps
- Business impact analysis
- Compliance considerations

### Key Recommendations Provided

**Immediate Actions (Critical):**
1. Disable null session on SMB share - require authentication
2. Remove password files from file shares
3. Disable SeImpersonatePrivilege unless required
4. Audit and remove uploaded malicious files

**Short-term Remediations:**
1. Implement network segmentation (separate web server and file share)
2. Use dedicated ports for different services
3. Enable SMB signing to prevent MITM attacks
4. Implement least privilege access controls

**Long-term Security Improvements:**
1. Regular vulnerability assessments
2. Penetration testing on recurring schedule
3. Security awareness training
4. Implement IDS/IPS for anomaly detection
5. Enhanced logging and SIEM deployment

### Skills Demonstrated

**Technical Skills:**
- Network reconnaissance and enumeration
- SMB protocol exploitation
- Web server attack vectors
- Reverse shell deployment and handling
- Windows privilege escalation
- Post-exploitation techniques

**Professional Skills:**
- Collaborative penetration testing
- Client communication and reporting
- Risk assessment and prioritization
- Compliance framework knowledge (NIST, PCI DSS, PIPEDA)
- Professional documentation standards
- Translating technical findings for executive audience

**Forensics-Relevant Skills:**
- Understanding attacker TTPs (critical for forensic investigation)
- Evidence location knowledge (where attackers leave traces)
- Attack timeline reconstruction methodology
- IOC identification from attacker perspective
- Log analysis for detection opportunities

### Real-World Application

**This project simulates actual penetration testing engagements conducted by:**
- External security consultants
- Red teams in large organizations
- Compliance-required security assessments
- Third-party risk assessments

**For digital forensics, understanding offensive techniques helps with:**
- Incident investigation (knowing what to look for)
- Evidence collection (understanding artifact locations)
- Attack attribution (recognizing tools and techniques)
- Detection rule development (identifying indicators)

### Why This Matters for Forensics Career

Forensic investigators need to understand offensive security because:

1. **Know Your Adversary:** Can't investigate what you don't understand
2. **Evidence Recognition:** Knowing attack tools helps identify their artifacts
3. **Timeline Accuracy:** Understanding attack sequences improves reconstruction
4. **Detection Development:** Offensive knowledge informs defensive strategies
5. **Expert Testimony:** May need to explain attack methods in legal proceedings

**Purple Team Perspective:**  
This project bridges red team (offensive) and blue team (defensive) skills - both essential for comprehensive forensic investigation and incident response.

---

## Digital Forensics Investigation: Rhino NIST Hunt

### Project Overview

**Type:** Digital Forensics Investigation  
**Framework:** NIST Incident Response Methodology  
**Tools:** SIFT Workstation, Foremost (file carving)  
**Format:** Lab Exercise + Technical Documentation

[**📄 View Full Forensics Investigation Documentation (PDF)**](./NIST%20Rhino%20Hunt%20-%20Digital%20Forensics.pdf)

**Objective:**  
Conduct a comprehensive digital forensics investigation following NIST guidelines to recover hidden files from a USB drive image and determine what happened to evidence.

**Scenario:**  
Investigate a USB drive image (RHINOUSB.dd) to recover deleted files and determine the fate of a hard drive involved in an incident.

### Investigation Methodology

#### Phase 1: Environment Setup

**Forensic Workstation:**
- Deployed SIFT Workstation (SANS Investigative Forensic Toolkit)
- Industry-standard Linux distribution for digital forensics
- Pre-loaded with forensic analysis tools

**Evidence Handling:**
- Mounted USB image as read-only (loop device)
- Maintained evidence integrity (no writes to original)
- Created separate output directory for recovered artifacts

#### Phase 2: File Recovery & Analysis

**Tool Used: Foremost**
- File carving tool for recovering deleted files
- Extracted files based on headers/footers (signature-based recovery)
- Targeted file types: JPG, GIF, PDF, OLE (Office documents)

**Command Executed:**
```
sudo foremost -v -t jpg,gif,pdf,ole -i /dev/loop0 -o /home/sansforensics/Desktop/Rhino\ Output**
```

## Incident Response Procedures

### Project Overview

**Type:** Incident Response Planning & Execution  
**Framework:** Industry best practices for IR  
**Format:** Documentation + Tabletop Exercise

**Objective:**  
Develop comprehensive incident response procedures and practice execution through simulated security incidents.

### Components Developed

**IR Documentation:**
- Incident response playbooks for common scenarios
- Escalation procedures and contact lists
- Evidence collection checklists
- Communication templates
- Post-incident review processes

**Scenarios Practiced:**
- Malware outbreak response
- Data breach investigation
- Ransomware incident handling
- Insider threat detection
- DDoS attack mitigation

### Skills Demonstrated

- Incident classification and severity assessment
- Rapid triage and initial response
- Evidence preservation during active incidents
- Stakeholder communication during crises
- Post-incident analysis and lessons learned

### Key Takeaways

Understanding that incident response requires:
- Pre-planned procedures (can't figure it out during crisis)
- Clear roles and responsibilities
- Balance between speed and evidence preservation
- Communication with both technical and executive stakeholders
- Continuous improvement through post-incident reviews

---

## MITRE ATT&CK Framework Application

### Project Overview

**Type:** Threat Analysis & Detection Development  
**Framework:** MITRE ATT&CK  
**Format:** Analysis + Detection Rules

**Objective:**  
Apply MITRE ATT&CK framework to understand adversary tactics and techniques, then develop detection strategies.

### Project Components

**Threat Analysis:**
- Mapping real-world attack campaigns to ATT&CK techniques
- Understanding adversary TTPs (Tactics, Techniques, Procedures)
- Identifying detection opportunities for each technique
- Prioritizing defenses based on threat landscape

**Detection Development:**
- Creating detection rules for specific ATT&CK techniques
- Identifying log sources needed for detection
- Developing investigation playbooks per technique
- Testing detection effectiveness

### Skills Demonstrated

- Understanding adversary behavior and methodology
- Translating threat intelligence into actionable defenses
- Detection engineering fundamentals
- Use of industry-standard threat framework
- Defensive strategy development

### Real-World Application

MITRE ATT&CK is the industry standard for:
- Threat intelligence analysis
- SOC detection rule development
- Red team/blue team exercises
- Security control gap analysis
- Incident investigation and attribution

---

## Vulnerability Assessment Projects

### Project Overview

**Type:** Technical Security Assessment  
**Tools:** Vulnerability scanners, manual testing  
**Format:** Technical Report + Remediation Plan

**Objective:**  
Conduct vulnerability assessments of systems and networks, analyze findings, and provide remediation recommendations.

### Assessment Activities

**Technical Scanning:**
- Network vulnerability scanning
- Web application security testing
- Configuration review and hardening
- Patch management assessment
- Security control verification

**Risk Analysis:**
- Vulnerability severity classification
- Business impact assessment
- Exploitability evaluation
- Risk prioritization

**Remediation Planning:**
- Specific remediation steps for each finding
- Prioritization based on risk
- Compensating controls where patching not possible
- Validation and re-testing procedures

### Skills Demonstrated

- Vulnerability assessment methodology
- Risk analysis and prioritization
- Technical report writing
- Remediation planning
- Understanding of common vulnerabilities and misconfigurations

---

## Hands-On Vulnerability Remediation: Nessus Security Assessment

### Project Overview

**Type:** Vulnerability Assessment & Remediation  
**Tool:** Tenable Nessus Professional  
**Target:** Metasploitable2 VM (intentionally vulnerable system)  
**Format:** Technical Lab + Documentation

[**📄 View Full Vulnerability Assessment Documentation (PDF)**](./Nessus_Vulnerability_Assessment.pdf)

**Objective:**  
Use industry-standard vulnerability scanner to identify security weaknesses, analyze findings across severity levels, and implement technical remediations to secure the system.

**Scenario:**  
Conduct comprehensive vulnerability scan, select three vulnerabilities of different severity levels (Critical, Medium, Low), implement fixes, and validate remediation through re-scanning.

### Assessment Methodology

#### Phase 1: Initial Vulnerability Scan

**Scanning Configuration:**
- Tool: Tenable Nessus Vulnerability Scanner
- Target: Metasploitable2 Linux system
- Scan type: Comprehensive security audit
- Network: Internal lab environment

**Initial Findings:**
- Multiple vulnerabilities identified across severity spectrum
- Critical, High, Medium, and Low severity issues detected
- Network services, configurations, and cryptographic weaknesses found

#### Phase 2: Vulnerability Analysis & Prioritization

**Selected Vulnerabilities for Remediation:**

**1. Critical: NFS Exported Share Information Disclosure**
- **Severity:** Critical (CVSS High)
- **Risk:** Remote attackers can mount NFS shares without authentication
- **Impact:** Unauthorized file access, potential data exfiltration or malware deployment
- **Attack Vector:** Network-accessible file shares with no access controls

**2. Medium: Telnet Service Enabled (Cleartext Protocol)**
- **Severity:** Medium
- **Risk:** Unencrypted remote access exposes credentials
- **Impact:** Credential theft via network sniffing, man-in-the-middle attacks
- **Attack Vector:** Plaintext transmission on port 23

**3. Low: Weak SSH MAC Algorithms Enabled**
- **Severity:** Low
- **Risk:** Cryptographic weakness allows potential hash collision attacks
- **Impact:** Message integrity compromise, potential authentication bypass
- **Attack Vector:** Cryptographic attacks against weak MAC algorithms (MD5-based)

### Technical Remediation

#### Remediation 1: NFS Share Access Control (Critical)

**Problem Identified:**
- NFS shares accessible without authentication
- Anonymous mounting possible from any network location
- Read/write access available to unauthorized users

**Solution Implemented:**

**Step 1: Mount Configuration**
- Mounted Metasploitable2 /home directory to /tmp/safemnt
- Validated proper mount points and permissions

**Step 2: Access Control Lists**
- Modified `/etc/hosts.deny`: Added `portmap: ALL` to block all external access
- Modified `/etc/hosts.allow`: Added `portmap: 192.168.35.0/255.255.255.0` to whitelist trusted subnet only
- Implemented network-based access control (principle of least privilege)

**Security Impact:**
- Eliminated anonymous NFS access
- Restricted access to trusted network segment only
- Prevented unauthorized file system mounting

**Validation:**
- Re-scanned with Nessus
- Critical vulnerability no longer detected
- Access controls verified functional

#### Remediation 2: Telnet Service Mitigation (Medium)

**Problem Identified:**
- Telnet server listening on port 23
- Cleartext protocol transmits credentials unencrypted
- Modern SSH alternative not enforced

**Solution Implemented:**

**Firewall Configuration:**
```
sudo ufw enable              # Enable firewall (was disabled)
```
```
sudo ufw deny 23             # Block Telnet port
```
```
sudo ufw status              # Verify rule active
```

**Approach Rationale:**
- Firewall-based blocking chosen due to missing Telnet config files
- More secure than service-level disable (defense in depth)
- Immediate mitigation without service reconfiguration

**Alternative Consideration:**
- Preferred solution: Disable Telnet service entirely and mandate SSH
- Implemented solution: Network-level blocking as practical alternative

**Security Impact:**
- Telnet port no longer accessible
- Forced migration to SSH (encrypted alternative)
- Reduced attack surface

**Validation:**
- Port scan confirmed port 23 blocked
- Nessus re-scan verified vulnerability remediated

#### Remediation 3: SSH Cryptographic Hardening (Low)

**Problem Identified:**
- Weak Message Authentication Code (MAC) algorithms enabled
- MD5-based MACs vulnerable to collision attacks
- Cryptographic downgrade attacks possible

**Solution Implemented:**

SSH Configuration Hardening - Modified SSH config file with new MAC configuration: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,
hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com, hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com

**Cryptographic Improvements:**
- Removed MD5-based MAC algorithms
- Implemented SHA-2 family (SHA-256, SHA-512)
- Added Encrypt-Then-MAC (ETM) variants for additional security
- Maintained compatibility with modern SSH clients

**System Changes:**
- Restarted SSH service to apply configuration
- Rebooted system to ensure persistent changes

**Security Impact:**
- Eliminated weak cryptographic algorithms
- Strengthened message integrity protection
- Aligned with current security best practices

**Validation:**
- SSH service restart confirmed
- Nessus re-scan verified weak algorithms no longer advertised
- Cryptographic compliance achieved

### Validation & Results

**Post-Remediation Scan:**

Re-scan using same Nessus profile to validate remediation effectiveness.

**Results:**
- Critical vulnerability: RESOLVED ✅
- Medium vulnerability: RESOLVED ✅
- Low vulnerability: RESOLVED ✅
- Overall security posture significantly improved
- Remaining vulnerabilities documented for future remediation cycles

**Before vs After:**
- Initial scan: Multiple critical and medium issues
- Post-remediation: Selected vulnerabilities successfully mitigated
- Measurable security improvement demonstrated

### Skills Demonstrated

**Vulnerability Assessment:**
- Nessus scanner deployment and configuration
- Vulnerability severity analysis (CVSS understanding)
- Risk prioritization across multiple findings
- Scan result interpretation

**Technical Remediation:**
- Linux system administration (firewall, services, configuration files)
- Access control implementation (hosts.allow/deny)
- Network security configuration (NFS, firewall rules)
- Cryptographic hardening (SSH configuration)
- Service management and validation

**Security Principles:**
- Defense in depth (multiple control layers)
- Principle of least privilege (restrictive access controls)
- Secure defaults (strong cryptography)
- Validation and verification (re-scanning)

**Professional Practices:**
- Systematic remediation approach
- Documentation of changes
- Before/after validation
- Risk-based prioritization

### Forensics & Incident Response Relevance

**Why This Matters for Forensics:**

**Vulnerability Understanding:**
- Forensic investigators often determine how systems were compromised
- Understanding vulnerabilities helps identify likely attack vectors
- Exploitation artifacts differ by vulnerability type

**Evidence Recognition:**
- NFS exploitation leaves network logs, mount records
- Telnet attacks show cleartext credentials in packet captures
- Weak SSH crypto may indicate downgrade attacks in logs

**Incident Reconstruction:**
- Knowing common vulnerabilities helps build attack timelines
- Understanding remediation shows what "secure" vs "vulnerable" looks like
- Helps identify whether attacker used known vulnerabilities

**System Baseline Knowledge:**
- Forensic analysts need to know secure configurations
- Identifying misconfigurations is key to root cause analysis
- Understanding remediation informs recommendations

### Real-World Application

**This project simulates:**
- Corporate vulnerability management programs
- Compliance-driven security assessments
- Penetration test remediation
- Continuous security improvement cycles

**Applicable to:**
- Security Operations Center (vulnerability tracking)
- Incident Response (identifying attack vectors post-breach)
- Digital Forensics (understanding how systems were exploited)
- Compliance audits (PCI DSS, NIST, ISO 27001)

### Tools & Technologies

- **Tenable Nessus** - Industry-standard vulnerability scanner
- **Metasploitable2** - Intentionally vulnerable training system
- **Linux CLI** - System administration and configuration
- **UFW (Uncomplicated Firewall)** - Linux firewall management
- **SSH/NFS** - Network services configuration
- **Access Control Lists** - Host-based security controls

### Key Takeaways

1. **Vulnerability Scanning is Foundational:** Regular scanning identifies security gaps before attackers do
2. **Severity Matters:** Prioritizing critical issues provides maximum risk reduction
3. **Defense in Depth:** Multiple control layers (firewall + service config) provide better security
4. **Validation is Essential:** Re-scanning confirms remediation effectiveness
5. **Documentation Matters:** Clear technical documentation enables knowledge transfer and compliance

### Recommendations Based on Experience

**For Vulnerability Management:**
- Establish regular scanning cadence (weekly/monthly)
- Prioritize remediation by severity and exploitability
- Validate all remediations through re-scanning
- Document configuration changes for audit trail

**For System Hardening:**
- Disable unnecessary services (Telnet, legacy protocols)
- Implement strong cryptography (modern algorithms only)
- Use access controls restrictively (whitelist approach)
- Apply principle of least privilege universally

---

**Full technical documentation with screenshots and detailed remediation steps available in portfolio.**

*This project demonstrates practical vulnerability assessment, risk analysis, technical remediation, and validation skills - essential for security operations, incident response, and forensic investigation roles.*

---

## Network Security Configuration Projects

### Sophos & FortiNet Firewall Configuration

**Project Type:** Network Security Implementation  
**Platforms:** Sophos XG Firewall, FortiGate Enterprise

**Activities:**
- Firewall rule development and optimization
- Network segmentation design
- VPN configuration for secure remote access
- Intrusion prevention system (IPS) configuration
- Security policy implementation
- Log analysis and security monitoring

**Skills Gained:**
- Enterprise firewall management
- Network security architecture
- Security policy enforcement
- Log analysis for security events
- Understanding of network-based attacks and defenses

### CCNA Network Configuration

**Project Type:** Network Infrastructure & Security  
**Focus:** Cisco networking with security emphasis

**Activities:**
- Secure network design and implementation
- VLAN segmentation for security
- Access control lists (ACLs) for traffic filtering
- Network monitoring and troubleshooting
- Understanding of network protocols and security implications

**Forensics Relevance:**
- Network packet analysis fundamentals
- Understanding protocol behavior (normal vs malicious)
- Network log interpretation
- Infrastructure knowledge critical for network forensics

---

## Key Skills Across All Projects

### Technical Skills
- Digital forensics investigation methodology
- Incident response procedures
- Penetration testing and exploitation
- Log analysis and correlation
- Network and system security
- Vulnerability assessment
- Threat analysis using MITRE ATT&CK

### Professional Skills
- Technical report writing
- Executive communication
- Evidence documentation
- Project documentation
- Teamwork and collaboration
- Time management under pressure

### Foundational Knowledge
- Security frameworks (NIST, MITRE ATT&CK)
- Compliance requirements (PCI DSS, PIPEDA, ITSG-33)
- Incident response lifecycle
- Digital evidence handling
- Risk assessment and prioritization
- Security control implementation
- Network and system architecture

---

## Academic Foundation for Digital Forensics Career

These projects provided strong foundation for digital forensics work:

1. **Forensic Methodology:** Hands-on practice with NIST-based investigation procedures
2. **Evidence Handling:** Understanding of proper evidence collection and documentation
3. **Incident Response:** Knowledge of IR procedures critical for forensic investigations
4. **Attack Understanding:** Offensive security knowledge helps identify evidence during investigations
5. **Technical Writing:** Professional documentation skills essential for forensic reports
6. **Framework Knowledge:** MITRE ATT&CK and NIST frameworks used daily in forensics
7. **Compliance Awareness:** Understanding regulatory requirements for investigations

---

**Full penetration testing report and additional project documentation available in portfolio.**

*These academic projects demonstrate foundational knowledge in digital forensics, incident response, penetration testing, and cybersecurity operations - providing the theoretical and practical basis for professional forensics work.*
