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

**Recovery Results:**
- 2 GIF files recovered
- 7 JPG files recovered  
- 1 DOC file recovered
- 1 OLE file recovered

**Total artifacts:** 11 files carved from deleted space

#### Phase 3: Evidence Analysis

**Document Analysis:**
- Examined recovered .doc file for case-relevant information
- Document contained critical evidence about incident
- Information revealed disposition of hard drive

**Key Finding:**

Through analysis of recovered documents, determined that **the hard drive was physically destroyed ("zapped") and disposed of in the Mississippi River** - indicating potential evidence destruction and obstruction.

---

## Incident Response Planning & Execution: Malware Threat Response

### Project Overview

**Type:** Incident Response Plan & Playbook Development  
**Scenario:** Malware infection investigation and remediation  
**Framework:** Canadian Cyber Centre ITSAP.40.003, ITSG-33  
**Format:** Professional IR documentation with step-by-step procedures

[**📄 View Full Incident Response Plan (PDF)**](./Incident_Response_Plan_Malware_Threat.pdf)

**Objective:**  
Develop comprehensive incident response procedures for handling malware threats, including identification, containment, eradication, recovery, and lessons learned. Document using enterprise security tools and Canadian government security frameworks.

**Scenario Background:**  
User reported suspected malware infection on endpoint device. Investigation required systematic approach to determine scope, contain threat, preserve evidence, and remediate while maintaining forensic integrity.

### Executive Summary

This IR plan outlines the complete response process for potential malware incidents, from initial report through post-incident review. The plan incorporates enterprise security tools (CrowdStrike EDR, Splunk SIEM, Wireshark), forensic evidence handling procedures, and compliance with Canadian cybersecurity standards.

**Key Components:**
- Device isolation and containment procedures
- Forensic evidence collection and preservation
- Timeline reconstruction and scope determination
- Malware analysis and threat assessment
- Remediation and recovery procedures
- Root cause analysis and lessons learned

### Tools & Technologies

**Security Information & Event Management (SIEM):**
- **Splunk** - Log aggregation, correlation, and analysis
- Index searching for web traffic and user activity
- Timeline analysis for incident reconstruction

**Endpoint Detection & Response (EDR):**
- **CrowdStrike Falcon** - Enterprise endpoint security console
- Host isolation and network containment
- Malware detection and system monitoring
- Endpoint forensic data collection

**Network Analysis:**
- **Wireshark** - Network protocol analysis and packet capture
- Traffic pattern analysis for data exfiltration detection
- Network-based IOC identification

**Threat Intelligence:**
- **VirusTotal** - OSINT malware scanning and URL reputation
- Suspicious file and URL analysis
- IOC correlation and threat identification

### Incident Response Phases

#### Phase 1: Identification & Containment

**Initial Response Actions:**

1. **Device Verification**
   - Confirm device is organization-managed
   - Identify endpoint hostname and user
   - Document initial user report details

2. **Network Isolation**
   - Access CrowdStrike Console
   - Navigate to Host Setup and Management
   - Search for affected endpoint by hostname
   - Execute network containment: Isolate device from network
   - **Purpose:** Prevent malware spread and lateral movement within internal network

3. **User Communication**
   - Assign IR team member to contact user
   - Gather initial information:
     - User activities before incident
     - Symptoms observed
     - Approximate timeline
     - Recent downloads or website visits

4. **Documentation Initiation**
   - Create live incident documentation
   - Include: Notes, screenshots, tools used, processes followed
   - Maintain running timeline of investigation

**Forensic Consideration:**  
Early containment prevents evidence destruction while maintaining system state for analysis.

#### Phase 2: Scope Determination & Evidence Collection

**Investigation Activities:**

**Firewall Log Review:**
- Check for suspicious outbound traffic patterns
- Identify unusual destination IPs or domains
- Look for data exfiltration indicators (large outbound transfers)

**Windows Event Log Analysis:**

Indicators of Compromise (IOCs) to identify:
- **Data Exfiltration:** Large amounts of COPY operations
- **Time Anomalies:** Unusual login times/dates (after-hours access)
- **Account Activity:** Abnormal user behavior patterns
- **Process Execution:** Unexpected program launches

**EDR System Detection Review:**

Using CrowdStrike Falcon console:
- Review detection alerts and quarantined items
- Identify downloaded files and execution history
- Check for persistence mechanisms
- Analyze process tree for malicious activity

**Decision Point: Malicious File Download Detected?**

**If NO malicious files downloaded:**
- Proceed to Phase 3 (Damage Assessment)

**If YES - malicious file confirmed:**

**Forensic Evidence Collection Protocol:**

1. **System Imaging**
   - Create forensic image of infected system
   - Use write-blocker to prevent evidence alteration
   - Generate hash values for image verification

2. **Order of Volatility Data Capture**
   
   Collect evidence from most volatile (spontaneously changing) to least:
   - CPU registers and cache
   - RAM contents (memory dump)
   - Network connections and routing tables
   - Running processes and loaded modules
   - Temporary file systems
   - Disk storage
   - Remote logging data
   - Physical configuration and topology

3. **Data Integrity Verification**
   - Create cryptographic hash (MD5, SHA-256) of all collected evidence
   - Document hash values for chain of custody
   - Verify hashes after evidence transfer

4. **Chain of Custody Documentation**
   - Record who collected evidence, when, and how
   - Document evidence storage and handling
   - Maintain unbroken custody trail for legal admissibility

5. **Escalation & Handoff**
   - Escalate to Incident Response Team Lead
   - Prepare evidence package for Digital Forensics team
   - Transfer to Malware Analysis Team for deep-dive investigation
   - Provide complete documentation and timeline

6. **System Recovery**
   - Determine earliest known-good backup point
   - Restore device from clean backup (if available)
   - Verify restored system integrity before reconnection

#### Phase 3: Damage Assessment & Remediation

**SIEM Analysis Using Splunk:**

**Web Traffic Investigation:**

Search indexes for user web activity:
```
index=wireshark user="username" url="URL AND url!=.js" | stats count by user url
```

This query:
- Aggregates events by user and URL
- Excludes JavaScript files for cleaner results
- Provides timeline of web browsing activity

**Timeline Reconstruction:**
- Set search timeframe to incident window
- Identify all URLs accessed during suspicious period
- Correlate web traffic with EDR detections

**Threat Intelligence Analysis:**

For each suspicious URL identified:

1. **VirusTotal Scanning**
   - Submit URLs to VirusTotal
   - Review antivirus detection results
   - Check community reputation scores

2. **Sandbox Investigation**
   - Create isolated sandbox environment
   - Navigate to suspicious URLs in controlled environment
   - Monitor network connections and behavior

3. **IOC Extraction**
   - Identify associated IP addresses
   - Document connected domains
   - Map URL redirection chains
   - Identify additional malicious infrastructure

**Remediation Actions:**

1. **Network Security Controls**
   - Blacklist all identified malicious URLs
   - Block malicious IP addresses at firewall
   - Update DNS filtering rules
   - Add IOCs to threat intelligence feeds

2. **Endpoint Remediation**
   - Run full antivirus/anti-malware scan
   - Remove malicious files and registry entries
   - Disable unauthorized browser notifications
   - Clear browser cache and cookies
   - Reset browser settings to defaults

3. **System Recovery**
   - Restore from backup if needed (use earliest clean backup)
   - Verify system integrity post-restoration
   - Confirm no persistence mechanisms remain

4. **Post-Remediation Validation**
   - Re-scan endpoint with multiple AV engines
   - Verify no suspicious network connections
   - Monitor for 24-48 hours for reinfection

#### Phase 4: Root Cause Analysis & Lessons Learned

**Incident Reconstruction:**

**Attack Chain Identified:**

1. **Initial Vector:** User performed Google search using specific keywords
2. **Malicious Result:** Clicked on first search result (SEO poisoning)
3. **Redirect Chain:** Legitimate-looking site redirected to malicious URL
4. **CAPTCHA Abuse:** Malicious CAPTCHA page (social engineering)
5. **User Action:** User clicked CAPTCHA verification
6. **Second Redirect:** Redirected to second malicious URL
7. **Notification Abuse:** User clicked "ALLOW Notifications" popup
8. **Malicious Activity:** Endpoint received spam notification attacks

**Root Cause:**  
Social engineering attack leveraging search engine optimization (SEO) poisoning and browser notification abuse. No actual malware downloaded, but malicious notifications enabled.

**Impact Assessment:**
- ✅ NO data exfiltration detected
- ✅ NO virus/malware downloaded to device
- ✅ NO lateral movement attempted
- ⚠️ Spam notifications caused user disruption
- ✅ Successfully remediated via notification blocking and URL blacklisting

**Lessons Learned:**

**Technical Improvements:**
- Implement browser notification restrictions via Group Policy
- Deploy URL filtering at DNS level (prevent access to malicious sites)
- Enhance user endpoint controls (restrict notification permissions)
- Add malicious URL categories to web filtering

**User Awareness Gaps:**
- Need for training on search result verification
- CAPTCHA awareness (legitimate sites rarely use aggressive CAPTCHAs)
- Browser notification permission education
- Reporting procedures reinforcement

**Process Improvements:**
- Document common social engineering tactics for quick reference
- Create user-facing guidance on notification permissions
- Establish regular user security awareness training
- Update IR playbook with notification abuse scenario

### Skills Demonstrated

**Incident Response:**
- Systematic IR methodology (Identify, Contain, Eradicate, Recover, Lessons Learned)
- Live incident coordination and documentation
- Evidence-based decision making
- Timeline reconstruction and analysis

**Forensic Skills:**
- Order of volatility understanding
- Chain of custody maintenance
- Evidence collection and preservation
- Forensic imaging and hashing
- Data integrity verification

**Technical Analysis:**
- SIEM log analysis and correlation (Splunk)
- EDR platform usage (CrowdStrike)
- Network traffic analysis (Wireshark)
- Threat intelligence integration (VirusTotal)
- IOC extraction and analysis

**Tool Proficiency:**
- Enterprise EDR console operation
- SIEM query development and analysis
- Network protocol analysis
- Sandbox investigation techniques
- Threat intelligence platforms

**Communication & Documentation:**
- Professional IR plan documentation
- Clear step-by-step procedures
- Technical and non-technical communication
- Lessons learned documentation
- Compliance framework alignment

### Compliance & Frameworks

**Canadian Cyber Centre Guidelines:**

- **ITSAP.40.003** - Developing Your Incident Response Plan
- **ITSG-33 Annex 3A** - Security Control Catalogue
- **ITSAP.40.002** - Backing Up Your Information

**IR Best Practices Applied:**
- Documented procedures for repeatability
- Evidence handling for legal admissibility
- Compliance with government security standards
- Post-incident review and improvement

### Real-World Applications

**This IR plan applies to:**

**Corporate Security Operations:**
- SOC analyst incident handling
- Tier 1/2 incident response procedures
- Escalation and handoff protocols
- Evidence collection for forensics

**Digital Forensics:**
- Proper evidence preservation
- Chain of custody maintenance
- Forensic imaging procedures
- Timeline reconstruction methodology

**Malware Analysis:**
- Sample collection and handling
- Sandbox analysis techniques
- IOC extraction and documentation
- Threat intelligence integration

**Compliance & Governance:**
- Government security framework adherence
- Documentation standards
- Audit trail maintenance
- Process improvement cycles

### Key Takeaways

1. **Early Containment Matters:** Network isolation prevents incident escalation
2. **Order of Volatility:** Proper evidence collection sequence preserves critical data
3. **Documentation is Critical:** Detailed notes enable forensic analysis and legal proceedings
4. **Tool Integration:** Multiple tools (EDR, SIEM, threat intel) provide complete picture
5. **User Factor:** Social engineering remains effective attack vector requiring awareness training
6. **Lessons Learned:** Post-incident analysis drives security improvements

### Why This Matters for Forensics Career

**IR and Forensics Connection:**

- IR teams are first responders who collect initial evidence
- Forensic analysts receive evidence from IR investigations
- Understanding IR procedures ensures forensically sound evidence
- IR documentation provides context for forensic examination
- Chain of custody originates in IR phase

**Skills Transfer:**
- Evidence handling procedures identical in IR and forensics
- Timeline reconstruction fundamental to both disciplines
- Tool proficiency (SIEM, EDR) applies to forensic investigations
- Documentation standards critical for both fields

---

**Full incident response plan with detailed procedures, tool usage, and compliance framework alignment available in portfolio.**

*This project demonstrates practical incident response planning, forensic evidence handling, enterprise security tool proficiency, and compliance with Canadian government cybersecurity standards - essential skills for digital forensics and incident response roles.*

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

SSH Configuration Hardening - Modified SSH config file with new MAC configuration: 
```
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,
hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com, hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
```

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
