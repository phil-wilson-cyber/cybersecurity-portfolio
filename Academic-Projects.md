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
**Completed:** November 2022  
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
**Format:** Lab Exercise + Technical Report

**Objective:**  
Conduct a comprehensive digital forensics investigation following NIST guidelines to identify, analyze, and document evidence of a security incident.

### Skills Demonstrated

**Forensic Investigation Methodology:**
- Evidence identification and preservation
- Chain of custody documentation
- Forensic imaging and data acquisition
- File system analysis
- Timeline reconstruction
- Evidence correlation across multiple sources

**Technical Analysis:**
- Artifact analysis (browser history, registry, logs)
- File metadata examination
- Deleted file recovery
- User activity reconstruction
- Identification of indicators of compromise

**Reporting & Documentation:**
- Technical forensic report writing
- Evidence documentation with screenshots
- Chain of custody maintenance
- Executive summary for non-technical stakeholders
- Actionable recommendations

### Key Learning Outcomes

1. **Proper Evidence Handling:** Understanding the critical importance of maintaining evidence integrity throughout investigation
2. **NIST Framework Application:** Practical application of NIST incident response procedures
3. **Forensic Tool Usage:** Hands-on experience with digital forensics tools and methodologies
4. **Documentation Standards:** Professional-grade forensic reporting and documentation practices
5. **Investigative Mindset:** Systematic approach to uncovering and analyzing digital evidence

### Real-World Application

This project simulates actual digital forensics investigations conducted by:
- Corporate incident response teams
- Law enforcement digital forensics units
- Third-party forensic investigators
- eDiscovery professionals

---

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
