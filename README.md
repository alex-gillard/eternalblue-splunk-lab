# Detection and Analysis of EternalBlue (CVE-2017-0144) in a Virtualized SIEM Homelab

## Objective

The EternalBlue-Splunk lab aimed to establish a controlled virtualized environment for simulating and detecting a remote code execution (RCE) attack. The primary focus was to exploit the MS17-010 (EternalBlue) vulnerability on a legacy Windows 7 system and analyze the resulting telemetry within a Splunk SIEM on Ubuntu Linux. This hands-on experience was designed to bridge the gap between offensive exploitation and defensive monitoring, deepening the understanding of kernel-level attack patterns and SIEM correlation strategies.

> [!IMPORTANT]
> **Technical Depth:** This README serves as a high-level summary of the lab. For a granular, 34-page step-by-step guide covering full environment configuration, network setup, and detailed attack/defense execution, please see the [Full Project Documentation](https://github.com/user-attachments/files/25456454/EternalBlue-Homelab-Project.pdf).

## Lab Architecture

![Network Topology Diagram](https://github.com/user-attachments/assets/7a544c3c-9e68-4a91-ba29-00d3796e7407)
> **Figure 1:** *Logical network diagram of the isolated lab environment (192.168.1.0/24). The red path indicates the MS17-010 exploitation traffic, while the green path represents the telemetry flow from the Windows 7 Universal Forwarder to the Splunk SIEM.*

### Skills Learned

- **SIEM Correlation:** Identified and correlated Windows EventCodes (4624 and 4672) and analyzing Logon Types (Type 3 vs Type 5).
- **Vulnerability Assessment:** Utilized Nmap and the Nmap Scripting Engine (NSE) to identify vulnerable SMBv1 services.
- **Exploitation Frameworks:** Demonstrated understanding of the Metasploit Framework to execute kernel-level exploits.
- **Endpoint Monitoring:** Configured Splunk Universal Forwarders to ingest security logs and monitor "honeytoken" files.
- **Detection Strategy Logic:** Identified SIEM alert logic based on temporal correlation and non-standard logon sequences.

### Tools Used

- **Splunk Enterprise:** SIEM system used for log ingestion, search, and behavior analysis.
- **Metasploit Framework:** Offensive tool used to execute the EternalBlue exploit.
- **Nmap:** Network discovery tool used for reconnaissance and vulnerability scanning.
- **VirtualBox:** Virtualization platform used to create a segregated "Internal Network" environment.
- **Splunk Universal Forwarder:** Agent used to stream Windows Event Logs and directory activity to the SIEM.

---

## Steps

### Phase I: Environment Setup
The lab consists of a segregated internal network (`EB_Lab`) containing a Kali Linux attacker (`Kali_AttackerVM`), a Windows 7 victim (`Win7_VictimVM`), and an Ubuntu Splunk server (`Ubuntu_SplunkVM`).

*Ref 1: Resource Allocation and Internal Network Confirmation*

#### Resource Allocation
| VM Role | OS / Distribution | RAM (GB) | CPU Cores | Storage (VDI) | Networking |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Attacker** | Kali Linux | 2 | 2 | 80 GB (Dynamic) | Internal (`EB_Lab`) |
| **Victim** | Windows 7 SP1 | 2 | 1 | 32 GB (Dynamic) | Internal (`EB_Lab`) |
| **SIEM Server** | Ubuntu 24.04 (Noble Numbat)| 8 | 4 | 500 GB (Dynamic) | Internal (`EB_Lab`) |

#### Internal Network Confirmation
<img width="874" height="295" alt="InternalNetworkConfirmation" src="https://github.com/user-attachments/assets/d2021881-d9e1-40ef-8c40-bc490aabccca" />


### Phase II: Reconnaissance
The attacker identifies the target and confirms the presence of the MS17-010 vulnerability via Nmap.

*Ref 2: Nmap Vulnerability Scan Results*

<img width="1135" height="820" alt="EB-Vuln-Confirmed" src="https://github.com/user-attachments/assets/7222b72a-0c82-458d-9d5e-3dc69db1c2f3" />


### Phase III: The Breaching Phase
Using Metasploit, the EternalBlue exploit is executed to gain `NT AUTHORITY\SYSTEM` access.

*Ref 3: Successful Meterpreter Shell*

<img width="1135" height="820" alt="meterpreter-shell-confirmation" src="https://github.com/user-attachments/assets/bb04fa9d-715b-40d4-8e57-83a4b3dbd991" />


### Phase IV: SIEM Detection & Analysis
Through entering the SPL query `index="main" (EventCode=4624 OR EventCode=4672 OR source="C:\\CompanyData\\*") | sort _time` and setting the time range to `All-time`, the Splunk SIEM captures the logon event and the immediate assignment of high-level privileges. A key discovery was the **Logon Type 5 (Service)** preceding the **Logon Type 3 (Network)** from a non-standard IP address, a signature of RCE automated access.

*Ref 4: Splunk Event Correlation (4624 & 4672)*

<img width="958" height="442" alt="Splunk-Event-Correlation-confirmed" src="https://github.com/user-attachments/assets/3c1120b8-f45a-417c-b955-de6b04238038" />

<img width="959" height="413" alt="Splunk-AttackerIP-confirmed" src="https://github.com/user-attachments/assets/17704980-6e12-42c0-9516-974a91a0f8be" />


### Phase V: Data Exfiltration
The attacker navigates to the "CompanyData" folder and exfiltrates the `credentials.txt` honeytoken, leaving a detectable "CONGRATS" string in the Splunk logs by dropping into the Windows shell and entering the command `echo "CONGRATS_YOUR_DATA_HAS_BEEN_EXFILTRATED" >> C:\CompanyData\credentials.txt`

Additionally the attacker downloads the `credentials.txt` file by entering the following command into the Meterpreter shell `download C:\\CompanyData\\credentials.txt /home/kali/Desktop`

*Ref 5: Exfiltration of Sensitive Data*

<img width="1275" height="825" alt="Splunk-data-exfil-confirmed" src="https://github.com/user-attachments/assets/ca1df085-3585-4f94-8055-16e0aa333f05" />
<img width="1132" height="818" alt="kali-captured-credentials" src="https://github.com/user-attachments/assets/a8aef0eb-2d9f-459f-b91d-0b5986998e14" />


### Phase VI: Remediation and Hardening

Exploitation of the Windows 7 VM was made possible primarily by the presence of the legacy **SMBv1** protocol and the absence of the **MS17-010** security patch. To prevent future compromises of this system, the following remediation steps are recommended:

#### 1. Patch Management (Immediate Action)
The primary defense against the EternalBlue exploit is the installation of **Microsoft Security Bulletin MS17-010**.
* **Action:** Deploy the latest possible updates for each legacy Windows asset.
* **Impact:** This patches the buffer overflow vulnerability present in the SMBv1 server drivers of legacy Windows assets affected by the EternalBlue exploit.

#### 2. System Hardening (Protocol Deactivation)
* **Action:** Disable **SMBv1** protocol entirely within the Windows Features settings or via Registry modification.
* **Impact:** If patches cannot be deployed due to business-critical functions, disabling SMBv1 removes the attack surface entirely. After disabling this protocol, the exploit cannot function as SMBv1 is no longer actively listening for connections.



#### 3. Security Monitoring (Detection Strategy)
The following alerting conditions should be set up in SIEMs to ensure legacy systems are protected against RCE exploits:

* **Condition 1:** Detect **EventCode 4672** (Privilege Escalation) and **EventCode 4624 Logon Type 5** (Service Logon) occurring within a 1-second window.
* **Condition 2:** Detect a subsequent **EventCode 4624 Logon Type 3** (Network Logon) from a non-standard IP within 60 seconds of the Type 5 event.

> **Analysis Observation:** Observing service logon events before network logons is highly indicative of a kernel-level exploit occurring under the hood. While human administrators usually authenticate (Type 3) before initiating a session, RCE exploits behave differently by forcing the system to start a privileged process (Type 5) before the attacker session is fully established. 
> 
> In the Splunk logs showing the full attack process, a 10-minute gap was observed between the initial exploit (3:43 PM) and the final exfiltration (3:56 PM) due to manual execution of the commands within the Meterpreter shell. The recommendation still stands for tightening the correlation window to **60 seconds**, as this ensures the detection of automated worms or scripted exploits in production environments while minimizing the probability of false positives.



---

## Conclusion

This project successfully simulated the full lifecycle of the **CVE-2017-0144 (EternalBlue)** exploit within a controlled virtual environment. By correlating offensive actions performed via Kali Linux with defensive telemetry captured in Splunk, this lab demonstrated that even kernel-level exploits leave a definitive forensic trail when proper monitoring is in place. The core evidence of the breach was identified through the chronological correlation of **EventCodes 4624 and 4672**, which provided a granular view of the attacker's progression from initial network contact to full system control.

A critical technical discovery was made by analyzing the specific sequence of logon types within the Splunk index. The appearance of a **Service Logon (Type 5)** immediately followed by a **Network Logon (Type 3)** served as a high-fidelity indicator of a non-human, automated exploit, as this "reverse" order deviates from standard administrative behavior. The subsequent assignment of **SeSecurityPrivilege** and **SeDebugPrivilege** highlighted the transition to total system compromise, granting the attacker the ability to manipulate security logs and inject code into sensitive processes. This analysis was further validated by the "Action on Objective" phase, where the modification of a honeytoken file was captured by Splunk's file integrity monitoring, providing an undeniable audit trail of data exfiltration.

Ultimately, this lab confirms that a **Defense in Depth** strategy is the most effective way to mitigate risks associated with legacy assets. Robust vulnerability management through the **MS17-010** patch and the total removal of the **SMBv1** protocol remain the primary methods for closing this specific attack vector. However, for systems where legacy protocols must exist, implementing behavioral SIEM alerting that flags unusual logon sequences within a tight 60-second temporal window is essential. This project proves that by transforming raw system telemetry into actionable intelligence, security teams can effectively detect and disrupt RCE exploits before they result in critical data loss.

---

## Technical Appendix & Supplemental Files

To provide full transparency and ensure **total reproducibility** of this lab, the following documentation has been appended to this repository:

* **[Full Technical Documentation](https://github.com/user-attachments/files/25456454/EternalBlue-Homelab-Project.pdf):** A comprehensive 34-page report detailing every phase of the project. This document is structured as a technical guide to allow other researchers/students to replicate the environment and the attack/defense lifecycle from scratch.
* **Environment Baseline:** Detailed specifications for OS builds, resource allocations, and network configurations required to reconstruct the isolated `EB_Lab` environment.
* **Implementation Methodology:** Exhaustive documentation of the Metasploit modules utilized and the specific Splunk search parameters required to successfully visualize the exploitation and post-exploitation phases.

---

## ⚖️ Legal & Ethical Disclaimer

This repository and its contents are for **educational and ethical security research purposes only**. All exploitation activities were conducted in a **fully isolated, author-controlled virtual lab environment**. 

The techniques, documentation, and logic provided here are intended to assist security analysts and students in understanding the mechanics of Remote Code Execution (RCE) and improving SIEM detection capabilities. The author assumes no liability for the misuse of this information. Unauthorized access to computer systems is illegal and strictly prohibited.
