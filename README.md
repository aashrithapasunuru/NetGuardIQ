# 🛡️ NetGuardIQ – AI-Assisted Network Threat Detection & SOC Investigation Platform

## Overview

NetGuardIQ is a Python-based network security monitoring and investigation platform designed to help security analysts detect, investigate, and understand suspicious network activity.

The project combines **network discovery, ARP spoofing detection, URL analysis, risk scoring, security alert management, incident timelines, reporting, and AI-assisted alert analysis** into a single dashboard.

Rather than simply generating alerts, NetGuardIQ provides contextual analysis to help analysts understand **what happened, why the activity may be dangerous, what evidence to investigate, and what mitigation actions may be appropriate**.

The project was developed as a hands-on cybersecurity homelab to demonstrate practical skills in **network security monitoring, SOC alert triage, incident investigation, security automation, and AI-assisted cybersecurity**.

---

## 🎯 Project Goals

The main goals of NetGuardIQ are to:

* Monitor network activity in a controlled cybersecurity lab
* Detect suspicious network behavior
* Generate and prioritize security alerts
* Investigate security events from a SOC analyst perspective
* Use AI to assist with initial alert triage
* Maintain visibility of discovered devices and security events
* Present investigation results through dashboards, timelines, and reports

---

## 🔐 Key Features

### 1. ARP Spoofing Detection

NetGuardIQ monitors ARP information and detects unexpected changes in IP-to-MAC address mappings.

When a suspicious mapping change is detected, NetGuardIQ creates a security alert containing:

* Alert ID
* Timestamp
* Alert type
* Description
* Severity
* Risk score
* Processing status

This enables investigation of potential **ARP poisoning and man-in-the-middle activity**.

---

### 2. AI-Assisted SOC Alert Analysis

Security alerts can be submitted to the AI analyst for automated security triage.

The AI analysis provides:

* **Summary**
* **What Happened?**
* **Why Is It Dangerous?**
* **Possible Causes**
* **Investigation Steps**
* **Mitigation**

The AI component is intended to assist a security analyst during initial triage rather than replace human investigation.

---

### 3. Network Discovery

The platform provides network discovery functionality to identify hosts and devices visible within the laboratory environment.

Discovered systems can be reviewed to improve network visibility and support investigation.

---

### 4. Network Device Inventory

NetGuardIQ maintains a device inventory based on discovered network information.

This helps analysts understand:

* Which systems are present
* Which devices may be involved in an incident
* Changes in the observed network environment

---

### 5. URL Analysis

NetGuardIQ includes a URL analysis component for evaluating potentially suspicious URLs and generating security-oriented analysis.

This provides an additional investigation capability alongside network monitoring.

---

### 6. Risk Scoring and Severity

Security events are assigned severity and risk information to help prioritize investigation.

Example:

```text
Alert Type : ARP Spoofing Suspected
Severity   : Critical
Risk Score : 100
```

---

### 7. Incident Timeline

Security events are presented chronologically through an incident timeline.

This helps analysts understand the sequence of events surrounding suspicious activity.

---

### 8. Security Reports

NetGuardIQ provides a reporting view to summarize security activity and investigation results.

This can help communicate findings during incident review or security documentation.

---

## 🧠 AI-Assisted Investigation Workflow

```text
Network Activity
       │
       ▼
Network Monitoring / Discovery
       │
       ▼
Suspicious Activity Detected
       │
       ▼
Security Alert Generated
       │
       ▼
Severity + Risk Score
       │
       ▼
SOC Alert Triage
       │
       ▼
AI-Assisted Analysis
       │
       ▼
Investigation Guidance
       │
       ▼
Mitigation Recommendations
       │
       ▼
Result Stored for Review
```

---

## 🚨 Example Security Investigation

During testing, NetGuardIQ detected a suspected ARP spoofing event involving the network gateway.

### Alert #22

```text
Alert Type : ARP Spoofing Suspected
Severity   : Critical
Risk Score : 100
Status     : Processed
```

The alert contained a mismatch between the stored MAC address and the observed MAC address for the gateway IP.

The AI analyst identified the possibility of a **man-in-the-middle attack** and provided investigation guidance including:

* Verifying the legitimate MAC address
* Identifying the device associated with the observed MAC address
* Reviewing additional ARP anomalies
* Checking recent network changes
* Inspecting traffic involving the affected IP
* Isolating a suspicious device when appropriate
* Considering protections such as DHCP snooping and Dynamic ARP Inspection

This demonstrated the complete workflow from **network detection to AI-assisted SOC investigation**.

---

## 🧪 Lab Environment

NetGuardIQ was developed and tested in a controlled virtualized cybersecurity laboratory using VirtualBox.

### Testing Environment

| System            | Purpose                                     |
| ----------------- | ------------------------------------------- |
| Ubuntu VM         | NetGuardIQ application and endpoint testing |
| Kali Linux VM     | Security testing and attack simulation      |
| Windows VM        | Endpoint and network behavior testing       |
| VirtualBox        | Virtualization platform                     |
| Host-Only Network | Isolated lab communication                  |

The **Ubuntu VM hosts the NetGuardIQ application** and also participates as a lab endpoint. The **Windows VM** is used as an additional endpoint for validating network behavior, while **Kali Linux** is used for controlled security testing and attack simulation.

---

## 🏗️ Testing Architecture

```text
                         ┌─────────────────────┐
                         │     Kali Linux      │
                         │  Security Testing   │
                         └──────────┬──────────┘
                                    │
                                    │
                         ┌──────────▼──────────┐
                         │   Host-Only Lab     │
                         │      Network        │
                         └──────┬────────┬─────┘
                                │        │
                         ┌──────▼─────┐ ┌▼──────────────┐
                         │ Ubuntu VM  │ │  Windows VM   │
                         │ NetGuardIQ │ │   Endpoint    │
                         │ + Endpoint │ │   Testing     │
                         └──────┬─────┘ └───────────────┘
                                │
                                │
                         ┌──────▼──────────────┐
                         │    NetGuardIQ       │
                         ├──────────────────────┤
                         │ Flask Dashboard      │
                         │ ARP Monitoring       │
                         │ Network Discovery    │
                         │ Alert Engine         │
                         │ Device Inventory     │
                         │ URL Analysis         │
                         │ Event Management     │
                         │ AI Analyst            │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      SQLite DB       │
                         │ Alerts / Events /    │
                         │ AI Analysis Results  │
                         └──────────────────────┘
```

## 🔎 Testing Performed

NetGuardIQ was validated through controlled cybersecurity testing using Ubuntu, Kali Linux, and a Windows endpoint within an isolated VirtualBox environment.

Testing included:

* Network host discovery
* Device discovery
* ARP monitoring
* ARP spoofing detection
* Security alert generation
* Risk scoring
* AI-assisted alert analysis
* Incident timeline generation
* Security reporting
* URL analysis
* Network connectivity testing
* Endpoint network behavior validation


## 🛠️ Technologies Used

| Category           | Technologies   |
| ------------------ | -------------- |
| Programming        | Python         |
| Web Framework      | Flask          |
| Database           | SQLite         |
| Network Monitoring | Scapy          |
| AI Integration     | OpenAI API     |
| Virtualization     | VirtualBox     |
| Security Testing   | Kali Linux     |
| Vulnerable Testing | Metasploitable |
| Endpoint Testing   | Windows        |
| Version Control    | Git / GitHub   |

---

## 📂 Project Structure

```text
NetGuardIQ/
│
├── api/
├── database/
├── email_engine/
├── engines/
│   ├── ai_analyzer.py
│   ├── alert_engine.py
│   ├── arp_monitor.py
│   ├── device_inventory.py
│   ├── discovery.py
│   └── event_manager.py
│
├── screenshots/
│
├── static/
│   └── css/
│
├── templates/
│
├── app.py
├── config.py
├── init_db.py
├── requirements.txt
├── test_email_scan.py
├── test_vt.py
├── testai.py
└── README.md
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/aashrithapasunuru/NetGuardIQ.git
cd NetGuardIQ
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🔑 OpenAI API Configuration

Set your OpenAI API key as an environment variable:

```bash
export OPENAI_API_KEY="your-api-key"
```

Do not commit API keys, passwords, tokens, or other credentials to GitHub.

---

## ▶️ Running NetGuardIQ

Start the Flask application:

```bash
python3 app.py
```

The application runs on:

```text
http://127.0.0.1:5001
```

The application can also be accessed through the VM's network interface when required for lab testing.

---

## 🔎 Testing Performed

The project was tested using practical cybersecurity lab scenarios including:

* Network host discovery
* Device discovery
* Network inventory collection
* ARP monitoring
* ARP spoofing detection
* Security alert generation
* Risk scoring
* AI-assisted security alert analysis
* Incident timeline generation
* Security reporting
* URL analysis
* Network connectivity validation across laboratory systems

---

## 📊 Demonstrated Security Workflow

The project demonstrated the following SOC-oriented workflow:

```text
Detect
  ↓
Validate
  ↓
Prioritize
  ↓
Investigate
  ↓
Analyze with AI
  ↓
Recommend Mitigation
  ↓
Document
```

This mirrors the type of workflow a junior SOC analyst may follow during initial alert triage.

---

## 📸 Screenshots

### AI-Assisted Alert Analysis

![AI Analysis](screenshots/AI%20analysis.png)

### Additional AI Analysis

![AI Analysis 2](screenshots/AI%20analysis1.png)

### AI Investigation Output

![AI Analysis 3](screenshots/AI%20analysis2.png)

### ARP Spoofing Detection

![ARP Spoofing Detected](screenshots/ARPspoof%20detected.png)

### Discovered Devices

![Discovered Devices](screenshots/Discovered%20devices.png)

### Discovered Hosts

![Discovered Hosts](screenshots/discovered%20hosts.png)

### Incident Timeline

![Incident Timeline](screenshots/incident%20timeline.png)

### Security Reports

![Security Reports](screenshots/Security%20reports.png)

### URL Analysis

![URL Analyzer](screenshots/url%20analyzer.png)

---

## 🎯 What This Project Demonstrates

NetGuardIQ demonstrates hands-on experience with:

* Security monitoring
* Network security fundamentals
* ARP-based attack detection
* Alert triage
* Risk assessment
* Incident investigation
* Network discovery
* Security automation
* Python scripting
* Flask application development
* SQLite data management
* API integration
* AI-assisted cybersecurity workflows
* Documentation and security reporting
* Git and GitHub project management

---

## 🧩 AI in the SOC Workflow

The AI component is designed to improve the efficiency of initial alert triage by turning raw alert information into structured investigation guidance.

For example:

```text
Raw Security Alert
        ↓
Context Extraction
        ↓
AI Security Analysis
        ↓
Potential Attack Explanation
        ↓
Investigation Steps
        ↓
Mitigation Guidance
```

The analyst remains responsible for validating AI-generated findings against actual security telemetry and other available evidence.

---

## 🚀 Future Enhancements

Potential future improvements include:

* SIEM integration
* EDR telemetry integration
* Additional network attack detection rules
* Automated alert correlation
* Improved anomaly detection
* Threat intelligence enrichment
* Automated incident response workflows
* Role-based access control enhancements
* Expanded AI-assisted investigation
* Additional attack simulations
* Authentication and security hardening
* Integration with additional security monitoring tools

---

## ⚠️ Security and Ethical Use

NetGuardIQ is intended for **educational, defensive, and authorized security testing**.

The security testing performed for this project was conducted within a controlled virtualized laboratory environment.

Do not use the project to monitor, scan, attack, or interfere with systems without appropriate authorization.

---

## 📌 Project Status

**Active Cybersecurity Homelab Project**

The platform is continuously being improved through additional detection scenarios, security tooling, automation, and AI-assisted investigation capabilities.

---

## 👩‍💻 Author

**Aashritha Pasunuru**

Cybersecurity-focused IT professional with hands-on interests in:

**SOC Operations · Network Security · Security Monitoring · Incident Investigation · AI-Assisted Cybersecurity**

---

## 🔗 Repository

GitHub:
https://github.com/aashrithapasunuru/NetGuardIQ

