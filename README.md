# IR Playbook Automation Engine

A Python-based incident response automation tool that executes 
structured IR playbooks aligned to the NIST CSF framework and 
mapped to MITRE ATT&CK techniques. Built to automate the manual 
triage and response workflow a SOC analyst performs during active 
incidents.

---

## What It Does

When an incident is declared the engine:

- Collects evidence automatically — account status, login history,
  endpoint processes, network connections
- Enriches IOCs against VirusTotal in real time
- Correlates evidence across identity, endpoint, and network layers
- Escalates severity automatically when critical indicators are found
- Executes containment actions in sequence
- Generates a complete timestamped incident report in both
  human-readable and JSON formats

---

## Playbooks

### Playbook 1 — Compromised Credential
**MITRE ATT&CK:** T1078 - Valid Accounts  
**NIST CSF Phases:** Identify → Detect → Respond → Recover

Automates response to suspected credential compromise. Checks 
account status, pulls login history, detects suspicious 
authentication sources, queries endpoint telemetry, enriches 
IOCs, executes containment, and generates incident report.

**Auto-escalation triggers:**
- Login from Tor exit node → escalates to P1
- Full attack chain confirmed → endpoint isolation

**Containment actions:**
- Account disabled in Active Directory
- All sessions terminated, SSO tokens revoked
- Suspicious IP blocked at perimeter firewall
- Endpoint isolated via EDR
- MFA re-enrollment triggered

---

### Playbook 2 — Malware Execution
**MITRE ATT&CK:** T1204.002 / T1059.001 / T1071  
**NIST CSF Phases:** Identify → Detect → Respond → Recover

Automates response to suspected malware execution. Collects 
process telemetry, detects malicious parent-child chains, 
checks network connections for C2 activity, auto-expands IOC 
scope from evidence, maps MITRE ATT&CK techniques dynamically, 
and executes containment.

**Auto-escalation triggers:**
- C2 communication confirmed → escalates to P1
- Lateral movement detected → account disablement added

**Containment actions:**
- Endpoint isolated via CrowdStrike Falcon
- Malicious processes terminated
- C2 IP blocked at perimeter firewall
- Memory dump captured for forensic analysis
- User account disabled if lateral movement confirmed

---

## Architecture

ir-playbook-automation/
│
├── playbooks/
│   ├── compromised_credential.py   # Credential compromise workflow
│   └── malware_execution.py        # Malware execution workflow
│
├── utils/
│   ├── logger.py                   # NIST-phase-tagged action logger
│   ├── evidence.py                 # Evidence collection engine
│   └── reporter.py                 # Report generation (TXT + JSON)
│
├── main.py                         # Analyst-facing interface
├── config.py                       # Analyst info, thresholds (not committed)
└── .gitignore                      # Excludes credentials and reports


---

## Setup

1. Clone the repo:
```bash
git clone https://github.com/iDea82/ir-playbook-automation.git
cd ir-playbook-automation
```

2. Create virtual environment:
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

3. Install dependencies:
```bash
pip install requests colorama jinja2
```

4. Create `config.py`:
```python
ANALYST_NAME = "Your Name"
ANALYST_TIER = "Tier 2"
SOC_TEAM = "Security Operations"
VIRUSTOTAL_API_KEY = "your_key_here"
SEVERITY_LEVELS = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low"
}
NIST_PHASES = ["Identify","Protect","Detect","Respond","Recover"]
AUTO_ESCALATE_TO_P1 = ["ransomware","data exfiltration confirmed",
                        "domain admin compromise","active lateral movement"]
REPORT_OUTPUT_DIR = "reports"
```

5. Run:
```bash
python main.py
```

---

## Sample Output

============================================================
COMPROMISED CREDENTIAL PLAYBOOK — INC-20260407-222043
[2026-04-07 22:20:43] [INFO]     [Identify] Checking account status for: atijani
[2026-04-07 22:20:43] [WARNING]  [Identify] High failed login count: 23 failures in 24 hours
[2026-04-07 22:20:43] [CRITICAL] [Detect]   Suspicious login from Tor exit node: 185.220.101.45
[2026-04-07 22:20:43] [CRITICAL] [Identify] Severity escalated to P1 — Tor login confirmed
[2026-04-07 22:20:44] [CRITICAL] [Detect]   Attack chain confirmed: Credential compromise →
Macro execution → PowerShell payload
[2026-04-07 22:20:44] [SUCCESS]  [Respond]  Account disabled in Active Directory: atijani
[2026-04-07 22:20:44] [SUCCESS]  [Respond]  Endpoint isolated via EDR: WKSTN-ATIJANI-01
Incident ID : INC-20260407-222043
Severity    : P1 (escalated from P2)
Findings    : 4
Containment : 5 actions taken
Duration    : 0:00:01


---

## MITRE ATT&CK Coverage

| Playbook | Technique | Description |
|----------|-----------|-------------|
| Compromised Credential | T1078 | Valid Accounts |
| Malware Execution | T1204.002 | Malicious File |
| Malware Execution | T1059.001 | PowerShell |
| Malware Execution | T1071 | Application Layer Protocol (C2) |

---

## Author

Adesina Tijani — Security Operations Analyst  
Detection Engineering · Incident Response · SOC Automation  
[linkedin.com/in/adesina-tijani-6372693b5](https://linkedin.com/in/adesina-tijani-6372693b5)  
[github.com/iDea82](https://github.com/iDea82)