# SIEM Home Lab — Wazuh + Sysmon Threat Detection

![Wazuh](https://img.shields.io/badge/Wazuh-4.7-blue)
![Sysmon](https://img.shields.io/badge/Sysmon-15.x-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

A self-directed home lab simulating real attacker techniques and 
detecting them with a custom-tuned SIEM. Built to demonstrate 
practical SOC analyst skills — log analysis, detection engineering, 
and incident investigation.

---

## Lab Architecture

┌─────────────────────┐         ┌──────────────────────┐
│   Windows 10 VM     │────────▶│   Wazuh Manager      │
│                     │  logs   │   (Docker on host)   │
│  • Sysmon v15       │         │                      │
│  • Wazuh Agent 4.7  │         │  • Wazuh Indexer     │
│  • Attack tools     │         │  • Wazuh Dashboard   │
└─────────────────────┘         └──────────────────────┘

## Tools & Technologies

| Tool | Version | Purpose |
|---|---|---|
| Wazuh | 4.7 | SIEM — log ingestion, alerting, dashboards |
| Sysmon | 15.x | Windows endpoint telemetry |
| VirtualBox | 7.x | Hypervisor for Windows VM |
| Docker | Latest | Runs Wazuh stack on host |
| Mimikatz | 2.2.0 | Credential dumping simulation |

---

## Attack Scenarios & Detection Coverage

| # | Technique | MITRE ID | Sysmon EID | Custom Rule IDs | Severity |
|---|---|---|---|---|---|
| A | Credential Dumping via Mimikatz | T1003.001 | 10 | 100100–100102 | Critical (15) |
| B | Registry Run Key Persistence | T1547.001 | 11, 13 | 100110–100112 | High (13) |
| C | Encoded PowerShell Recon | T1059.001 | 1, 22 | 100120–100122 | High (12) |
| — | Multi-stage Attack Correlation | T1003+T1547 | — | 100130 | Critical (15) |

---

## Repository Structure

'''
siem-homelab/
├── README.md                          # This file
├── rules/
│     └── custom_rules.xml            # 10 custom Wazuh detection rules
├── sysmon/
│     └── sysmonconfig.xml            # Tuned Sysmon config with EID 10/13 includes
├── docs/
│     ├── scenario-a-walkthrough.md   # Credential dumping investigation
│     ├── scenario-b-walkthrough.md   # Persistence investigation
│     └── scenario-c-walkthrough.md   # Encoded PowerShell investigation
└── evidence/
├── setup/                       # Lab setup screenshots
├── scenario-a/                  # Mimikatz alert evidence
├── scenario-b/                  # Registry persistence evidence
└── scenario-c/                  # PowerShell recon evidence

'''


---

## Setup Guide

### Prerequisites
- Host machine with 8 GB RAM
- VirtualBox installed
- Docker Desktop installed (5 GB RAM allocated)

### 1. Deploy Wazuh
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
Access dashboard at `https://localhost` — credentials: `admin / SecretPassword`

### 2. Deploy Custom Detection Rules
```bash
docker exec -it single-node-wazuh.manager-1 bash
cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
# paste contents of rules/custom_rules.xml into local_rules.xml
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-control restart
```

### 3. Deploy Sysmon on Windows VM
```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

---

## Key Findings

- Default Wazuh rules do not cover Sysmon EID 10 (lsass access) or EID 13
  (registry run key writes) — custom rules are essential for these detections
- SwiftOnSecurity Sysmon config excludes lsass process access by default —
  requires explicit include rule for `\CurrentVersion\Run` and lsass target
- Mimikatz uses access mask `0x1410` against lsass — highly specific and
  reliable detection indicator with near-zero false positives
- Encoded PowerShell (`-EncodedCommand`) combined with a scripting engine
  parent process is a high-confidence execution indicator

---

## Author
**Abdul Hadi**
MCA Graduate — Lovely Professional University
[LinkedIn](https://www.linkedin.com/in/abdul-hadi-719810248/) 
[GitHub](https://github.com/meAlien)
