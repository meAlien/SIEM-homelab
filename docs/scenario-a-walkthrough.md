# Incident Investigation Walkthrough — Scenario A
## Credential Dumping via Mimikatz (T1003.001)

**Date:** [Your simulation date]
**Severity:** Critical (Level 15)
**Status:** Detected and Investigated

---

## 1. Alert Triage

**Alert fired:** Rule 100101 — Mimikatz credential dump detected
**Rule level:** 15 (Critical)
**Triggered by:** Sysmon Event ID 10 (ProcessAccess)

Initial alert showed a process accessing `lsass.exe` with 
access mask `0x1410` — a known Mimikatz signature.

![Wazuh Alert](../evidence/scenario-a/wazuh-alert-mimikatz.png)

---

## 2. Evidence Collection

**Sysmon EID 10 raw event:**

| Field | Value |
|---|---|
| SourceImage | C:\Tools\Mimikatz\x64\mimikatz.exe |
| TargetImage | C:\Windows\System32\lsass.exe |
| GrantedAccess | 0x1410 |
| CallTrace | ntdll.dll, KERNELBASE.dll |

![Sysmon EID 10](../evidence/scenario-a/scenario-a-eid10-eventviewer.png)

---

## 3. Attack Reconstruction

1. Attacker gained admin access to the endpoint
2. Dropped `mimikatz.exe` to `C:\Tools\Mimikatz\x64\`
3. Executed `privilege::debug` to obtain SeDebugPrivilege
4. Executed `sekurlsa::logonpasswords` — opened a handle 
   to lsass.exe with access mask 0x1410
5. Extracted plaintext credentials and NTLM hashes from memory

---

## 4. MITRE ATT&CK Mapping

- **Tactic:** Credential Access
- **Technique:** T1003 — OS Credential Dumping
- **Sub-technique:** T1003.001 — LSASS Memory

---

## 5. Detection Logic

Custom Wazuh rule 100101 fired because:
- Sysmon EID 10 was generated (process access event)
- `TargetImage` matched `lsass.exe`
- `GrantedAccess` matched known Mimikatz mask `0x1410`

```xml
<rule id="100101" level="15">
  <if_sid>100100</if_sid>
  <field name="win.eventdata.grantedAccess" type="pcre2">
    0x1010|0x1410|0x143a|0x1438|0x1418
  </field>
  <description>Mimikatz credential dump detected (T1003.001)</description>
</rule>
```

---

## 6. Response Actions

1. **Isolate** the endpoint from the network immediately
2. **Invalidate** all credentials that were logged into 
   this machine — assume all are compromised
3. **Reset** passwords for all affected accounts from a 
   clean machine
4. **Hunt** for lateral movement using the dumped credentials
   — check authentication logs on other systems
5. **Forensic image** the endpoint before remediation

---

## 7. Lessons Learned

- Credential dumping from lsass is detectable with high 
  confidence using Sysmon EID 10 + access mask matching
- Default Wazuh rules do not cover this — custom rules are required
- SeDebugPrivilege acquisition (`privilege::debug`) should 
  also be monitored as an early indicator