
# MySQL Database Destruction and Ransom Extortion | SOC & DFIR Case Study

**Analyst:** Christopher Akpala  
**Report Date:** 19 October 2026  
**Affected Host:** `CORP-Kristich` / `corp-kristich`  
**Incident Period:** 16–19 October 2026  
**Severity:** Critical  
**Database Investigation:** Confirmed Destructive Activity  
**MDE Forensic Assessment:** Inconclusive

> **Investigation Summary:** This case study combines a Security Operations Centre (SOC) incident investigation with a comparative Digital Forensics and Incident Response (DFIR) assessment. The MySQL audit logs confirm destructive database activity and ransom extortion attempts. The MDE forensic packages do not independently establish malicious Windows persistence, credential theft or lateral movement.

---

### 1. Executive Summary

On 16 October 2026, privileged MySQL `root` activity was associated with data-reading queries, four `DROP DATABASE` commands and the creation of a ransom note demanding **0.0103 BTC** on `corp-kristich`.

Additional SQL statements attempted to reset or purge binary logs, modify privileges and shut down MySQL, potentially complicating database recovery.

Remote MySQL root authentications and Windows administrator logons were observed. However, the initial access method, attacker identity and successful data exfiltration were not established.

A separate comparison of two Microsoft Defender for Endpoint (MDE) live-response packages identified changes in system processes, services, scheduled tasks and user sessions. Most changes were consistent with routine Windows activity, and no independent evidence of malicious persistence or command-and-control activity was established.

**Overall Assessment:** Critical database compromise confirmed. Independent Windows host compromise remains inconclusive.

---

### 2. Investigation Scope and Evidence

The investigation incorporated Microsoft Defender Advanced Hunting, MySQL audit logs and MDE live-response forensic collections.

| Evidence Source | Records | Investigation Purpose |
|---|---|---|
| `mysql_CL_Queries_B.csv` | 285 | SQL execution, ransom-note creation and database destruction |
| `mysql_CL_Auth_Logs_B.csv` | 107 | MySQL authentication activity and source IP addresses |
| `device_logon_events_B.csv` | 23 | Windows authentication and remote logons |
| `device_process_events.csv` | 2,805 | Process execution and application activity |
| MDE Pre-Breach Package | Forensic archive | Earlier endpoint snapshot |
| MDE Post-Breach Package | Forensic archive | Later endpoint snapshot |

#### MDE Forensic Collection Timeline

| Collection | Timestamp (UTC) | Package |
|---|---|---|
| Earlier Snapshot | 16 October 2026, 22:57 | `Pre_Breach_MDE_Investigation_Package.zip` |
| Later Snapshot | 19 October 2026, 01:10 | `Post_breach_MDE_Investigation_Package (1).zip` |

**Important:** Although the earlier package is labelled "Pre-Breach", its collection timestamp follows the destructive SQL timestamps reported in the incident investigation. The SQL timezone was not independently verified, so the precise relationship requires validation.

The package name alone does not establish a genuine pre-attack baseline.

---

### 3. Incident Details

| Field | Finding |
|---|---|
| Incident Classification | Destructive Database Compromise and Ransom Extortion |
| Severity | Critical |
| Affected Host | `corp-kristich` |
| Compromised Database Account | MySQL `root` |
| Earliest MySQL Authentication | 16 October 2026, 13:15:41 |
| Affected Databases | `kristich_corp`, `sakila`, `world`, `recover_your_data` |
| Detection Timestamp | Not determined from available logs |
| Incident Reporter | Not determined from available logs |
| Containment Status | Not verified |
| Recovery Status | Not verified |

#### Impact Assessment

| Security Principle | Assessment |
|---|---|
| Confidentiality | SQL `SELECT *` statements indicate database read activity. Successful data exfiltration remains unconfirmed. |
| Integrity | Four `DROP DATABASE` commands were recorded, including against `kristich_corp`. |
| Availability | Destructive SQL and a `SHUTDOWN` statement were recorded. Actual service downtime is unknown. |

**Potential Business Impact:**

- Loss of operational database records.
- Disruption to database-dependent applications.
- Potential exposure of sensitive information.
- Database restoration and recovery costs.
- Reduced confidence in system integrity.

The quantity and sensitivity of affected data were not determined.

---

### 4. Incident Timeline

The following timeline was reconstructed using MySQL authentication logs, SQL audit records and Microsoft Defender telemetry.

*Times reflect exported event values. The timezone has not been independently verified.*

| Date / Time | Event | Evidence Source |
|---|---|---|
| 16 Oct, 12:59 | Failed Windows administrator network logons from `119.18.1.155` | DeviceLogonEvents |
| 16 Oct, 13:15–13:16 | Local MySQL root activity and successful connections from `64.89.163.92` | MySQL Authentication |
| 16 Oct, 13:16:44–47 | `RECOVER_YOUR_DATA` database and ransom table created | MySQL Queries |
| 16 Oct, 13:16–13:19 | Database enumeration and `SELECT *` queries | MySQL Queries |
| 16 Oct, 13:19:24–25 | Four `DROP DATABASE` commands recorded | MySQL Queries |
| 16 Oct, 13:19:25–26 | Ransom database recreated and ransom messages reinserted | MySQL Queries |
| 16 Oct, 13:19:27–42 | Binary-log interference, privilege changes and shutdown commands | MySQL Queries |
| 16–19 Oct | Additional external MySQL root connections | MySQL Authentication |
| 19 Oct, 10:54–10:56 | MySQL Workbench activity and ransom-table inspection | DeviceProcessEvents / MySQL Queries |
| 19 Oct, 10:59 | Successful remote-interactive Windows administrator logons | DeviceLogonEvents |

**Detection Time:** Not determined from available logs.

---

### 5. Indicators of Compromise

#### Confirmed Ransom Indicators

| Indicator Type | Value |
|---|---|
| Bitcoin Address | `bc1qt6kstjjdatqnxd3ksdcfv0jnhdjzndcnkx8zla` |
| Contact Email | `ak+2g6ah@onionmail.org` |
| Ransom URL | `hxxps://cuq[.]in/844` |
| DATAID | `2G6AH` |

These indicators were recovered from the MySQL ransom-note records.

#### Suspicious Authentication Sources

| IP Address | Observation |
|---|---|
| `64.89.163.92` | 27 successful MySQL root authentications |
| `77.90.185.30` | Repeated successful and failed MySQL authentications |
| `119.18.1.155` | Windows administrator remote-interactive logons |
| `64.89.163.154` | MySQL root authentication source |
| `64.89.163.79` | MySQL root authentication source |
| `213.209.159.115` | MySQL root authentication source |
| `77.90.185.21` | MySQL root authentication source |
| `45.128.199.195` | MySQL root authentication source |
| `89.248.171.24` | MySQL root authentication source |

These addresses are investigative indicators. Their involvement in the destructive SQL activity has not been established individually.

Additional unsuccessful Windows administrator logons were associated with:

- `93.92.200.50`
- `82.114.228.224`
- `20.172.139.103`
- `194.180.48.6`

#### Unconfirmed Indicators

The following indicators were supplied separately but were not observed in the reviewed logs:

| Indicator | Value |
|---|---|
| Bitcoin Address | `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99` |
| Contact Email | `ak+28t2@onionmail.org` |
| URL | `hxxps://2no[.]co/2mysql` |
| DATAID | `28T2` |

These indicators should not be attributed to the confirmed ransom activity without additional evidence.

---

### 6. MDE Comparative DFIR Assessment

#### Investigation Objective

Compare two Microsoft Defender for Endpoint live-response investigation packages collected from the same Windows host to identify:

- Potential persistence mechanisms.
- Suspicious process execution.
- Changes to local accounts and privileges.
- Newly created scheduled tasks.
- Unusual network connections.
- Potential credential theft or log manipulation.

**Assessment:** Inconclusive  
**Confidence:** Moderate

#### Comparative Artifact Findings

| Artifact Category | Observed Change | Assessment |
|---|---|---|
| Registry Autoruns | New OneDrive and Edge startup entries | Likely legitimate application activity |
| Scheduled Tasks | OneDrive and Windows SoftLanding tasks added | Consistent with Microsoft maintenance |
| Running Processes | Approximately 114 to 249 process records | Increase alone does not indicate compromise |
| Services | Approximately 44 additional service records | Predominantly per-user services |
| Local Groups | No changes in privileged group membership | No newly privileged account established |
| Network Connections | Additional HTTPS and local MySQL connections | No confirmed malicious destination |
| DNS Cache | Differences in cached records | Consistent with normal DNS cache changes |
| Prefetch | Additional Windows executable artifacts | No confirmed malicious execution |
| Installed Software | Microsoft application and version changes | Likely routine software updates |

#### Finding 1: Administrative Sessions

The later forensic package contained disconnected user sessions:

| Account | Session | Logon Time |
|---|---|---|
| `kristich` | 2 | 18 October 2026, 4:49 PM |
| `administrator` | 3 | 18 October 2026, 5:00 PM |

The earlier package did not show active sessions.

Both accounts were already members of the local Administrators group in the earlier snapshot.

**Assessment:** The sessions require validation, but the artifacts do not establish unauthorised activity or privilege escalation.

#### Finding 2: Credential and Event Log Artifacts

Two Prefetch artifacts were identified in both packages:

```text
COOKIE_EXPORTER.EXE-7154AAA7.pf
WEVTUTIL.EXE-4CD23CAE.pf
```

These artifacts warrant investigation because their executable names suggest possible browser-cookie handling and Windows event-log management.

However:

- Both artifacts existed in the earlier package.
- No new execution attributable to the incident was established.
- Prefetch alone cannot confirm credential theft.
- Prefetch alone cannot confirm Windows event-log clearing.

**Assessment:** Requires further investigation.

#### Finding 3: Potential Persistence Mechanisms

The later package contained additional OneDrive Registry Run-key entries and scheduled tasks associated with the administrator account.

The associated commands referenced standard Microsoft OneDrive binaries.

**Assessment:** The changes appear consistent with legitimate application persistence. Malicious use was not demonstrated.

---

### 7. MITRE ATT&CK Assessment

The following techniques represent possible investigative leads rather than confirmed attacker behaviour.

| Technique | MITRE ATT&CK ID | Assessment |
|---|---|---|
| Valid Accounts | T1078 | Requires confirmation of unauthorised administrative activity |
| Credentials from Web Browsers | T1555.003 | Browser credential access not established |
| Clear Windows Event Logs | T1070.001 | Log clearing not confirmed |
| Registry Run Keys / Startup Folder | T1547.001 | Persistence mechanism observed; malicious use unconfirmed |
| Scheduled Task | T1053.005 | Scheduled tasks observed; malicious use unconfirmed |

**Conclusion:** The MDE package comparison did not identify a high-confidence malicious executable, new privileged account, confirmed malicious persistence mechanism or command-and-control destination.

---

### 8. KQL Hunting Queries

The following queries were prepared for Microsoft Defender and Log Analytics investigations.

The MySQL audit data is accessible through:

```kql
MySQLAudit_CL
```

The SQL statement column was not independently verified. The following searches therefore use `pack_all()` to search across available event fields.

#### 8.1 Verify MySQL Audit Schema

```kql
MySQLAudit_CL
| getschema
```

#### 8.2 Hunt for Destructive SQL Statements

```kql
MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-10-16 13:15:00) ..
    datetime(2026-10-19 13:21:00)
)
| extend AuditText = tostring(pack_all())
| where AuditText contains "DROP DATABASE"
    or AuditText contains "SELECT *"
    or AuditText contains "RESET MASTER"
    or AuditText contains "PURGE BINARY LOGS"
    or AuditText contains "SHUTDOWN"
| project TimeGenerated, AuditText
| order by TimeGenerated asc
```
<img width="800" height="600" alt="Screenshot 2026-10-19 144212" src="https://github.com/user-attachments/assets/5ed2623d-89eb-4e0b-8ed1-0e9cbb5ee432" />

**Purpose:** Identify destructive SQL, data-reading queries and activity potentially interfering with database recovery.

#### 8.3 Hunt for Ransom Indicators

```kql
MySQLAudit_CL
| extend AuditText = tostring(pack_all())
| where AuditText contains "RECOVER_YOUR_DATA"
    or AuditText contains "onionmail.org"
    or AuditText contains "bc1q"
    or AuditText contains "2G6AH"
| project TimeGenerated, AuditText
| order by TimeGenerated asc
```
<img width="629" height="632" alt="Screenshot 2026-10-19 144340" src="https://github.com/user-attachments/assets/0496e684-757f-4a52-8a44-8fac8df3f92b" />

**Purpose:** Identify ransom-note creation and related SQL activity.

#### 8.4 Investigate Privileged MySQL Access

```kql
MySQLAudit_CL
| where TimeGenerated between (
    datetime(2026-10-16 12:30:00) ..
    datetime(2026-10-16 13:30:00)
)
| extend AuditText = tostring(pack_all())
| where AuditText contains "root"
| project TimeGenerated, AuditText
| order by TimeGenerated asc
```
<img width="1097" height="513" alt="Screenshot 2026-10-19 144700" src="https://github.com/user-attachments/assets/b2c02dc2-0953-4a39-afdb-9f9099019c39" />

**Purpose:** Review privileged database activity surrounding the destructive commands.

#### 8.5 Investigate Windows Administrator Logons

```kql
// Virtual Machine Logons
let MyDevice = "corp-kristich"; // MDE Truncates/cuts off the device name
let Start_Time = todatetime("2026-10-16T01:22:32.6381185Z");
let End_Time = todatetime("2026-10-19T02:08:44.905054");
DeviceLogonEvents
| where TimeGenerated between (Start_Time .. End_Time)
| where DeviceName == MyDevice
//| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
| order by TimeGenerated asc
```
<img width="1022" height="690" alt="Screenshot 2026-10-19 142242" src="https://github.com/user-attachments/assets/27922ef5-e7cb-465c-9602-fd8a6fb6cd1d" />

**Purpose:** Identify remote authentication activity and potentially unauthorised administrator sessions.

#### 8.6 Identify Continued MySQL Access

```kql
MySQLAudit_CL
| where TimeGenerated > datetime(2026-10-16 13:20:00)
| extend AuditText = tostring(pack_all())
| where AuditText contains "Connect"
    or AuditText contains "LogonSuccess"
| where AuditText contains "root"
| project TimeGenerated, AuditText
| order by TimeGenerated asc
```
<img width="1089" height="600" alt="Screenshot 2026-10-19 144745" src="https://github.com/user-attachments/assets/b65b7829-1e28-45c0-ae42-ca0765892a22" />

**Purpose:** Identify continued privileged database access after the destructive activity.

#### 8.7 Investigate Outbound Network Connections

```kql
DeviceNetworkEvents
| where DeviceName =~ "corp-kristich"
| where TimeGenerated between (
    datetime(2026-10-16) ..
    datetime(2026-10-20)
)
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort,
          InitiatingProcessFileName, ActionType
| order by TimeGenerated asc
```
<img width="892" height="644" alt="Screenshot 2026-10-19 144842" src="https://github.com/user-attachments/assets/206b6a49-e983-4ef3-aa14-478201357f6a" />

**Purpose:** Identify potentially suspicious outbound network activity.

**Limitation:** Network connection records alone do not prove data exfiltration. Correlation with network-flow and traffic-volume data is required.

---

### 9. Root Cause Analysis

#### Confirmed Findings

- Privileged MySQL `root` activity was associated with destructive SQL statements.
- Multiple databases were targeted by `DROP DATABASE` commands.
- A ransom note was created within the database environment.
- Commands intended to interfere with database recovery were recorded.
- External MySQL root authentications were observed.

#### Unconfirmed Findings

The following could not be established from the available evidence:

- Whether credentials were stolen, guessed or exposed.
- Whether a MySQL vulnerability was exploited.
- Whether MySQL was directly exposed to the internet.
- Whether the Windows host was compromised before the database.
- Whether data was successfully exfiltrated.
- Whether the observed Windows administrator sessions were unauthorised.

**Root Cause:** The confirmed attack mechanism involved privileged MySQL access. The underlying initial access vector remains undetermined.

---

### 10. Incident Response Recommendations

The available evidence does not confirm that containment, eradication or recovery actions were completed.

The following actions are recommended.

| Incident Response Phase | Recommended Actions |
|---|---|
| Containment | Restrict MySQL access, isolate affected systems where appropriate and terminate unauthorised sessions |
| Credential Security | Rotate MySQL root and Windows administrator credentials |
| Evidence Preservation | Preserve audit logs, database records, forensic images and relevant event logs |
| Eradication | Remove unauthorised accounts, grants and unnecessary remote access |
| Recovery | Restore affected databases from verified clean backups |
| Validation | Confirm database integrity, application functionality and logging |
| Monitoring | Detect unusual root logins, destructive SQL and suspicious network activity |

---

### 11. Evidence Gaps

| Evidence Category | Limitation |
|---|---|
| Initial Access | No confirmed entry point |
| Data Exfiltration | No verified data-transfer evidence |
| Windows Security Logs | Security EVTX records not fully decoded and correlated |
| System/Application Logs | Separate EVTX evidence not established |
| File-System Activity | No comprehensive creation/deletion timeline |
| Executable Hashes | No complete SHA-256 inventory |
| Network History | Snapshots do not establish historical C2 or exfiltration |
| Recovery | No verified backup restoration evidence |


### 12. Security Recommendations

| Priority | Recommendation |
|---|---|
| P1 | Restrict MySQL connectivity to approved application and management networks |
| P1 | Remove unnecessary remote MySQL root access and implement least privilege |
| P1 | Maintain offline or immutable database backups and test restoration |
| P2 | Monitor destructive SQL statements and binary-log manipulation |
| P2 | Correlate MySQL audit records with Windows authentication and process telemetry |
| P2 | Strengthen remote administration security and enforce MFA through approved access paths |

---

### 13. Final Investigation Assessment

#### MySQL Database Investigation

**Verdict:** Confirmed Destructive Database Compromise  
**Severity:** Critical

Evidence establishes:

- Privileged MySQL activity.
- Database-reading queries.
- Four destructive `DROP DATABASE` commands.
- Ransom-note creation.
- Commands intended to interfere with database recovery.

The initial access mechanism, data exfiltration, actual service downtime and successful recovery remain unverified.

#### Microsoft Defender Comparative Investigation

**Verdict:** Inconclusive  
**Confidence:** Moderate

The forensic comparison did not independently establish:

- Malicious Windows persistence.
- Newly created privileged accounts.
- Credential theft.
- Malicious executable deployment.
- Command-and-control communications.

Administrative sessions and selected execution artifacts require additional validation.

#### Overall Conclusion

The available evidence confirms a destructive MySQL database attack involving privileged access and ransom extortion.

The comparative MDE forensic assessment identified changes in system activity but did not independently establish that the Windows host was compromised.

The investigation demonstrates the importance of correlating database auditing, endpoint telemetry, authentication records and forensic artifacts while distinguishing confirmed findings from investigative hypotheses.

---

### Skills Demonstrated

- SOC Incident Investigation
- Digital Forensics and Incident Response (DFIR)
- Microsoft Defender for Endpoint
- Microsoft Defender Advanced Hunting
- Kusto Query Language (KQL)
- MySQL Audit Log Analysis
- Incident Timeline Reconstruction
- Indicators of Compromise Analysis
- Windows Authentication Investigation
- Persistence and Scheduled Task Analysis
- MITRE ATT&CK Mapping
- Incident Response Planning
- Technical Reporting and Documentation



