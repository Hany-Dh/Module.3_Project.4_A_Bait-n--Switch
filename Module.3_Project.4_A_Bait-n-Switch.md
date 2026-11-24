# Bait n' Switch: Windows Honeypot Monitoring and Investigation

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-5E5E5E)
![Honeypot](https://img.shields.io/badge/Honeypot-T--Pot%2024.04.1-orange)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

> **CyberSteps | Cybersecurity Fundamentals | Module 3 | Project 4A**
> Author: Hany Dhannoon | Lab period: 31 Oct to 2 Nov 2026 | Report date: 2 Nov 2026

A deliberately vulnerable Windows server was exposed to the internet on Azure, and every sign-in attempt was monitored in Microsoft Sentinel. A second honeypot platform, T-Pot, was added to capture a wider range of attacks. The project also includes a simulated breach that was reconstructed from the logs.

> **Disclaimer:** Training exercise. The honeypot is intentionally vulnerable and contains no real data. Do not copy this setup onto a production network.

---

## Objective

Act as a SOC analyst: design, deploy and monitor a honeypot, capture telemetry from live attackers, analyse their techniques and perform forensics on a simulated breach.

## Architecture

```
Internet attackers and scanners
   |-- NSG (RDP 3389 open) --> Windows honeypot HR-HDH-SRV-01 (Azure Monitor Agent)
   |                              --> Data Collection Rule (All Security Events)
   |                              --> Log Analytics + Microsoft Sentinel (KQL, Workbook)
   |
   |-- T-Pot NSG (TCP 1-64000) --> T-Pot VM (Debian 13, honeypot sensors)
                                      --> T-Pot Attack Map + Kibana (management: analyst IP only)
```

| Component | Detail |
|---|---|
| Cloud / region | Microsoft Azure, Germany West Central |
| Windows honeypot | `HR-HDH-SRV-01` (Windows 11), RDP 3389 open, strong password |
| Monitoring | Microsoft Sentinel, Windows Security Events via AMA, DCR: All Security Events |
| Second honeypot | T-Pot 24.04.1 on Debian 13.7 (8 GB RAM) |

## Tools and technologies

Microsoft Azure, Microsoft Sentinel, Log Analytics, Azure Monitor Agent (AMA), KQL, Sentinel Workbooks, T-Pot, Kibana, Sysmon, Windows Security Events (4624, 4625, 4688, 4720, 4726, 4732, 4733), Geo-IP (`geo_info_from_ip_address()`).

## Project phases

| Phase | What was done |
|---|---|
| 1. Deploy the bait | Windows VM with an inviting name, RDP open, AMA and DCR for all security events, process-creation auditing enabled (4688) |
| 2. Smoke test | Manual failed RDP logons verified in Sentinel with KQL (4625) |
| 3. Active monitoring | Failed logons analysed over time, attackers mapped by country, attack patterns identified, custom Sentinel workbook built |
| 4. Peer attack and forensics | A classmate logged in with shared credentials; new accounts, commands and a file download were reconstructed from logs |
| 5. Continuous improvement | Sentinel attack-map workbook, T-Pot deployment and analysis in Kibana, default Sysmon installed |

## Key results

| Question | Result |
|---|---|
| First external attempt | 31 Oct 2026, 14:36 |
| Failed sign-ins | **2,361** (2,329 from the internet) |
| Attackers | **11 IPs in 9 countries** (Romania 905, Spain 462, Singapore 336, USA 235) |
| Busiest hour | 563 attempts at 22:00 on 31 Oct |
| Typical targets | `Administrator`, `Admin`, `Backup`, `User`, `Guest` (network logons, type 3) |
| External break-in | **None.** No external IP had a successful logon |
| T-Pot (24 h) | 3,463 honeypot events after filtering out noise and the analyst IP |
| Requirements | 15 done, 2 partial, 6 bypassed or not performed (see the report) |

### Simulated breach reconstruction

Accounts created and deleted by the test user, the reconnaissance commands (`systeminfo`, `whoami /priv`, `net user`, `arp -a`) and three file-download commands were all rebuilt from Windows events 4624, 4720, 4732, 4688, 4733 and 4726.

### Key findings

| ID | Finding | Rating |
|---|---|---|
| F-01 | Internet-exposed RDP is attacked continuously and quickly | High |
| F-02 | Attacks are automated guesses of privileged and default account names | High |
| F-03 | A strong, non-default credential stopped external access | Positive |
| F-04 | Shared credentials give full access from anywhere; a new admin account was created within minutes | High |
| F-05 | Process-creation auditing is off by default; early activity was lost | Medium |
| F-06 | PowerShell script-block events were created locally but not ingested into Sentinel | Medium |
| F-08 | Scanners and bots hit many services, not only RDP (T-Pot) | Medium |
| F-09 | Raw telemetry contains a lot of platform noise | Low |

## Example KQL

Top attacking IPs with Geo-IP:

```kql
SecurityEvent
| where EventID == 4625 and isnotempty(IpAddress) and IpAddress != "-"
| summarize Attempts=count(), TargetAccounts=make_set(TargetAccount,10),
            FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by IpAddress
| extend Geo = geo_info_from_ip_address(IpAddress)
| extend Country=tostring(Geo.country), City=tostring(Geo.city)
| order by Attempts desc
```

Enable command-line process auditing (run on the VM as Administrator):

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

More queries (RDP logons, account changes, download activity, workbook map and top usernames) are in **Appendix B** of the report.

## Limitations and further work

- The Brute Force incident rule and Investigation Graph were bypassed (Defender detection wizard blocked at entity mapping). Completion path is in the report.
- Sysmon was installed with the default configuration only; the SwiftOnSecurity config and Sysmon events in Sentinel are not completed.
- PowerShell 4103/4104 events were not ingested; RDP session recording was not implemented.
- Firewall disable and scheduled-task persistence were not part of the peer test.
- Events before 14:46 on 31 Oct were not recorded because process auditing started late.

## Hardening recommendations (summary)

1. Remove public RDP; use Azure Bastion, Just-in-Time access or a VPN.
2. Enforce long unique passwords, MFA and account lockout.
3. Enable detailed Windows auditing and PowerShell logging, and alert on 10+ failed logons per IP.

## Lessons learned

- Verify log sources early; process-creation and PowerShell logging are off by default.
- Filter noise (platform traffic, sensors, your own IP) before reading telemetry.
- Check product requirements first (T-Pot needed Debian 13) and plan for resource limits.
- Geo-IP needs context: a classmate's VPN exit node looked like an intrusion until confirmed.

## Repository contents

```
.
|-- README.md
|-- Bait_n_Switch_Project_Report.pdf   # full 36-page report
`-- queries/                            # KQL queries from Appendix B (optional)
```

## Acknowledgements

Thanks to teammates Robin, Eszter and Arshad for their involvement in the attack simulations and testing.
