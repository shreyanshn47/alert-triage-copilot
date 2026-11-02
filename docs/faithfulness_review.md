# Evidence faithfulness review (to be filled in by a person)

20 verdicts from the LLM + retrieval system, drawn at random (fixed seed) from those with evidence. For each evidence item, check whether the quoted source really supports the claim being made, and write `yes`, `partly` or `no`. Then record the counts at the bottom. The `verbatim` flag is only an automated text match, not a judgement of support.


## ben-T1003.001-05  (true label: benign, verdict: **benign**, confidence 0.85)

- Alert: `process_access` | process `None` | details `C:\Program Files\CrowdStrike\CSFalconService.exe accessed C:\Windows\System32\lsass.exe access=0x1410`
- Rationale: The accessing process is CrowdStrike's Falcon sensor service running from C:\Program Files as SYSTEM, which is endpoint security tooling that routinely reads LSASS. The access mask 0x1410 would match the LSASS access rule's selection, but that rule explicitly excludes processes under Program Files. Nothing in the alert suggests credential dumping or other abuse, though confidence is not absolute because a single alert lacks surrounding telemetry.

  1. **alert_field / command_line**; quote: "C:\Program Files\CrowdStrike\CSFalconService.exe accessed C:\Windows\System32\lsass.exe access=0x1410" (verbatim: yes)
     - Source text: C:\Program Files\CrowdStrike\CSFalconService.exe accessed C:\Windows\System32\lsass.exe access=0x1410
     - Supports the claim? ____
  2. **alert_field / user**; quote: "NT AUTHORITY\SYSTEM" (verbatim: yes)
     - Source text: NT AUTHORITY\SYSTEM
     - Supports the claim? ____
  3. **sigma / LSASS Access From Non System Account**; quote: "filter_main_generic: {ProcessName|contains: [':\Program Files\', ':\Program Files (x86)\']}" (verbatim: yes)
     - Source text: Sigma detection rule: LSASS Access From Non System Account Techniques: T1003.001 Description: Detects potential mimikatz-like tools accessing LSASS from non system account Log source: product=windows, service=security Detection logic: {condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_generic: {ProcessName|contains: [':\Program Files\', ':\Program Files (x86)\']}, filter_main_service_account: {SubjectUserName|endswith: $}, filter_main_wmiprvse: {AccessMask: '0x1410', ProcessName: 'C:\Windows\System32\wbem\WmiPrvSE.exe'}, filter_optional_steam: {Process
     - Supports the claim? ____

## ben-T1003.001-06  (true label: benign, verdict: **needs_human**, confidence 0.60)

- Alert: `process_access` | process `None` | details `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe accessed C:\Windows\System32\lsass.exe access=0x1010`
- Rationale: The alert shows vmtoolsd.exe opening lsass.exe with access mask 0x1010, which includes PROCESS_VM_READ and is the kind of access credential-dumping tools use. However, the context rules for LSASS dumping require a dump tool such as TrolleyExpress, ProcessDump or dump64, or a dbgcore/dbghelp call trace, and none of these appear, and no dump file or suspicious child process is shown. The access is unusual for VMware Tools but could be legitimate, so a human should check whether vmtoolsd normally touches LSASS on this host and look for follow-on activity.

  1. **alert_field / command_line**; quote: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe accessed C:\Windows\System32\lsass.exe access=0x1010" (verbatim: yes)
     - Source text: C:\Program Files\VMware\VMware Tools\vmtoolsd.exe accessed C:\Windows\System32\lsass.exe access=0x1010
     - Supports the claim? ____
  2. **alert_field / user**; quote: "NT AUTHORITY\SYSTEM" (verbatim: yes)
     - Source text: NT AUTHORITY\SYSTEM
     - Supports the claim? ____

## ben-T1021.002-07  (true label: benign, verdict: **needs_human**, confidence 0.60)

- Alert: `network_share_access` | process `None` | details `share \\*\ADMIN$ file Shares\Finance\q3.xlsx`
- Rationale: The alert shows the service account svc-backup accessing the ADMIN$ share and touching a finance file, which matches the SMB admin-share pattern in T1021.002, but the Sigma rule notes that legitimate administrative activity causes this access. Backup jobs can run as service accounts and may legitimately read files over admin shares, so the alert does not settle the question. The command_line field is malformed and the alert lacks the source host of the file and the job context needed to confirm whether this backup is authorized, so a human should check the backup schedule and the target system.

  1. **attack / T1021.002**; quote: "Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB" (verbatim: no)
     - Source text: T1021.002 SMB/Windows Admin Shares (MITRE ATT&CK technique; tactics: lateral-movement). Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.  SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.
     - Supports the claim? ____
  2. **sigma / Access To ADMIN$ Network Share**; quote: "Detects access to ADMIN$ network share" (verbatim: yes)
     - Source text: Sigma detection rule: Access To ADMIN$ Network Share Techniques: T1021.002 Description: Detects access to ADMIN$ network share Log source: product=windows, service=security, definition=Requirements: The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure Detection logic: {condition: selection and not 1 of filter_*, filter_main_computer_account: {SubjectUserName|endswith: $}, selection: {EventID: 5140, ShareName: Admin$}} Known false positives: Legitimate administrative activity Severity: low Author: Florian Roth (Nextron Systems) Source: http
     - Supports the claim? ____
  3. **alert_field / command_line**; quote: "share \\*\ADMIN$ file Shares\Finance\q3.xlsx" (verbatim: yes)
     - Source text: share \\*\ADMIN$ file Shares\Finance\q3.xlsx
     - Supports the claim? ____

## ben-T1021.002-08  (true label: benign, verdict: **malicious**, confidence 0.70)

- Alert: `network_share_access` | process `None` | details `share \\*\ADMIN$ file Windows\Temp\sccm_pkg.exe`
- Rationale: The alert shows a remote SMB session to the ADMIN$ share on SRV-FILE-01 that writes an executable into Windows\Temp, which matches the file-transfer and binary-staging pattern described for T1021.002. The filename suggests SCCM packaging, which could be legitimate, but the session is run by svc-backup, a backup service account that has no obvious reason to deploy SCCM packages. Because the account does not match the apparent purpose and the alert is a single event, confidence is moderate and a human should confirm the change with the owner of svc-backup and the SCCM team.

  1. **attack / T1021.002**; quote: "Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries" (verbatim: no)
     - Source text: T1021.002 SMB/Windows Admin Shares (MITRE ATT&CK technique; tactics: lateral-movement). Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.  SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.
     - Supports the claim? ____
  2. **sigma / Access To ADMIN$ Network Share**; quote: "Detects access to ADMIN$ network share" (verbatim: yes)
     - Source text: Sigma detection rule: Access To ADMIN$ Network Share Techniques: T1021.002 Description: Detects access to ADMIN$ network share Log source: product=windows, service=security, definition=Requirements: The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure Detection logic: {condition: selection and not 1 of filter_*, filter_main_computer_account: {SubjectUserName|endswith: $}, selection: {EventID: 5140, ShareName: Admin$}} Known false positives: Legitimate administrative activity Severity: low Author: Florian Roth (Nextron Systems) Source: http
     - Supports the claim? ____
  3. **alert_field / command_line**; quote: "share \\*\ADMIN$ file Windows\Temp\sccm_pkg.exe" (verbatim: yes)
     - Source text: share \\*\ADMIN$ file Windows\Temp\sccm_pkg.exe
     - Supports the claim? ____
  4. **alert_field / user**; quote: "svc-backup" (verbatim: yes)
     - Source text: svc-backup
     - Supports the claim? ____

## ben-T1053.005-07  (true label: benign, verdict: **benign**, confidence 0.85)

- Alert: `process_create` | process `C:\Windows\System32\schtasks.exe` | details `schtasks.exe /Create /TN "Backup\Nightly" /TR "C:\Program Files\BackupAgent\run.exe" /SC DAILY /ST 02:00 /RU SYSTEM`
- Rationale: The task runs a binary from the standard Program Files install path of a named backup agent on a fixed daily schedule, which matches routine backup administration. It does not point to a suspicious folder, environment variable, SSH tunnel, curl/PowerShell download, or a one-time temp-folder run. The account is an IT admin account, which is consistent with administrative setup, though the SYSTEM run-as is worth a quick check against the change record.

  1. **alert_field / command_line**; quote: "schtasks.exe /Create /TN "Backup\Nightly" /TR "C:\Program Files\BackupAgent\run.exe" /SC DAILY /ST 02:00 /RU SYSTEM" (verbatim: yes)
     - Source text: schtasks.exe /Create /TN "Backup\Nightly" /TR "C:\Program Files\BackupAgent\run.exe" /SC DAILY /ST 02:00 /RU SYSTEM
     - Supports the claim? ____
  2. **sigma / Scheduled Task Creation Via Schtasks.EXE**; quote: "Known false positives: Administrative activity; Software installation" (verbatim: yes)
     - Source text: Sigma detection rule: Scheduled Task Creation Via Schtasks.EXE Techniques: T1053.005 Description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility. Log source: category=process_creation, product=windows Detection logic: {condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_system_user: {User|contains: [AUTHORI, AUTORI]}, filter_optional_msoffice: {CommandLine|contains: Microsoft\Office\Office Performance Monitor, Image: ['C:\Windows\System32\schtasks.exe', 'C:\Windows\SysWOW64\schtasks.exe'], ParentImage: ['C:\Program Fi
     - Supports the claim? ____

## ben-T1053.005-08  (true label: benign, verdict: **benign**, confidence 0.80)

- Alert: `process_create` | process `C:\Windows\System32\schtasks.exe` | details `schtasks.exe /Create /TN "Maintenance\DiskCleanup" /TR "C:\IT\tools\cleanup.cmd" /SC WEEKLY /D SUN /ST 03:30 /RU SYSTEM`
- Rationale: The task is a weekly scheduled cleanup run at 03:30 on a backup server, from a tool path under C:\IT\tools, created by an IT administrator account, which is routine maintenance. The task runs as SYSTEM, which is worth a glance, but it is not in a temp or user-writable location and nothing else in the alert suggests abuse. The Sigma rules that flag schtasks creation list administrative activity as a known false positive, and the other rules' suspicious-path and encoded-command indicators are absent. Confidence is moderate because a single alert cannot confirm the cleanup.cmd contents or the change-request context.

  1. **alert_field / command_line**; quote: "schtasks.exe /Create /TN "Maintenance\DiskCleanup" /TR "C:\IT\tools\cleanup.cmd" /SC WEEKLY /D SUN /ST 03:30 /RU SYSTEM" (verbatim: yes)
     - Source text: schtasks.exe /Create /TN "Maintenance\DiskCleanup" /TR "C:\IT\tools\cleanup.cmd" /SC WEEKLY /D SUN /ST 03:30 /RU SYSTEM
     - Supports the claim? ____
  2. **alert_field / user**; quote: "CORP\adm-it2" (verbatim: yes)
     - Source text: CORP\adm-it2
     - Supports the claim? ____
  3. **sigma / Scheduled Task Creation Via Schtasks.EXE**; quote: "Known false positives: Administrative activity; Software installation" (verbatim: yes)
     - Source text: Sigma detection rule: Scheduled Task Creation Via Schtasks.EXE Techniques: T1053.005 Description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility. Log source: category=process_creation, product=windows Detection logic: {condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_system_user: {User|contains: [AUTHORI, AUTORI]}, filter_optional_msoffice: {CommandLine|contains: Microsoft\Office\Office Performance Monitor, Image: ['C:\Windows\System32\schtasks.exe', 'C:\Windows\SysWOW64\schtasks.exe'], ParentImage: ['C:\Program Fi
     - Supports the claim? ____

## ben-T1059.001-05  (true label: benign, verdict: **benign**, confidence 0.75)

- Alert: `process_create` | process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | details `powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Get-Inventory.ps1`
- Rationale: The command runs a local IT inventory script from a administrative share path under an IT admin account on a backup server, which looks like routine administration. None of the context rules match: the PowerShell Sigma rules need a ScriptBlock LSASS access, a scheduled task with specific switches, a redirected input stream, or a non-interactive parent that is not visible here. Parent process and follow-on activity are not available, so confidence is moderate rather than high.

  1. **alert_field / command_line**; quote: "powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Get-Inventory.ps1" (verbatim: yes)
     - Source text: powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Get-Inventory.ps1
     - Supports the claim? ____
  2. **alert_field / user**; quote: "CORP\adm-it2" (verbatim: yes)
     - Source text: CORP\adm-it2
     - Supports the claim? ____

## ben-T1059.001-06  (true label: benign, verdict: **benign**, confidence 0.80)

- Alert: `process_create` | process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | details `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Install-Updates.ps1`
- Rationale: The command runs a local IT maintenance script from a D:\IT\scripts path with a conventional RemoteSigned execution policy, which matches routine administration. It has no encoded command, no remote session parameters, no scheduled task creation, and no remote thread or PsExec artefacts that match the context rules. Confidence is moderate because the alert lacks parent process and follow-on telemetry, so an analyst should confirm the script and the adm-it2 account's expected activity.

  1. **alert_field / command_line**; quote: "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Install-Updates.ps1" (verbatim: yes)
     - Source text: powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Install-Updates.ps1
     - Supports the claim? ____
  2. **alert_field / user**; quote: "CORP\adm-it2" (verbatim: yes)
     - Source text: CORP\adm-it2
     - Supports the claim? ____

## ben-T1059.001-07  (true label: benign, verdict: **benign**, confidence 0.70)

- Alert: `process_create` | process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | details `powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Export-Report.ps1`
- Rationale: The command runs a named script file from an internal IT scripts directory under a patch service account, which is consistent with routine scheduled administration. It does not match the redirected-input rule (no '<' redirect), the Runscripthelper rule, or the script-block rules, and no script content or credential-access indicators are present. Confidence is moderate because the alert omits the parent process, the script contents, and any follow-on activity.

  1. **alert_field / command_line**; quote: "powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Export-Report.ps1" (verbatim: yes)
     - Source text: powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Export-Report.ps1
     - Supports the claim? ____

## ben-T1059.001-08  (true label: benign, verdict: **benign**, confidence 0.70)

- Alert: `process_create` | process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | details `powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Sync-AD-Groups.ps1`
- Rationale: The alert shows a non-interactive PowerShell run of a named script from an IT scripts directory under a service account, which is consistent with routine administration. None of the context detection rules match the visible fields: the command line contains no New-PSSession, shadow copy, New-LocalUser, scheduled task, or LSASS strings, although the script body is not visible. Confidence is moderate because the script contents are unknown and the service account could still be misused.

  1. **alert_field / command_line**; quote: "powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Sync-AD-Groups.ps1" (verbatim: yes)
     - Source text: powershell.exe -NonInteractive -NoLogo -File D:\IT\scripts\Sync-AD-Groups.ps1
     - Supports the claim? ____
  2. **alert_field / user**; quote: "CORP\svc-patch" (verbatim: yes)
     - Source text: CORP\svc-patch
     - Supports the claim? ____

## ben-T1059.001-10  (true label: benign, verdict: **benign**, confidence 0.80)

- Alert: `process_create` | process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | details `powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Sync-AD-Groups.ps1`
- Rationale: The alert shows a PowerShell process running a named administrative script from an IT scripts directory, under an operations admin account, with no encoded command, remote session, shadow copy, or LSASS access indicators. The command line matches routine administration such as directory group synchronisation, and no context rule matches its fields. Confidence is moderate because the single alert lacks parent process and follow-on telemetry, and the script contents are not visible.

  1. **alert_field / command_line**; quote: "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Sync-AD-Groups.ps1" (verbatim: yes)
     - Source text: powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\IT\scripts\Sync-AD-Groups.ps1
     - Supports the claim? ____
  2. **alert_field / user**; quote: "CORP\adm-ops" (verbatim: yes)
     - Source text: CORP\adm-ops
     - Supports the claim? ____

## ben-T1110-07  (true label: benign, verdict: **needs_human**, confidence 0.30)

- Alert: `logon_failure` | process `C:\Windows\System32\winlogon.exe` | details ``
- Rationale: The alert shows a single logon failure for user mpatel on WS-ACCT-014 with winlogon.exe as the process, but it contains no registry key, DLL path, or script content, so it does not match the Winlogon Helper DLL or Notify key rules in context. The logon failure itself fits routine mistyped passwords as well as password guessing (T1110.001), and the alert lacks the fields needed to decide between them. A human should check the failure count, the source IP, and any follow-on logons or registry changes on the host.

  1. **alert_field / event_type**; quote: "logon_failure" (verbatim: yes)
     - Source text: logon_failure
     - Supports the claim? ____
  2. **alert_field / process**; quote: "C:\Windows\System32\winlogon.exe" (verbatim: yes)
     - Source text: C:\Windows\System32\winlogon.exe
     - Supports the claim? ____

## ben-T1110-08  (true label: benign, verdict: **needs_human**, confidence 0.60)

- Alert: `logon_failure` | process `None` | details ``
- Rationale: The account name svc-nessus and the internal source IP suggest a scheduled vulnerability scanner using a service account, which would be routine. However, the alert is a single failed logon at 01:54 UTC with no failure reason, attempt count, or target pattern, so it cannot rule out password guessing with a borrowed scanner account name. The Sigma rules in context (MSSQL, public IP, status-code tampering) either do not apply or lack the fields needed to match. A human should confirm whether a Nessus scan was scheduled at that time and whether other accounts show failures from the same source.

  1. **alert_field / user**; quote: "svc-nessus" (verbatim: yes)
     - Source text: svc-nessus
     - Supports the claim? ____
  2. **alert_field / src_ip**; quote: "10.20.9.50" (verbatim: yes)
     - Source text: 10.20.9.50
     - Supports the claim? ____
  3. **alert_field / event_type**; quote: "logon_failure" (verbatim: yes)
     - Source text: logon_failure
     - Supports the claim? ____

## ben-T1547.001-05  (true label: benign, verdict: **malicious**, confidence 0.85)

- Alert: `registry_set` | process `C:\Windows\SysWOW64\OneDriveSetup.exe` | details `registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Teams = C:\Users\Public\Teams\Update.exe --processStart Teams.exe`
- Rationale: A process named OneDriveSetup.exe running as NT AUTHORITY\SYSTEM from C:\Windows\SysWOW64 wrote a machine-wide Run key (HKLM) that launches an executable from C:\Users\Public, which is a user-writable location. This matches the autostart persistence technique T1547.001 and the Sigma ASEP modification rule. The OneDriveSetup name does not match the legitimate OneDrive install paths the rule excludes, and a Teams Run entry pointing to a Public folder on a backup server has no obvious business purpose, though I lack the parent process and follow-on telemetry to confirm.

  1. **attack / T1547.001**; quote: "Registry Run Keys / Startup Folder" (verbatim: yes)
     - Source text: T1547.001 Registry Run Keys / Startup Folder (MITRE ATT&CK technique; tactics: persistence, privilege-escalation). * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders  The following Registry keys can control automatic startup of services during boot:  * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\
     - Supports the claim? ____
  2. **sigma / CurrentVersion Autorun Keys Modification**; quote: "Detects modification of autostart extensibility point (ASEP) in registry." (verbatim: yes)
     - Source text: Sigma detection rule: CurrentVersion Autorun Keys Modification Techniques: T1547.001 Description: Detects modification of autostart extensibility point (ASEP) in registry. Log source: category=registry_set, product=windows Detection logic: {condition: all of selection_* and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_ctfmon: {Details: ctfmon.exe /n, Image: 'C:\Windows\system32\userinit.exe'}, filter_main_defender: {Image: 'C:\Program Files\Windows Defender\MsMpEng.exe'}, filter_main_edge: {Image|startswith: ['C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\', 'C:\Pro
     - Supports the claim? ____
  3. **alert_field / command_line**; quote: "registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Teams = C:\Users\Public\Teams\Update.exe --processStart Teams.exe" (verbatim: yes)
     - Source text: registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Teams = C:\Users\Public\Teams\Update.exe --processStart Teams.exe
     - Supports the claim? ____
  4. **alert_field / process**; quote: "C:\Windows\SysWOW64\OneDriveSetup.exe" (verbatim: yes)
     - Source text: C:\Windows\SysWOW64\OneDriveSetup.exe
     - Supports the claim? ____

## ben-T1547.001-06  (true label: benign, verdict: **needs_human**, confidence 0.60)

- Alert: `registry_set` | process `C:\Program Files\Common Files\Update\setup.exe` | details `registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom = C:\Program Files\Zoom\bin\Zoom.exe --autostart`
- Rationale: The alert writes an HKLM Run value that matches the CurrentVersion Autorun Keys Modification rule and the T1547.001 persistence technique. The value points to Zoom.exe in Program Files, and the writer runs as SYSTEM from a Program Files path, which is consistent with a legitimate Zoom install or update. However, the writer is a generic 'setup.exe' from Common Files\Update that is not a known installer, and the alert has no signature, parent, or install-context data to confirm legitimacy, so an analyst should verify the writer's signature and whether Zoom was deployed on this host.

  1. **sigma / CurrentVersion Autorun Keys Modification**; quote: "Detects modification of autostart extensibility point (ASEP) in registry." (verbatim: yes)
     - Source text: Sigma detection rule: CurrentVersion Autorun Keys Modification Techniques: T1547.001 Description: Detects modification of autostart extensibility point (ASEP) in registry. Log source: category=registry_set, product=windows Detection logic: {condition: all of selection_* and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_ctfmon: {Details: ctfmon.exe /n, Image: 'C:\Windows\system32\userinit.exe'}, filter_main_defender: {Image: 'C:\Program Files\Windows Defender\MsMpEng.exe'}, filter_main_edge: {Image|startswith: ['C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\', 'C:\Pro
     - Supports the claim? ____
  2. **attack / T1547.001**; quote: "Adversaries can add other programs or processes to this registry value which will automatically launch at boot." (verbatim: no)
     - Source text: T1547.001 Registry Run Keys / Startup Folder (MITRE ATT&CK technique; tactics: persistence, privilege-escalation). Run keys may exist under multiple hives. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"
     - Supports the claim? ____
  3. **alert_field / command_line**; quote: "registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom = C:\Program Files\Zoom\bin\Zoom.exe --autostart" (verbatim: yes)
     - Source text: registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Zoom = C:\Program Files\Zoom\bin\Zoom.exe --autostart
     - Supports the claim? ____
  4. **alert_field / process**; quote: "C:\Program Files\Common Files\Update\setup.exe" (verbatim: yes)
     - Source text: C:\Program Files\Common Files\Update\setup.exe
     - Supports the claim? ____

## mal-T1003.001-09  (true label: malicious, verdict: **malicious**, confidence 0.80)

- Alert: `process_access` | process `None` | details `C:\Windows\System32\rundll32.exe accessed C:\windows\system32\lsass.exe access=0x1fffff`
- Rationale: rundll32.exe opened lsass.exe with access mask 0x1fffff (PROCESS_ALL_ACCESS), which is the kind of LSASS memory access used for credential dumping, and there is no evident legitimate reason for rundll32 to request this. The alert does not include the CallTrace or source-path fields that the dbgcore/dbghelp Sigma rule needs, and rundll32 is not one of the named tool filenames, so those rules do not fully match. Confidence is moderate because the alert lacks parent process and follow-on telemetry, and an EDR or administrator action cannot be fully excluded from this single event.

  1. **attack / T1003.001**; quote: "Similar to Image File Execution Options Injection, the silent process exit mechanism can be abused to create a memory dump of `lsass.exe`" (verbatim: yes)
     - Source text: T1003.001 LSASS Memory (MITRE ATT&CK technique; tactics: credential-access). Similar to Image File Execution Options Injection, the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).  Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: HKLM\SYSTEM
     - Supports the claim? ____
  2. **alert_field / command_line**; quote: "C:\Windows\System32\rundll32.exe accessed C:\windows\system32\lsass.exe access=0x1fffff" (verbatim: yes)
     - Source text: C:\Windows\System32\rundll32.exe accessed C:\windows\system32\lsass.exe access=0x1fffff
     - Supports the claim? ____

## mal-T1003.001-10  (true label: malicious, verdict: **malicious**, confidence 0.80)

- Alert: `process_create` | process `C:\Program Files\PowerShell\7\createdump.exe` | details `"C:\Program Files\PowerShell\7\createdump.exe" -u -f C:\Users\ADMINI~1\AppData\Local\Temp\2\dotnet-lsass.dmp`
- Rationale: The alert shows createdump.exe run with dump flags (-u -f) to write a memory dump into a Temp folder, which is the LOLOBIN pattern the Sigma rule describes for process memory dumping. The output filename 'dotnet-lsass.dmp' suggests the target was LSASS, which would be credential dumping under T1003.001. The alert does not show the target process ID or follow-on activity, and the binary sits in the legitimate PowerShell 7 install path run by an Administrator on what looks like a lab host, so a documented diagnostic run cannot be fully ruled out, but the lsass naming makes abuse the more likely explanation.

  1. **sigma / CreateDump Process Dump**; quote: "Detects uses of the createdump.exe LOLOBIN utility to dump process memory" (verbatim: yes)
     - Source text: Sigma detection rule: CreateDump Process Dump Techniques: T1036, T1003.001 Description: Detects uses of the createdump.exe LOLOBIN utility to dump process memory Log source: category=process_creation, product=windows Detection logic: {condition: all of selection_*, selection_cli: {CommandLine|contains: [' -u ', ' --full ', ' -f ', ' --name ', '.dmp ']}, selection_img: [{Image|endswith: \createdump.exe}, {OriginalFileName: FX_VER_INTERNALNAME_STR}]} Known false positives: Command lines that use the same flags Severity: high Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextro
     - Supports the claim? ____
  2. **alert_field / command_line**; quote: "-u -f C:\Users\ADMINI~1\AppData\Local\Temp\2\dotnet-lsass.dmp" (verbatim: yes)
     - Source text: "C:\Program Files\PowerShell\7\createdump.exe" -u -f C:\Users\ADMINI~1\AppData\Local\Temp\2\dotnet-lsass.dmp
     - Supports the claim? ____

## mal-T1021.002-04  (true label: malicious, verdict: **needs_human**, confidence 0.50)

- Alert: `network_share_access` | process `None` | details `share \\*\IPC$`
- Rationale: The alert shows a user connecting to the IPC$ share on a workstation at 02:57 UTC, which could be share enumeration or lateral-movement preparation (T1135, T1021.002). It does not name the target system or the named pipe accessed, so the Sigma SVCCTL and ATSVC rules cannot be confirmed as matching. Without the destination host and pipe name or follow-on activity, the evidence does not clearly separate routine access from abuse, so a human should review.

  1. **alert_field / command_line**; quote: "share \\*\IPC$" (verbatim: yes)
     - Source text: share \\*\IPC$
     - Supports the claim? ____
  2. **attack / T1135**; quote: "Net can be used to query a remote system for available shared drives using the net view \\remotesystem command." (verbatim: no)
     - Source text: T1135 Network Share Discovery (MITRE ATT&CK technique; tactics: discovery). Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.  File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \\\\
     - Supports the claim? ____

## mal-T1053.005-06  (true label: malicious, verdict: **malicious**, confidence 0.80)

- Alert: `process_create` | process `C:\Windows\System32\schtasks.exe` | details `schtasks  /create /F /tn \Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager /tr "C:\Windows\system32\cmd.exe /C C:\Windows\System32\notepad.exe" /sc ONSTART /ru system /S WORKSTATION6`
- Rationale: A standard user account (pgustavo) created a scheduled task with schtasks.exe that runs as SYSTEM at startup, using /S to target a different host (WORKSTATION6), which suggests remote persistence or lateral movement. The task name is placed under a legitimate Windows SoftwareProtectionPlatform path to blend in, and the action launches cmd.exe, a common abuse pattern. The payload shown (notepad) looks harmless, and an administrator could have run this, but nothing in the alert establishes that it was authorized.

  1. **sigma / Scheduled Task Creation Via Schtasks.EXE**; quote: "CommandLine|contains: ' /create ', Image|endswith: \schtasks.exe" (verbatim: yes)
     - Source text: Sigma detection rule: Scheduled Task Creation Via Schtasks.EXE Techniques: T1053.005 Description: Detects the creation of scheduled tasks by user accounts via the "schtasks" utility. Log source: category=process_creation, product=windows Detection logic: {condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*, filter_main_system_user: {User|contains: [AUTHORI, AUTORI]}, filter_optional_msoffice: {CommandLine|contains: Microsoft\Office\Office Performance Monitor, Image: ['C:\Windows\System32\schtasks.exe', 'C:\Windows\SysWOW64\schtasks.exe'], ParentImage: ['C:\Program Fi
     - Supports the claim? ____
  2. **alert_field / command_line**; quote: "schtasks  /create /F /tn \Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager /tr "C:\Windows\system32\cmd.exe /C C:\Windows\System32\notepad.exe" /sc ONSTART /ru system /S WORKSTATION6" (verbatim: yes)
     - Source text: schtasks  /create /F /tn \Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager /tr "C:\Windows\system32\cmd.exe /C C:\Windows\System32\notepad.exe" /sc ONSTART /ru system /S WORKSTATION6
     - Supports the claim? ____
  3. **alert_field / user**; quote: "pgustavo" (verbatim: yes)
     - Source text: pgustavo
     - Supports the claim? ____

## mal-T1547.001-06  (true label: malicious, verdict: **benign**, confidence 0.60)

- Alert: `process_create` | process `C:\Windows\System32\reg.exe` | details `REG  DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f`
- Rationale: The command removes a single Run-key value named "Atomic Red Team" from HKCU, which looks like cleanup of an attack-simulation artifact rather than adding persistence. The context rule for Run-key persistence (T1547.001) covers adding entries with reg add, not deleting them, so it does not match. Confidence is moderate because the alert lacks the parent process and any surrounding activity, and a deletion of an autorun entry on a domain controller should still be confirmed by a person.

  1. **alert_field / command_line**; quote: "REG  DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f" (verbatim: yes)
     - Source text: REG  DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f
     - Supports the claim? ____

## Totals (fill in)

Evidence items checked: ____  yes: ____  partly: ____  no: ____
