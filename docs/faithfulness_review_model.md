# Evidence faithfulness: model-judged (blinded) review

**This is NOT the human review.** `docs/faithfulness_review.md` is the human sheet and is not complete (this model check never wrote to it). This file is a separate, model-made check, kept so the two can be compared.

## Method

- 20 verdicts / 49 evidence items from the LLM + retrieval test run (the same sample as the human sheet).
- A fresh Claude Sonnet 5.5 subagent judged each item with no repository access. It saw only a copy of the sheet from which the **true label, the system's verdict and confidence, and the automated `verbatim` flag were removed**. It still saw the rationale (the claim being checked), the quote and the cited source text.
- The system under test is Claude Haiku 5.5, so the judge is a larger model from the same family. That is not independent of the generator's blind spots.
- Source text in the sheet is cut at about 600 characters, so some quotes could not be checked against the cut-off part.

## Result

| Judgement | Items | Share |
|---|---|---|
| yes | 44 | 90% |
| partly | 5 | 10% |
| no | 0 | 0% |

Of the 44 `yes`, **4 were given on trust** because the supporting text was in the cut-off part (marked *unverifiable* below), so 40 are fully verified and 4 are plausible but unseen.

By source of the evidence item:

| Source | yes | partly | no |
|---|---|---|---|
| alert_field | 33 | 1 | 0 |
| sigma | 9 | 0 | 0 |
| attack | 2 | 4 | 0 |

Against the automated verbatim check (revealed only after judging): items flagged `verbatim: no` were judged partly 3, yes 1; items flagged `verbatim: yes` were judged partly 2, yes 43.

## Items judged `partly` (unblinded)

| Verdict id | True label | System verdict | Item | Why |
|---|---|---|---|---|
| ben-T1021.002-07 | benign | needs_human | attack / T1021.002 | Source supports the SMB admin-share lateral-movement idea, but the exact quote is not in the visible text (likely hidden by the 600-char cut-off). |
| ben-T1021.002-08 | benign | malicious | attack / T1021.002 | Visible source supports SMB share use, but the file-transfer and run-binaries wording is not visible (likely cut off). |
| mal-T1003.001-09 | malicious | malicious | attack / T1003.001 | Real LSASS-dump text, but it concerns the silent process exit and WerFault mechanism, not rundll32 or a 0x1fffff access mask. |
| mal-T1021.002-04 | malicious | needs_human | attack / T1135 | True technique text about net view share discovery, but the alert only shows an IPC$ connection, not net view or enumeration. |
| mal-T1053.005-06 | malicious | malicious | alert_field / user | The user pgustavo is confirmed, but nothing shows the account is a standard user. |

## All items

| Verdict id | True label | System verdict | Item | Verbatim (auto) | Judge | Reason |
|---|---|---|---|---|---|---|
| ben-T1003.001-05 | benign | benign | 1. alert_field / command_line | yes | yes | Quote is the alert detail showing CSFalconService.exe from Program Files accessing lsass with 0x1410. |
| ben-T1003.001-05 | benign | benign | 2. alert_field / user | yes | yes | User field is SYSTEM, as the rationale states. |
| ben-T1003.001-05 | benign | benign | 3. sigma / LSASS Access From Non System Account | yes | yes | The rule's filter_main_generic excludes paths containing Program Files, as claimed. |
| ben-T1003.001-06 | benign | needs_human | 1. alert_field / command_line | yes | yes | Alert shows vmtoolsd.exe accessing lsass.exe with mask 0x1010. |
| ben-T1003.001-06 | benign | needs_human | 2. alert_field / user | yes | yes | User field is SYSTEM; nothing in the claim goes beyond it. |
| ben-T1021.002-07 | benign | needs_human | 1. attack / T1021.002 | no | partly | Source supports the SMB admin-share lateral-movement idea, but the exact quote is not in the visible text (likely hidden by the 600-char cut-off). |
| ben-T1021.002-07 | benign | needs_human | 2. sigma / Access To ADMIN$ Network Share | yes | yes | Rule text says it detects ADMIN$ access and lists legitimate administrative activity as a false positive. |
| ben-T1021.002-07 | benign | needs_human | 3. alert_field / command_line | yes | yes | Alert detail shows ADMIN$ share and the Finance q3.xlsx file. |
| ben-T1021.002-08 | benign | malicious | 1. attack / T1021.002 | no | partly | Visible source supports SMB share use, but the file-transfer and run-binaries wording is not visible (likely cut off). |
| ben-T1021.002-08 | benign | malicious | 2. sigma / Access To ADMIN$ Network Share | yes | yes | Rule is for ADMIN$ access, matching the alert. |
| ben-T1021.002-08 | benign | malicious | 3. alert_field / command_line | yes | yes | Alert shows ADMIN$ share and Windows\Temp\sccm_pkg.exe. |
| ben-T1021.002-08 | benign | malicious | 4. alert_field / user | yes | yes | The user is svc-backup, a backup-named service account. |
| ben-T1053.005-07 | benign | benign | 1. alert_field / command_line | yes | yes | Command line shows a daily schtasks creation of a Program Files BackupAgent task as SYSTEM. |
| ben-T1053.005-07 | benign | benign | 2. sigma / Scheduled Task Creation Via Schtasks.EXE | yes | yes (unverifiable) | Admin activity as a known false positive is plausibly in the cut-off part of the rule; not visible, so unverified. |
| ben-T1053.005-08 | benign | benign | 1. alert_field / command_line | yes | yes | Command shows a weekly SYSTEM task running C:\IT\tools\cleanup.cmd at 03:30. |
| ben-T1053.005-08 | benign | benign | 2. alert_field / user | yes | yes | User is an adm-it2 admin-style account. |
| ben-T1053.005-08 | benign | benign | 3. sigma / Scheduled Task Creation Via Schtasks.EXE | yes | yes (unverifiable) | Same false-positive quote as V05.2; the text is cut off, so unverified but consistent. |
| ben-T1059.001-05 | benign | benign | 1. alert_field / command_line | yes | yes | Command line is a NonInteractive -File run of an inventory script. |
| ben-T1059.001-05 | benign | benign | 2. alert_field / user | yes | yes | User is the IT admin account adm-it2. |
| ben-T1059.001-06 | benign | benign | 1. alert_field / command_line | yes | yes | Command line shows RemoteSigned, -File, and the D:\IT\scripts path. |
| ben-T1059.001-06 | benign | benign | 2. alert_field / user | yes | yes | User is adm-it2. |
| ben-T1059.001-07 | benign | benign | 1. alert_field / command_line | yes | yes | Command line shows a named script file and no redirect. |
| ben-T1059.001-08 | benign | benign | 1. alert_field / command_line | yes | yes | Command line has no New-PSSession, shadow copy or LSASS strings, as claimed. |
| ben-T1059.001-08 | benign | benign | 2. alert_field / user | yes | yes | User is the svc-patch service account. |
| ben-T1059.001-10 | benign | benign | 1. alert_field / command_line | yes | yes | Command line shows a named script and no encoded or remote indicators. |
| ben-T1059.001-10 | benign | benign | 2. alert_field / user | yes | yes | User is adm-ops, an operations admin account. |
| ben-T1110-07 | benign | needs_human | 1. alert_field / event_type | yes | yes | event_type is logon_failure. |
| ben-T1110-07 | benign | needs_human | 2. alert_field / process | yes | yes | Process is winlogon.exe. |
| ben-T1110-08 | benign | needs_human | 1. alert_field / user | yes | yes | User is svc-nessus. |
| ben-T1110-08 | benign | needs_human | 2. alert_field / src_ip | yes | yes | src_ip 10.20.9.50 is an internal private address. |
| ben-T1110-08 | benign | needs_human | 3. alert_field / event_type | yes | yes | event_type is logon_failure. |
| ben-T1547.001-05 | benign | malicious | 1. attack / T1547.001 | yes | yes | The technique T1547.001 title and Run key content support the persistence claim. |
| ben-T1547.001-05 | benign | malicious | 2. sigma / CurrentVersion Autorun Keys Modification | yes | yes | Rule is about ASEP modification, matching the HKLM Run write. |
| ben-T1547.001-05 | benign | malicious | 3. alert_field / command_line | yes | yes | Command line shows an HKLM Run value pointing to C:\Users\Public. |
| ben-T1547.001-05 | benign | malicious | 4. alert_field / process | yes | yes | Process is OneDriveSetup.exe in SysWOW64. |
| ben-T1547.001-06 | benign | needs_human | 1. sigma / CurrentVersion Autorun Keys Modification | yes | yes | Rule is about ASEP modification in the registry, which matches a Run key write. |
| ben-T1547.001-06 | benign | needs_human | 2. attack / T1547.001 | no | yes (unverifiable) | Run-key persistence claim is supported by the technique text; the exact quote is not visible (possibly cut off). |
| ben-T1547.001-06 | benign | needs_human | 3. alert_field / command_line | yes | yes | Alert shows an HKLM Run value for Zoom in Program Files. |
| ben-T1547.001-06 | benign | needs_human | 4. alert_field / process | yes | yes | Writer process is Common Files\Update\setup.exe under Program Files. |
| mal-T1003.001-09 | malicious | malicious | 1. attack / T1003.001 | yes | partly | Real LSASS-dump text, but it concerns the silent process exit and WerFault mechanism, not rundll32 or a 0x1fffff access mask. |
| mal-T1003.001-09 | malicious | malicious | 2. alert_field / command_line | yes | yes | Alert shows rundll32.exe accessing lsass.exe with 0x1fffff. |
| mal-T1003.001-10 | malicious | malicious | 1. sigma / CreateDump Process Dump | yes | yes | Rule text says it detects createdump.exe dumping process memory. |
| mal-T1003.001-10 | malicious | malicious | 2. alert_field / command_line | yes | yes | Command line has -u -f and writes dotnet-lsass.dmp to Temp. |
| mal-T1021.002-04 | malicious | needs_human | 1. alert_field / command_line | yes | yes | Alert detail shows an IPC$ share access. |
| mal-T1021.002-04 | malicious | needs_human | 2. attack / T1135 | no | partly | True technique text about net view share discovery, but the alert only shows an IPC$ connection, not net view or enumeration. |
| mal-T1053.005-06 | malicious | malicious | 1. sigma / Scheduled Task Creation Via Schtasks.EXE | yes | yes (unverifiable) | Rule matches /create with schtasks.exe; the exact quote is likely in the cut-off part. |
| mal-T1053.005-06 | malicious | malicious | 2. alert_field / command_line | yes | yes | Command line shows /ru system, /sc ONSTART, /S WORKSTATION6, and the SoftwareProtectionPlatform path. |
| mal-T1053.005-06 | malicious | malicious | 3. alert_field / user | yes | partly | The user pgustavo is confirmed, but nothing shows the account is a standard user. |
| mal-T1547.001-06 | malicious | benign | 1. alert_field / command_line | yes | yes | Command line shows REG DELETE of the "Atomic Red Team" Run value from HKCU. |

## How to read this

- Most evidence items are fields copied from the alert itself (user, command line, event type). Those are easy to support, which lifts the `yes` rate.
- The five `partly` cases: a real technique description stretched to a claim it does not make (V16.1, V18.2), an assumption about a user that is not in the data (V19.3), and two quotes the judge could not locate because of truncation (V03.1, V04.1).
- The weakness is concentrated in ATT&CK-sourced evidence: 4 of its 6 items were `partly`, against 1 of 34 alert-field items and 0 of 9 Sigma items. General technique descriptions are the easiest thing to stretch.
- The automated verbatim check and the judge mostly agree (43 of 44 verbatim items were `yes`), but verbatim does not guarantee support: two verbatim quotes (V16.1, V18.2) were only `partly` supportive.
- A model judging a model's output can share its biases. The human review is still needed before this is quoted as evidence faithfulness. Until then report it as: model-judged, 44 of 49 items supported (4 of them unverifiable), 5 partly, 0 no, from 20 verdicts.
