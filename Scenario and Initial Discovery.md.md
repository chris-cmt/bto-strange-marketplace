# Scenario
A few days ago, internal threat intelligence flagged suspicious activity targeting developer environments. The report highlighted a growing trend of adversaries leveraging trojanized—yet legitimate—development tools, exploiting developers' inherent trust by injecting malicious code and embedding webhooks to automate data exfiltration.

Shortly after this alert, the SOC detected an unusual outbound HTTP request originating from one of the organization’s developer workstations. You’ve been assigned to investigate and determine the source and nature of this activity.

This lab is based on the blog post: https://www.securityblue.team/blog/posts/malicious-vs-code-extensions-data-exfiltration , which provides players with foundational insight into the triage process.

# Investigation Tools
- chainsaw_x86_64-pc-windows-msvc
- kape
- yara-v4.5.2-2326-win64
- Disk image that was part of the kape-result directory `c:\Users\SBTuser\Desktop\Investigation\kape-findings`

# Investigation data
PATH to files
```
c:\Users\SBTuser\Desktop\Investigation
c:\Users\SBTuser\Desktop\Investigation\kape-findings
```
# Initial discovery

- Mounted disk image produced by kape
- Reviewed malicious vs code link provided with the lab
- Reviewed KAPE and the KAPE-Findings directory
- Reviewed `%USERPROFILE%\.vscode\extensions`

# Questions

1) Hunt for Initial Access: When was the initial access? And what binary is responsible for signing the payload?(4 points)
`YYYY-MM-DD HH:MM:SS, binary.exe`

2) Hunt for Credential Access: The attacker has accessed a file containing credentials in plain text. Identify the file name, user, and password that’s been stolen.(3 points)
`file.ext, user:password`

3) Hunt for Data Exfiltration: An attempt was made to exfiltrate this data. What IP and Port did the attacker use for C2 communication? What Living-of-the-Land binary was used? Used defanged format for IP address (4 points)
`IP:Port, lolbin.exe`

4) Hunt for Collection: Which PowerShell Cmdlet was used to stage the files? In which file were the staged files saved?(3 points)
`PS-Cmdlet, name.ext`

5) Hunt for Collection: List the directories in which these files were stored in the developer’s workstation before they were staged. What was the final location of the staged file(full path)?(3 points)
`Folder1, Folder2, Target\Full\Path\StageFile.ext`

6) Hunt for Impact: Within the Lab’s user account (not the Mounted Hard Disk Image), identify the file that was modified by the attacker. What indicator of compromise (IOC) was introduced or added to this file?(4 points)
`file.ext, IOC`

7) Hunt for Impact: How many lines of code was not commited? Who was the user or author for this action?(4 points)
