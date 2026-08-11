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
`c:\Users\SBTuser\Desktop\Investigation\kape-findings`

# Initial discovery

# Questions

