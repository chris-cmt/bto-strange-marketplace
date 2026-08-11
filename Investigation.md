
1) Hunt for Initial Access: When was the initial access? And what binary is responsible for signing the payload?(4 points)

```
c:\Users\SBTuser\Desktop\Investigation\chainsaw_x86_64-pc-windows-msvc\chainsaw>

.\chainsaw.exe search -t "Event.System.EventID: =4688" d:\C\Windows\System32\winevt\logs -- skip-errors -- output c:\Users\SBTuser\Desktop\findings\outpit.csv
```
<img width="2742" height="1362" alt="image" src="https://github.com/user-attachments/assets/aeee2a9f-9252-4279-983c-836d0e9e1057" />
<img width="2951" height="1205" alt="image" src="https://github.com/user-attachments/assets/db008951-65f1-4394-bf49-3b9d77ce970d" />

---

2) Hunt for Credential Access: The attacker has accessed a file containing credentials in plain text. Identify the file name, user, and password that’s been stolen.(3 points)

Manual investigation of the disk image, found the file. credentials.txt, admin:hunter2

<img width="1269" height="934" alt="image" src="https://github.com/user-attachments/assets/299f2c0e-84d0-4517-b9bb-443e8254e6bb" />

---

3) Hunt for Data Exfiltration: An attempt was made to exfiltrate this data. What IP and Port did the attacker use for C2 communication? What Living-of-the-Land binary was used? Used defanged format for IP address (4 points)
 
Too many IP addresses and false positives with the following
```
c:\Users\SBTuser\Desktop\Investigation\chainsaw_x86_64-pc-windows-msvc\chainsaw>. \chainsaw.exe search -e "\b\d{1, 3}\.\d{1, 3}\.\d{1,3}\.\d{1,3}\b" d:\C\Windows\System32\winevt\logs -- skip-errors >> c:\Users\SBTuser\Desktop\IP-address.txt
```

Searched via network commands/related events
```
.\chainsaw.exe search -e "(?i)(wget|certutil|ping|nslookup|Test-NetConnection|Invoke-WebRequest|http|tcp)" d:\C\Windows\System32\winevt\logs\ --timestamp "2025-03-27T14:25:00" --skip-errors > c:\Users\SBTuser\Desktop\Network-strings.txt

.\chainsaw.exe search -e "(?i)(powershell|certutil|curl|wget|desktopimgdownldr).*\.exe" "C:\Windows\System32\winevt\logs\"

.\chainsaw.exe search -e "(?i)(curl|wget|ping|nslookup|Test-NetConnection|Invoke-WebRequest|http|tcp)" "D:\C\Windows\System32\winevt\logs\" --from "2025-03-27T14:25:00" --skip-errors >> c:\Users\SBTuser\Desktop\Network-strings.txt

```

Used Notepad++ to filter on the file Network-strings.txt
- Ctrl + H
- Regex to search for an IP address
- `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`

<img width="2753" height="758" alt="image" src="https://github.com/user-attachments/assets/7d646c88-a68f-4902-af3c-101bf55fb58c" />

- 165{.]22[.]189[.]77:80, certutil.exe
  
---

4) Hunt for Collection: Which PowerShell Cmdlet was used to stage the files? In which file were the staged files saved?(3 points)

Hunting with Notepad++ again on the file Network-strings.txt
- Ctrl + F
- Search for all Compress
Compress-Archive, dump.zip

---

5) Hunt for Collection: List the directories in which these files were stored in the developer’s workstation before they were staged. What was the final location of the staged file(full path)?(3 points)

Hunting with Notepad++ again on the file Network-strings.txt
- DeveloperLab, Projects, C:\Users\SBTuser\AppData\Local\Temp\Dump.zip

---

6) Hunt for Impact: Within the Lab’s user account (not the Mounted Hard Disk Image), identify the file that was modified by the attacker. What indicator of compromise (IOC) was introduced or added to this file?(4 points)
`file.ext, IOC`
Ran the following command to search for a file that was written by the attacker
```
C:\Users\SBTuser\Desktop\Investigation\chainsaw_x86_64-pc-windows-msvc\chainsaw>. \chainsaw.exe search -e "(?i)git .*. (txt|json|js)" c:\Windows\System32\winevt \logs -o c:\Users\SBTuser\Desktop\localhost.txt
```

<img width="1058" height="178" alt="image" src="https://github.com/user-attachments/assets/6d16913b-28be-4e7a-b250-ccb32ccd4537" />

<img width="1048" height="622" alt="image" src="https://github.com/user-attachments/assets/2615d92c-1268-4cee-84d2-f50d69547c59" />

<img width="1062" height="717" alt="image" src="https://github.com/user-attachments/assets/51e9b80e-c405-4e44-99da-3ded900b8d92" />
File was modified at a different time

- Gruntfile.js, https://discord.com/api/webhook/nnvwnficnalc/Thisiswebhook

---

7) Hunt for Impact: How many lines of code was not commited? Who was the user or author for this action?(4 points)

Changed into the directory and checked the diff

<img width="1438" height="293" alt="image" src="https://github.com/user-attachments/assets/f81e359e-c1e6-4cdf-b0e1-0244be8e1f8e" />

Username and password was not accepting, searched the localhost.txt file for the answer

<img width="1733" height="658" alt="image" src="https://github.com/user-attachments/assets/1a3a01c7-cb2c-4219-af57-e472f947b17b" />


---

# Interesting observations
```
Search for strings .\chainsaw.exe search -e "(?i)(type|cat|Get-Content|password|creds).*.(txt|csv|json|cfg)" "D:\C\Windows\System32\winevt\logs" --from "2025-03-27T14:25:00" --to "2025-03-27T15:25:00" --csv -o C:\DFIR\Chainsaw_Filtered\

d:\C\Windows\System32\winevt\logs --skip-errors >> c:\Users\SBTuser\Desktop\IP-address.txt

Search for strings relating to network .\chainsaw.exe search -e "(?i)(curl|wget|ping|nslookup|Test-NetConnection|Invoke-WebRequest|http|tcp)" d:\C\Windows\System32\winevt\logs\ --timestamp "2025-03-27T14:25:00" --skip-errors >> c:\Users\SBTuser\Desktop\Network-strings.txt

Command
'"C:\Windows\system32\net.exe" share test=C:\Users\SBTUser\AppData\Local\Temp /GRANT:Everyone,FULL'
```
