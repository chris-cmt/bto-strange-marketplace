
1) Hunt for Initial Access: When was the initial access? And what binary is responsible for signing the payload?(4 points)

```
c:\Users\SBTuser\Desktop\Investigation\chainsaw_x86_64-pc-windows-msvc\chainsaw>

.\chainsaw.exe search -t "Event.System.EventID: =4688" d:\C\Windows\System32\winevt\logs -- skip-errors -- output c:\Users\SBTuser\Desktop\findings\outpit.csv
```
<img width="2742" height="1362" alt="image" src="https://github.com/user-attachments/assets/aeee2a9f-9252-4279-983c-836d0e9e1057" />
<img width="2951" height="1205" alt="image" src="https://github.com/user-attachments/assets/db008951-65f1-4394-bf49-3b9d77ce970d" />



3) Hunt for Credential Access: The attacker has accessed a file containing credentials in plain text. Identify the file name, user, and password that’s been stolen.(3 points)

Manual investigation of the FS. credentials.txt, admin:hunter2

4) Hunt for Data Exfiltration: An attempt was made to exfiltrate this data. What IP and Port did the attacker use for C2 communication? What Living-of-the-Land binary was used? Used defanged format for IP address (4 points)
`IP:Port, lolbin.exe`

5) Hunt for Collection: Which PowerShell Cmdlet was used to stage the files? In which file were the staged files saved?(3 points)
`PS-Cmdlet, name.ext`

6) Hunt for Collection: List the directories in which these files were stored in the developer’s workstation before they were staged. What was the final location of the staged file(full path)?(3 points)
`Folder1, Folder2, Target\Full\Path\StageFile.ext`

7) Hunt for Impact: Within the Lab’s user account (not the Mounted Hard Disk Image), identify the file that was modified by the attacker. What indicator of compromise (IOC) was introduced or added to this file?(4 points)
`file.ext, IOC`

8) Hunt for Impact: How many lines of code was not commited? Who was the user or author for this action?(4 points)
