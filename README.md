# PowerShell & Command Prompt Commands

> [!NOTE]
> The index **titles will be linked later** so you can reach the commands faster. **PowerShell scripts** will also be added to create an actual toolkit.

INDEX

1. GENERAL (PowerShell)
   - Get-Process
     - Show processes by name
     - Show file version info for a process
   - Start-Process
     - Start a process or executable file
   - Get-WindowsOptionalFeature
     - Check the status of the built-in Telnet Client feature
     - Install and enable the built-in Telnet Client feature
     - Disable the built-in Telnet Client feature
   - Test-NetConnection
     - Test a port on remote host
     - Test a port on remote host with advanced details
   - Get-SmbSession
     - Show active SMB sessions
   - Get-SmbOpenFile
     - Show SMB files opened by users

2. ADDS (PowerShell)
   - Get-ADUser
     - Show users of an OU
     - Export users of an OU to CSV
     - Show only enabled users of an OU
     - Export only enabled users of an OU to CSV
     - Show only disabled users of an OU
     - Export only disabled users of an OU to CSV
   - Get-ADUser + Set-ADUser
     - Edit a user's profile attribute
     - Update attributes (e.g. initials) via UPN filter
   - Get-ADGroup
     - Find groups that contain a specific word in the name
     - Show all AD groups with the number of members
   - Get-ADGroupMember
     - Show members of an AD group
   - Get-ADComputer
     - Show details of an AD computer
     - Show details for a list of AD computers
     - Export details for a list of AD computers
   - Get-ADDomainController
     - Locate the Primary DC
     - Find DC with specific services
   - Start-ADSyncSyncCycle
     - Start Azure AD Connect Sync

3. EXCHANGE (Exchange Management Shell)
   - Get-DistributionGroup
     - Show distribution group details

4. OTHER (Command Prompt)
   - Repadmin
     - Show AD replica status
     - General summary of the AD reply
   - wuauclt
     - Reset Windows Update Authorization
     - Force update detection
   - netstat
     - Show active connections and processes
     - Show keyword-filtered active connections and processes
   - query
     - Show users connected to the machine

## GENERAL (PowerShell)

## Get-Process

### Show processes by name

```powershell
Get-Process -Name "<PROCESS_NAME[]>"
```

### Show file version info for a process

```powershell
Get-Process -Name "<PROCESS_NAME[]>" -FileVersionInfo
```

## Start-Process

### Start a process or executable file

```powershell
Start-Process -FilePath "<PROCESS_NAME/FILE_PATH>"
```

## Get-WindowsOptionalFeature

### Check the status of the built-in Telnet Client feature

```powershell
Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
```

### Install and enable the built-in Telnet Client feature

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
```

### Disable the built-in Telnet Client feature

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
```

## Test-NetConnection

### Test a port on remote host

```powershell
Test-NetConnection -ComputerName "<HOSTNAME/IP>" -Port "<PORT>"
```

### Test a port on remote host with advanced details

```powershell
Test-NetConnection -ComputerName "<HOSTNAME/IP>" -Port "<PORT>" -InformationLevel "Detailed"
```

## Get-SmbSession

### Show active SMB sessions

```powershell
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
```

## Get-SmbOpenFile

### Show SMB files opened by users

```powershell
Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path, SessionId
```

## ADDS (PowerShell)

## Get-ADUser

### Show users of an OU

```powershell
Get-ADUser -Filter * -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Format-Table -AutoSize
```

### Export users of an OU to CSV

```powershell
Get-ADUser -Filter * -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Export-Csv -Path "C:\Users\<USER_NAME>\Documents\User_List.csv" -NoTypeInformation -Encoding UTF8
```

### Show only enabled users of an OU

```powershell
Get-ADUser -Filter 'Enabled -eq $true' -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Format-Table -AutoSize
```

### Export only enabled users of an OU to CSV

```powershell
Get-ADUser -Filter 'Enabled -eq $true' -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Export-Csv -Path "C:\Users\<USER_NAME>\Documents\Enabled_User_List.csv" -NoTypeInformation -Encoding UTF8
```

### Show only disabled users of an OU

```powershell
Get-ADUser -Filter 'Enabled -eq $false' -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Format-Table -AutoSize
```

### Export only disabled users of an OU to CSV

```powershell
Get-ADUser -Filter 'Enabled -eq $false' -SearchBase "OU=<OU_NAME>,OU=<OU_NAME>,DC=<SUBDOMAIN>,DC=<SLD>,DC=<TLD>" -Properties Name | Select-Object Name, Enabled, DistinguishedName | Export-Csv -Path "C:\Users\<USER_NAME>\Documents\Disabled_User_List.csv" -NoTypeInformation -Encoding UTF8
```

## Get-ADUser + Set-ADUser

### Edit a user's profile attribute

```powershell
Get-ADUser -Filter {GivenName -like "<FIRST_NAME>" -and Surname -like "<LAST_NAME>"} | Set-ADUser -title "JOB_TITLE"
```

### Update attributes (e.g. initials) via UPN filter

```powershell
Get-ADUser -Filter "UserPrincipalName -like '<E-MAIL>'" | Set-ADUser -Replace @{initials="000"}
```

## Get-ADGroup

### Find groups that contain a specific word in the name

```powershell
Get-ADGroup -Filter 'Name -like "*<KEYWORD>*"' | Select-Object Name, DistinguishedName, GroupScope, GroupCategory
```

### Show all AD groups with the number of members

```powershell
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory, @{Name="MembersCount";Expression={(Get-ADGroupMember $_ | Measure-Object).Count}} | Format-Table -AutoSize
```

## Get-ADGroupMember

### Show members of an AD group

```powershell
Get-ADGroupMember -Identity "<ADGroup>"
```

## Get-ADComputer

### Show details of an AD computer

```powershell
Get-ADComputer -Identity "<ADComputer>" -Properties Description | Select-Object Name, DNSHostName, Description | Format-Table -AutoSize
```

### Show details for a list of AD computers

```powershell
Get-Content "C:\Users\<USER_NAME>\Documents\Server_List.txt" | ForEach-Object {Get-ADComputer -Identity $_ -Properties Description | Select-Object Name, DNSHostName, Description} | Format-Table -AutoSize
```

### Export details for a list of AD computers

```powershell
Get-Content "C:\Users\<USER_NAME>\Documents\Server_List.txt" | ForEach-Object { Get-ADComputer -Identity $_ -Properties Description | Select-Object Name, DNSHostName, Description } | Export-Csv -Path "C:\Users\<USER_NAME>\Documents\Server_Output.csv" -NoTypeInformation -Encoding UTF8
```

## Get-ADDomainController

### Locate the Primary DC

```powershell
Get-ADDomainController -Discover -Service "PrimaryDC"
```

### Find DC with specific services

```powershell
Get-ADDomainController -Discover -Domain "<FQDN>" -Service "PrimaryDC", "TimeService"
```

## Start-ADSyncSyncCycle

### Start Azure AD Connect Sync

```powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

## EXCHANGE (Exchange Management Shell)

## Get-DistributionGroup

### Show distribution group details

```powershell
Get-DistributionGroup -Identity "<DistributionGroupIdParameter>" | Format-List
```

## OTHER (Command Prompt)

## Repadmin

### Show AD replica status

```bash
repadmin /showrepl
```

### General summary of the AD reply

```bash
repadmin /replsummary
```

## wuauclt

### Reset Windows Update Authorization

```bash
wuauclt.exe /resetauthorization
```

### Force update detection

```bash
wuauclt.exe /detectnow
```

## netstat

### Show active connections and processes

```bash
netstat -abno
```

### Show keyword-filtered active connections and processes

```bash
netstat -abno | findstr -i "<KEYWORD>"
```

## query

### Show users connected to the machine

```bash
query user
```
