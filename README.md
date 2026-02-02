# Cyber Deception Walkthrough: Canary Deployment on Windows Systems

## Table of Contents
- [Introduction](#introduction)
- [Why Cyber Deception?](#why-cyber-deception)
- [Prerequisites](#prerequisites)
- [Canary Accounts](#canary-accounts)
- [Canary Files](#canary-files)
- [Canary Shares](#canary-shares)
- [Canary SPNs (Kerberoasting Detection)](#canary-spns-kerberoasting-detection)
- [Auditing Configuration](#auditing-configuration)
- [Group Policy Configuration](#group-policy-configuration)
- [Windows Event IDs for SIEM Detection](#windows-event-ids-for-siem-detection)
- [SIEM Detection Rules](#siem-detection-rules)
- [Deployment Scenarios](#deployment-scenarios)
- [Best Practices](#best-practices)
- [References](#references)

---

## Introduction

Cyber deception is a proactive defense strategy that deploys decoy assets (canaries, honeypots, honeytokens) throughout your environment to detect adversary presence. Unlike traditional security tools that rely on signatures or known malicious behavior, deception techniques detect attackers by monitoring access to resources that have **no legitimate business purpose**.

**Key Principle:** Any interaction with a canary asset is inherently suspicious because legitimate users and processes have no reason to access them.

---

## Why Cyber Deception?

### Limitations of Traditional Security Tools

| Traditional Tool | Limitation |
|------------------|------------|
| Antivirus/EDR | Relies on signatures; can be bypassed with custom malware |
| Firewalls | Cannot detect lateral movement within trusted networks |
| IDS/IPS | Generates false positives; misses novel attack techniques |
| SIEM | Only as good as the logs collected; alert fatigue |

### Advantages of Cyber Deception

- **Low False Positive Rate:** Canaries have no legitimate use, so any access is suspicious
- **Detects Unknown Threats:** Works against zero-days, custom malware, and living-off-the-land techniques
- **Early Warning System:** Detects reconnaissance and lateral movement early in the kill chain
- **Attacker Attribution:** Provides insight into attacker TTPs and objectives
- **Cost Effective:** Minimal infrastructure and maintenance requirements
- **Works Against Insider Threats:** Detects both external attackers and malicious insiders

---

## Prerequisites

### Required Permissions

| Environment | Required Role |
|-------------|---------------|
| Domain Controller | Domain Admin or Enterprise Admin |
| Domain-Joined Server/Workstation | Local Administrator + Domain privileges for auditing |
| Standalone Server/Workstation | Local Administrator |

### Tools Needed

- PowerShell (Run as Administrator)
- Active Directory Users and Computers (ADUC) - Domain environments
- Group Policy Management Console (GPMC) - Domain environments
- Local Security Policy (secpol.msc) - Standalone systems
- Advanced Security Audit Policy Configuration

---

## Canary Accounts

Canary accounts are fake user accounts designed to attract attackers performing credential harvesting, enumeration, or lateral movement.

### Naming Strategy

Choose names that appear valuable to attackers:

```
svc_backup
svc_sql
admin_temp
helpdesk_admin
svc_scanner
IT_Admin
Domain_Admin_Backup
svc_azure_sync
emergency_admin
```

### Domain Environment Setup

#### Creating the Canary Account

```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Create canary account with enticing properties
New-ADUser -Name "svc_backup" `
    -SamAccountName "svc_backup" `
    -UserPrincipalName "svc_backup@domain.local" `
    -Description "Backup Service Account - DO NOT DELETE" `
    -DisplayName "Backup Service Account" `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -CannotChangePassword $true `
    -AccountPassword (ConvertTo-SecureString "C0mpl3x_P@ssw0rd_2024!" -AsPlainText -Force) `
    -Path "OU=Service Accounts,DC=domain,DC=local"

# Add to enticing groups (but not actually privileged)
Add-ADGroupMember -Identity "Backup Operators" -Members "svc_backup"

# Set additional attributes to make it look valuable
Set-ADUser -Identity "svc_backup" -Add @{
    'adminDescription' = 'Critical backup infrastructure account'
    'info' = 'Contact IT Security before modifying'
}
```

#### Making the Account Discoverable (But Not Usable)

```powershell
# Option 1: Disable the account but keep it visible
Disable-ADAccount -Identity "svc_backup"

# Option 2: Set logon restrictions (cannot logon anywhere)
Set-ADUser -Identity "svc_backup" -LogonWorkstations "YOURDOMAINCONTROLLER"

# Option 3: Set expired password (account exists but can't authenticate)
Set-ADAccountExpiration -Identity "svc_backup" -DateTime (Get-Date).AddDays(-1)
```

### Standalone/Workgroup Environment Setup

```powershell
# Create local canary account
$Password = ConvertTo-SecureString "C0mpl3x_P@ssw0rd_2024!" -AsPlainText -Force
New-LocalUser -Name "svc_backup" `
    -Password $Password `
    -Description "Backup Service Account" `
    -PasswordNeverExpires $true `
    -UserMayNotChangePassword $true

# Add to Administrators group (for attractiveness)
Add-LocalGroupMember -Group "Administrators" -Member "svc_backup"

# Disable the account
Disable-LocalUser -Name "svc_backup"
```

### Auditing Canary Account Access

#### Configure SACL on the Account (Domain)

```powershell
# Get the canary account
$CanaryAccount = Get-ADUser -Identity "svc_backup"
$CanaryDN = $CanaryAccount.DistinguishedName

# Get the current ACL
$ACL = Get-Acl "AD:\$CanaryDN"

# Create audit rule for all access
$AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    [System.Security.Principal.SecurityIdentifier]"S-1-1-0",  # Everyone
    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add the audit rule
$ACL.AddAuditRule($AuditRule)
Set-Acl "AD:\$CanaryDN" $ACL

Write-Host "SACL configured for canary account: $CanaryDN"
```

#### GUI Method for SACL Configuration

1. Open **Active Directory Users and Computers**
2. Enable **View > Advanced Features**
3. Right-click the canary account > **Properties** > **Security** > **Advanced**
4. Go to the **Auditing** tab
5. Click **Add** and configure:
   - Principal: **Everyone**
   - Type: **Success**
   - Applies to: **This object only**
   - Permissions: **Read all properties**, **Read permissions**

---

## Canary Files

Canary files are decoy documents placed in strategic locations to detect unauthorized file access, data exfiltration attempts, or ransomware activity.

### File Naming Strategy

Create files with names that attract attackers:

```
passwords.xlsx
credentials.txt
employee_ssn.csv
financial_records_2024.xlsx
admin_passwords.docx
network_diagram.pdf
vpn_credentials.txt
bitcoin_wallet.txt
customer_database_backup.sql
hr_salaries_confidential.xlsx
```

### File Placement Locations

| Location | Purpose |
|----------|---------|
| `C:\Users\Administrator\Desktop\` | Attracts attackers with admin access |
| `C:\Users\Public\Documents\` | Visible to all users |
| `\\server\share\IT\` | Network share commonly targeted |
| `C:\inetpub\wwwroot\backup\` | Web server sensitive area |
| `C:\Program Files\` | Unusual location, detects deep enumeration |
| User home directories | Detects lateral movement |

### Creating Canary Files

```powershell
# Define canary file locations
$CanaryLocations = @(
    "C:\Users\Public\Documents\passwords.xlsx",
    "C:\Users\Public\Documents\admin_credentials.txt",
    "C:\Users\Administrator\Desktop\network_diagram.pdf",
    "C:\Shares\IT\vpn_credentials.txt"
)

# Create convincing fake content
$FakeContent = @"
=== CONFIDENTIAL - DO NOT DISTRIBUTE ===
VPN Credentials
Server: vpn.company.com
Username: admin
Password: [CONTACT IT SECURITY]
Last Updated: 2024-01-15
"@

foreach ($Path in $CanaryLocations) {
    # Ensure directory exists
    $Directory = Split-Path -Path $Path -Parent
    if (!(Test-Path $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force
    }

    # Create the canary file
    Set-Content -Path $Path -Value $FakeContent

    Write-Host "Created canary file: $Path"
}
```

### Configuring File Auditing (SACL)

```powershell
# Function to set SACL on a file
function Set-CanaryFileAudit {
    param(
        [string]$FilePath
    )

    # Get current ACL
    $ACL = Get-Acl -Path $FilePath

    # Create audit rule for Everyone - Read access
    $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "Read, ReadData",
        "Success, Failure"
    )

    # Add the audit rule
    $ACL.AddAuditRule($AuditRule)

    # Apply the ACL
    Set-Acl -Path $FilePath -AclObject $ACL

    Write-Host "Audit rule set for: $FilePath"
}

# Apply to all canary files
foreach ($Path in $CanaryLocations) {
    if (Test-Path $Path) {
        Set-CanaryFileAudit -FilePath $Path
    }
}
```

### GUI Method for File SACL

1. Right-click the canary file > **Properties**
2. Go to **Security** > **Advanced** > **Auditing**
3. Click **Add**
4. Configure:
   - Principal: **Everyone**
   - Type: **Success** and **Failure**
   - Basic Permissions: **Read & execute**, **Read**
5. Click **OK** and apply

---

## Canary Shares

Canary shares are fake network shares designed to detect lateral movement and network enumeration.

### Share Naming Strategy

```
\\server\IT_Admin$
\\server\Backup_Archive
\\server\HR_Confidential
\\server\Finance_Reports
\\server\Executive_Data
\\server\Password_Vault
\\server\Domain_Backup
```

### Creating a Canary Share

```powershell
# Create the folder for the share
$SharePath = "C:\CanaryShares\IT_Admin"
New-Item -ItemType Directory -Path $SharePath -Force

# Create some decoy files in the share
$DecoyFiles = @(
    "domain_admin_passwords.txt",
    "server_inventory.xlsx",
    "network_credentials.docx"
)

foreach ($File in $DecoyFiles) {
    $Content = "=== CONFIDENTIAL - IT USE ONLY ==="
    Set-Content -Path (Join-Path $SharePath $File) -Value $Content
}

# Create the SMB share
New-SmbShare -Name "IT_Admin$" `
    -Path $SharePath `
    -Description "IT Administration Files" `
    -FullAccess "Domain Admins" `
    -ReadAccess "Authenticated Users"

Write-Host "Canary share created: \\$env:COMPUTERNAME\IT_Admin$"
```

### Hidden Share Detection (Dollar Sign Shares)

Hidden shares (ending with `$`) won't appear in network browsing but will be discovered by tools like:
- `net view \\server /all`
- BloodHound
- PowerView
- CrackMapExec

### Configuring Share Auditing

```powershell
# Enable auditing on the share folder
$SharePath = "C:\CanaryShares\IT_Admin"
$ACL = Get-Acl -Path $SharePath

# Create comprehensive audit rule
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Read, ListDirectory, ReadAttributes, ReadExtendedAttributes",
    "ContainerInherit, ObjectInherit",
    "None",
    "Success"
)

$ACL.AddAuditRule($AuditRule)
Set-Acl -Path $SharePath -AclObject $ACL

Write-Host "Share auditing configured for: $SharePath"
```

### Auditing SMB Access via GPO

This must be enabled via Group Policy to capture network share access events.

---

## Canary SPNs (Kerberoasting Detection)

Service Principal Names (SPNs) associated with user accounts are prime targets for Kerberoasting attacks. Canary SPNs detect when attackers request service tickets for offline cracking.

### Understanding the Attack

1. Attacker enumerates user accounts with SPNs
2. Requests TGS tickets for those SPNs
3. Extracts tickets and cracks them offline
4. Canary SPNs have no real service—any ticket request is malicious

### Creating a Canary SPN Account

```powershell
# Create the canary service account
New-ADUser -Name "svc_sqlreport" `
    -SamAccountName "svc_sqlreport" `
    -UserPrincipalName "svc_sqlreport@domain.local" `
    -Description "SQL Reporting Services Account" `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -AccountPassword (ConvertTo-SecureString "Sup3r_C0mpl3x_P@ssw0rd_2024!!" -AsPlainText -Force) `
    -Path "OU=Service Accounts,DC=domain,DC=local"

# Register a fake SPN
Set-ADUser -Identity "svc_sqlreport" -ServicePrincipalNames @{
    Add = "MSSQLSvc/sqlreport.domain.local:1433",
         "MSSQLSvc/sqlreport.domain.local"
}

# Verify SPN registration
Get-ADUser -Identity "svc_sqlreport" -Properties ServicePrincipalNames |
    Select-Object Name, ServicePrincipalNames
```

### Multiple Canary SPNs for Different Services

```powershell
# Array of canary SPN configurations
$CanarySPNs = @(
    @{
        Name = "svc_sqlbackup"
        SPN = "MSSQLSvc/sqlbackup.domain.local:1433"
        Description = "SQL Backup Service"
    },
    @{
        Name = "svc_iis_admin"
        SPN = "HTTP/iis-admin.domain.local"
        Description = "IIS Administration Service"
    },
    @{
        Name = "svc_exchange"
        SPN = "exchangeMDB/exchange01.domain.local"
        Description = "Exchange Mailbox Service"
    }
)

foreach ($Config in $CanarySPNs) {
    # Create account
    New-ADUser -Name $Config.Name `
        -SamAccountName $Config.Name `
        -Description $Config.Description `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -AccountPassword (ConvertTo-SecureString "C@nary_$(Get-Random -Maximum 99999)!" -AsPlainText -Force) `
        -Path "OU=Service Accounts,DC=domain,DC=local"

    # Set SPN
    Set-ADUser -Identity $Config.Name -ServicePrincipalNames @{Add = $Config.SPN}

    Write-Host "Created canary SPN account: $($Config.Name) with SPN: $($Config.SPN)"
}
```

### Detecting Kerberoasting Attempts

When an attacker requests a TGS ticket for a canary SPN, Event ID **4769** is generated on the Domain Controller.

**Key Detection Logic:**
- Event ID 4769 where Service Name = canary account
- Ticket Encryption Type = 0x17 (RC4) indicates potential Kerberoasting
- Any TGS request for canary SPN = immediate alert

---

## Auditing Configuration

### Required Audit Policies

#### Domain Controller Audit Policy

```powershell
# These settings should be applied via GPO for persistence

# Account Logon Events
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# DS Access
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

#### Standalone System Audit Policy

```powershell
# Object Access
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

### Verifying Audit Configuration

```powershell
# View all audit policy settings
auditpol /get /category:*

# Export audit policy for documentation
auditpol /backup /file:C:\AuditPolicy_Backup.csv
```

---

## Group Policy Configuration

### Creating a Canary Detection GPO

#### GPO Settings Path

```
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Advanced Audit Policy Configuration
                └── Audit Policies
```

### Required GPO Audit Settings

#### Account Logon

| Setting | Configuration |
|---------|---------------|
| Audit Credential Validation | Success and Failure |
| Audit Kerberos Authentication Service | Success and Failure |
| Audit Kerberos Service Ticket Operations | Success and Failure |

#### Account Management

| Setting | Configuration |
|---------|---------------|
| Audit User Account Management | Success and Failure |
| Audit Security Group Management | Success and Failure |

#### DS Access (Domain Controllers)

| Setting | Configuration |
|---------|---------------|
| Audit Directory Service Access | Success |
| Audit Directory Service Changes | Success |

#### Logon/Logoff

| Setting | Configuration |
|---------|---------------|
| Audit Logon | Success and Failure |
| Audit Account Lockout | Success and Failure |
| Audit Special Logon | Success |

#### Object Access

| Setting | Configuration |
|---------|---------------|
| Audit File System | Success |
| Audit File Share | Success |
| Audit Detailed File Share | Success |
| Audit Handle Manipulation | Success |

### PowerShell GPO Creation

```powershell
# Create new GPO for canary detection
$GPOName = "Canary Detection Audit Policy"
$GPO = New-GPO -Name $GPOName -Comment "Audit policy for cyber deception canary assets"

# Link GPO to domain (or specific OUs)
New-GPLink -Name $GPOName -Target "DC=domain,DC=local" -LinkEnabled Yes

Write-Host "GPO '$GPOName' created. Configure audit settings via GPMC."
```

### Applying GPO to Specific Systems

```powershell
# Link to specific OU containing servers
New-GPLink -Name "Canary Detection Audit Policy" -Target "OU=Servers,DC=domain,DC=local"

# Link to workstations OU
New-GPLink -Name "Canary Detection Audit Policy" -Target "OU=Workstations,DC=domain,DC=local"

# Force GPO update on target systems
Invoke-GPUpdate -Computer "Server01" -Force
```

---

## Windows Event IDs for SIEM Detection

### Critical Event IDs for Canary Detection

| Event ID | Log | Description | Canary Use Case |
|----------|-----|-------------|-----------------|
| **4624** | Security | Successful logon | Canary account logon attempt |
| **4625** | Security | Failed logon | Canary account auth failure |
| **4634** | Security | Account logoff | Canary account session end |
| **4648** | Security | Explicit credential logon | Canary creds used explicitly |
| **4656** | Security | Handle to object requested | Canary file/folder access |
| **4658** | Security | Handle to object closed | Canary file access completed |
| **4660** | Security | Object deleted | Canary file deletion |
| **4663** | Security | Object access attempt | Canary file read/write |
| **4670** | Security | Permissions changed | Canary object ACL modified |
| **4768** | Security | Kerberos TGT requested | Canary account AS-REQ |
| **4769** | Security | Kerberos TGS requested | **Kerberoasting detection** |
| **4770** | Security | Kerberos TGS renewed | Canary SPN ticket renewal |
| **4771** | Security | Kerberos pre-auth failed | Canary account auth failure |
| **4776** | Security | NTLM authentication | Canary account NTLM use |
| **4798** | Security | User's local group enum | Account enumeration |
| **4799** | Security | Security group enum | Group enumeration |
| **5140** | Security | Network share accessed | Canary share access |
| **5142** | Security | Network share created | Share enumeration |
| **5143** | Security | Network share modified | Share modification |
| **5145** | Security | Detailed share access | **Canary share file access** |

### Event ID Deep Dive

#### Event 4769 - Kerberos Service Ticket Request (Kerberoasting)

```xml
<Event>
  <System>
    <EventID>4769</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_sqlreport$</Data>
    <Data Name="ServiceName">svc_sqlreport</Data>
    <Data Name="TicketEncryptionType">0x17</Data>  <!-- RC4 = Kerberoast indicator -->
    <Data Name="IpAddress">::ffff:192.168.1.100</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>
```

**Detection Logic:**
- ServiceName matches canary SPN account
- TicketEncryptionType 0x17 (RC4) = legacy/weak encryption
- Any request = immediate alert (no legitimate use)

#### Event 4663 - Object Access (File)

```xml
<Event>
  <System>
    <EventID>4663</EventID>
  </System>
  <EventData>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="ObjectName">C:\Users\Public\Documents\passwords.xlsx</Data>
    <Data Name="AccessList">%%4416</Data>  <!-- ReadData -->
    <Data Name="ProcessName">C:\Windows\explorer.exe</Data>
  </EventData>
</Event>
```

#### Event 5145 - Detailed File Share Access

```xml
<Event>
  <System>
    <EventID>5145</EventID>
  </System>
  <EventData>
    <Data Name="SubjectUserName">attacker</Data>
    <Data Name="ShareName">\\*\IT_Admin$</Data>
    <Data Name="RelativeTargetName">domain_admin_passwords.txt</Data>
    <Data Name="AccessMask">0x1</Data>  <!-- Read -->
    <Data Name="IpAddress">192.168.1.100</Data>
  </EventData>
</Event>
```

---

## SIEM Detection Rules

### Splunk Detection Queries

#### Canary Account Authentication

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4776)
(TargetUserName="svc_backup" OR TargetUserName="svc_sqlreport" OR TargetUserName="admin_temp")
| stats count by EventCode, TargetUserName, IpAddress, WorkstationName
| sort -count
```

#### Kerberoasting Detection (Canary SPN)

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4769
ServiceName IN ("svc_sqlreport", "svc_sqlbackup", "svc_iis_admin")
| eval encryption_type=case(
    TicketEncryptionType="0x17", "RC4 (Kerberoast Indicator)",
    TicketEncryptionType="0x12", "AES256",
    TicketEncryptionType="0x11", "AES128",
    true(), TicketEncryptionType
)
| table _time, ServiceName, TargetUserName, IpAddress, encryption_type
```

#### Canary File Access

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4663
ObjectName IN (
    "C:\\Users\\Public\\Documents\\passwords.xlsx",
    "C:\\Users\\Public\\Documents\\admin_credentials.txt",
    "C:\\Shares\\IT\\vpn_credentials.txt"
)
| table _time, SubjectUserName, ObjectName, ProcessName, AccessList
```

#### Canary Share Access

```spl
index=windows sourcetype=WinEventLog:Security EventCode=5145
ShareName="\\\\*\\IT_Admin$"
| table _time, SubjectUserName, ShareName, RelativeTargetName, IpAddress, AccessMask
```

### Microsoft Sentinel (KQL) Detection Rules

#### Canary Account Authentication

```kql
SecurityEvent
| where EventID in (4624, 4625, 4648, 4776)
| where TargetUserName in ("svc_backup", "svc_sqlreport", "admin_temp")
| project TimeGenerated, EventID, TargetUserName, IpAddress, WorkstationName, LogonType
| order by TimeGenerated desc
```

#### Kerberoasting Detection

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName in ("svc_sqlreport", "svc_sqlbackup", "svc_iis_admin")
| extend EncryptionType = case(
    TicketEncryptionType == "0x17", "RC4-Kerberoast",
    TicketEncryptionType == "0x12", "AES256",
    TicketEncryptionType == "0x11", "AES128",
    TicketEncryptionType
)
| project TimeGenerated, ServiceName, TargetUserName, IpAddress, EncryptionType
```

#### Canary File Access

```kql
SecurityEvent
| where EventID == 4663
| where ObjectName has_any ("passwords.xlsx", "admin_credentials.txt", "vpn_credentials.txt")
| project TimeGenerated, SubjectUserName, ObjectName, ProcessName, AccessList
```

### Elastic Security Detection Rules

#### Canary Account Login

```json
{
  "rule": {
    "name": "Canary Account Authentication Attempt",
    "description": "Detects authentication attempts to canary accounts",
    "severity": "critical",
    "query": "event.code:(4624 or 4625 or 4648) and winlog.event_data.TargetUserName:(svc_backup or svc_sqlreport or admin_temp)"
  }
}
```

---

## Deployment Scenarios

### Scenario 1: Domain-Joined Server

```powershell
# Complete deployment script for domain-joined server

# 1. Create canary local account
$Password = ConvertTo-SecureString "L0c@l_C@nary_2024!" -AsPlainText -Force
New-LocalUser -Name "svc_backup_local" -Password $Password -Description "Backup Service"
Disable-LocalUser -Name "svc_backup_local"

# 2. Create canary files
$CanaryDir = "C:\CanaryFiles"
New-Item -ItemType Directory -Path $CanaryDir -Force

$Files = @("passwords.txt", "admin_creds.xlsx", "network_diagram.pdf")
foreach ($File in $Files) {
    Set-Content -Path "$CanaryDir\$File" -Value "CONFIDENTIAL DATA"

    # Set SACL
    $ACL = Get-Acl "$CanaryDir\$File"
    $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "Read", "Success"
    )
    $ACL.AddAuditRule($AuditRule)
    Set-Acl "$CanaryDir\$File" $ACL
}

# 3. Create canary share
New-SmbShare -Name "Backup_Admin$" -Path $CanaryDir -ReadAccess "Authenticated Users"

# 4. Enable audit policies
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

Write-Host "Domain server canary deployment complete"
```

### Scenario 2: Standalone Workstation

```powershell
# Complete deployment for standalone workstation

# 1. Create canary account
$Password = ConvertTo-SecureString "St@nd@l0ne_2024!" -AsPlainText -Force
New-LocalUser -Name "helpdesk_admin" -Password $Password -Description "Helpdesk Admin Account"
Add-LocalGroupMember -Group "Administrators" -Member "helpdesk_admin"
Disable-LocalUser -Name "helpdesk_admin"

# 2. Create canary files in user-accessible locations
$Locations = @(
    "C:\Users\Public\Documents",
    "C:\Users\Public\Desktop"
)

foreach ($Location in $Locations) {
    $FilePath = Join-Path $Location "IT_Credentials.txt"
    Set-Content -Path $FilePath -Value "VPN: admin/P@ssw0rd123"

    # Configure SACL
    $ACL = Get-Acl $FilePath
    $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "Read, ReadData", "Success"
    )
    $ACL.AddAuditRule($AuditRule)
    Set-Acl $FilePath $ACL
}

# 3. Enable local audit policy
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

Write-Host "Standalone workstation canary deployment complete"
```

### Scenario 3: Domain Controller

```powershell
# Complete deployment for Domain Controller

# 1. Create canary domain accounts
$CanaryAccounts = @(
    @{Name="svc_backup"; Desc="Enterprise Backup Service"},
    @{Name="svc_sqlprod"; Desc="SQL Production Service"},
    @{Name="admin_emergency"; Desc="Emergency Admin Account"}
)

foreach ($Account in $CanaryAccounts) {
    New-ADUser -Name $Account.Name `
        -SamAccountName $Account.Name `
        -Description $Account.Desc `
        -Enabled $false `
        -PasswordNeverExpires $true `
        -AccountPassword (ConvertTo-SecureString "C@nary_$(Get-Random)!" -AsPlainText -Force) `
        -Path "OU=Service Accounts,DC=domain,DC=local"
}

# 2. Create canary SPNs
Set-ADUser -Identity "svc_sqlprod" -ServicePrincipalNames @{
    Add = "MSSQLSvc/sql-prod.domain.local:1433"
}
Enable-ADAccount -Identity "svc_sqlprod"

# 3. Configure SACL on canary accounts
foreach ($Account in $CanaryAccounts) {
    $User = Get-ADUser -Identity $Account.Name
    $DN = $User.DistinguishedName

    # Set audit on the account object
    $ACL = Get-Acl "AD:\$DN"
    $AuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        [System.Security.Principal.SecurityIdentifier]"S-1-1-0",
        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AuditFlags]::Success,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    )
    $ACL.AddAuditRule($AuditRule)
    Set-Acl "AD:\$DN" $ACL
}

# 4. Enable DC audit policies via auditpol
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

Write-Host "Domain Controller canary deployment complete"
```

---

## Best Practices

### Naming Conventions

| Do | Don't |
|----|-------|
| Use realistic service account names | Use obviously fake names like "honeypot" |
| Include common prefixes (svc_, admin_) | Make them stand out from real accounts |
| Use names that suggest privilege | Use names that suggest they're traps |

### Placement Strategy

1. **Defense in Depth:** Place canaries at multiple layers
   - Network (shares)
   - Endpoint (files)
   - Identity (accounts, SPNs)

2. **Strategic Locations:**
   - High-value target systems
   - Common lateral movement paths
   - Administrative workstations
   - File servers

3. **Blend In:** Canaries should look like legitimate assets

### Maintenance

- **Regular Review:** Check canary alerts monthly
- **Update Content:** Refresh file dates periodically
- **Document Everything:** Maintain inventory of all canaries
- **Test Alerts:** Verify detection rules quarterly

### Documentation Template

```markdown
## Canary Asset Inventory

| Asset Name | Type | Location | Created | Owner | SIEM Rule |
|------------|------|----------|---------|-------|-----------|
| svc_backup | Account | AD | 2024-01-15 | Security Team | CR-001 |
| passwords.xlsx | File | \\server\share | 2024-01-15 | Security Team | CR-002 |
| IT_Admin$ | Share | Server01 | 2024-01-15 | Security Team | CR-003 |
| svc_sqlreport | SPN | AD | 2024-01-15 | Security Team | CR-004 |
```

### Alert Response Playbook

1. **Triage:** Verify the alert is not a false positive (should be rare)
2. **Contain:** Identify the source system and user
3. **Investigate:** Determine scope of compromise
4. **Eradicate:** Remove attacker access
5. **Recover:** Restore affected systems
6. **Lessons Learned:** Update defenses

---

## References

### Microsoft Documentation
- [Advanced Security Audit Policy Settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
- [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)

### MITRE ATT&CK References
- [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1558.003 - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)

### Additional Resources
- [SANS - Honeypots and Deception](https://www.sans.org/white-papers/41)
- [SpecterOps - BloodHound](https://bloodhound.readthedocs.io/)
- [Canary Tokens](https://canarytokens.org/)

---

## Quick Reference Card

### Essential Event IDs

```
4624 - Successful logon (canary account)
4625 - Failed logon (canary account)
4663 - File access (canary files)
4769 - TGS request (canary SPN - Kerberoasting)
5145 - Share access (canary shares)
```

### Essential Audit Policies

```
auditpol /set /subcategory:"File System" /success:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### Quick Detection Query (Splunk)

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4769 ServiceName="svc_*canary*") OR
(EventCode=4663 ObjectName="*password*") OR
(EventCode=5145 ShareName="*Admin$") OR
(EventCode=4624 TargetUserName="svc_backup")
| table _time, EventCode, TargetUserName, ObjectName, ServiceName, IpAddress
```

---

*Last Updated: January 2024*
*Author: Security Operations Team*
*Version: 1.0*
