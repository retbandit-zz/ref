## Windows Host Info Gathering

Get OS, Domain, username, active connections:

	net config workstation
	ver
	systeminfo

PowerShell:

	Get-Childitem -Path Env:* | Sort-Object Name
	$env:COMPUTERNAME
	$env:USERDOMAIN
	$env:USERNAME
	$env:HOMEDRIVE
	$env:HOMEPATH
	$env:LOGONSERVER
	$env:OS
	$env:SESSIONNAME
	$env:SYSTEMDRIVE
	$env:TEMP
	$env:ComSpec
	Tree $home 
	Copy any of the commands to clipboard with  | clip.exe (i.e.; Tree $home | clip.exe )

**WMIC:**

	wmic process list brief
	wmic group list brief
	wmic group list brief
	wmic computerystem list full /format:list  
	wmic process list /format:list  
	wmic ntdomain list /format:list  
	wmic useraccount list /format:list  
	wmic group list /format:list  
	wmic sysaccount list /format:list 

**PowerShell WMI CMDlets:**

	Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'"
	Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID
	
**PowerShell CIM CMDlets:**<BR>
https://technet.microsoft.com/en-us/itpro/powershell/windows/cimcmdlets/get-ciminstance

Local:

	Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName | FL
	Get-CimInstance -ClassName Win32_Process

Remote:
	
	Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName Server01,Server02	

Empire Module:<BR>
<https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1>

MSF:<BR>
>collects installed packages, installed services, mount information, user list, user bash history and cron jobs:

`use post/windows/gather/enum_system`

---------

## Active Connections
Find Active Connections using netstat:

	netstat -a | find “LISTENING”
	netstat -ano | find “ESTABLISHED”
	netstat -ano | find “8080”
	netstat -ano | find “udevd_pid
	netstat -ano | find “udevd"
	tasklist /svc /FI “PID eq 456″ 

Get OS, Domain, username, active connections:<BR>
`net config workstation`

---------

## Find connectable domain resources

	net view [\\computername [/CACHE] | [/ALL] | /DOMAIN[:domainname]]

---------
### Running Processes

Manually:

	wmic process list brief
	wmic process where “name like ‘%smc%.exe’”
	tasklist /s /v
	qprocess

PowerShell:

	Get-Process | Select-Object ProcessName,Id,Description,Path

Other Examples:

	tree /f (full file tree)

Kill a process:

	wmic process where “name like ‘%smc%.exe’” delete

References:

- <https://capec.mitre.org/data/definitions/573.html><BR>
- <http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html>

---------
### Installed Apps

Manually:

	wmic product get Name,Vendor

PowerShell:

	x64: Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
	x86: Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
	
Other Examples:

	meterpreter > run post/windows/gather/enum_applications 

---------

## Services
Manually:

	wmic service get name,displayname,pathname,startmode
	
List services running as SYSTEM & possibly weak file perms: 

	wmic service where StartName="LocalSystem"|findstr /IV ":\WIN :\PROG"
			
Other Examples:

	sc qc name (check service permisions)
	net start >> %temp%\download
	tasklist /svc

References/Resources:
	
- [Hackfest 2016 - Chris Nickerson : Adversarial Simulation: Why your defenders are the Fighter Pilots.](https://www.youtube.com/watch?v=flmxbKfIAE4&list=PLaXanmjyAPzF_Sa1JHpgZlHWz0_MDYTe2&index=21)<BR>
- <https://twitter.com/wincmdfu> <BR>
- <https://attack.mitre.org/wiki/Technique/T1007> 

---------

## Installed Updates

Manually

	systeminfo
	
	wmic qfe list brief
	
	wmic qfe get hotfixid, description, Installedon | findstr "Security"   
	#(This command shows limited updates, need to dive deeper into why)
		
	wmic qfe get Caption,Description,HotFixID,InstalledOn

PowerShell

	List missing updates: 
	PS C:\> (New-Object -c Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|Select Title
		
PowerShell Empire

	Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object InstalledOn -First 1
	
<https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1>
	
Metasploit Module
	
	msf > use post/windows/gather/enum_patches 
	msf post(enum_patches) > sessions ...sessions... 
	msf post(enum_patches) > set SESSION <session-id> 
	msf post(enum_patches) > show options ...show and set options... 
	msf post(enum_patches) > run 

Source/Resources:

-<http://www.rapid7.com/db/modules/post/windows/gather/enum_patches> 

---------

## Applied GPOs

View Group Policy Objects that have been applied to a system: 

	C:\> gpresult /z /h outputfile.html

## Current User Privileges

	cmd.exe /C whoami /all
	whoami /groups

---------

## Local Users

Manually:

	wmic useraccount list
	wmic useraccount list /record:users_list.xml
	net user cthompson /domain
	net localgroup Administrators
	wmic group list brief
	
	#List logged on users:
	C:\> net session | find "\\"
	
	#See who else is connected to the machine:
	query user
	
WMI:

	Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'" | Select-Object Name 
	wmic useraccount get /ALL


Preferred Tool Usage:

	Empire:
	
	#Conduct enumeration with a username and keyword
	Invoke-WindowsEnum -User "sandersb"
	https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1
	
Other Examples:

	#View user account password and logon requirements (also displays the machine type - NT Server or NT workstation)
	NET ACCOUNTS
	
	#The same command issued against a remote system in another domain looks like this:
	wmic /user:"FOREIGN_DOMAIN\Admin" /password:"Password" /node:192.168.33.25 group list brief
	
	NetUser-GetInfo
	
Source/Resources:<BR>
- <https://attack.mitre.org/wiki/Technique/T1033> 

---------

## Local Password Policy

	net accounts

---------

## File Shares

Manually:

	net share
	wmic share list

---------

## Windows Firewall

Show current status:

	netsh advfirewall show allprofiles
	netsh advfirewall show allprofiles state

Enable Firewall:

	netsh advfirewall set allprofiles state on

Disable:

	netsh advfirewall set allprofiles state off

Show rules:

	netsh advfirewall firewall dump
	netsh advfirewall firewall show rule name=all
	netsh advfirewall firewall show rule name="Windows Diagnostics"
	netsh advfirewall firewall show rule RemoteIP=54.193.27.226

Add Rule:

	netsh advfirewall firewall add rule name="Windows Diagnostics" dir=out action=block protocol=TCP localport=5986
	netsh advfirewall firewall add rule name="Windows Diagnostics" dir=out action=block service=macnmsvc
	netsh advfirewall firewall add rule name="Windows Diagnostics" dir=out action=block protocol=any RemoteIP=x.x.x.x

Allow Remote Management:

	netsh advfirewall firewall set rule group="remote administration" new enable=yes

Allow RDP:

	netsh advfirewall firewall set rule group="remotea desktop" new enable=Yes

Show config & state info for Network Access Protection (NAP) enabled client: 

	netsh nap client show configuration

References:

<https://technet.microsoft.com/en-us/library/cc732643.aspx>

---------

## Find Files

Empire:

	Invoke-WindowsEnum -keyword "putty"

<https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1> 

---------

## RDP Sessions/History

Manually:

	#Check RDP session history:
	for /f "delims=" %i in ('reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"') do reg query "%i"
		
	#Check current RDP info:
	qwinsta -ano
		
	#Enable RDP:
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	
In Empire: 

	Find-RDPClientConnections 
	
<https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Get-ComputerDetails.ps1>
		
		
This script is used to get useful information from a computer. Currently, the script gets the following information:<BR>
- Explicit Credential Logons (Event ID 4648)<BR>
- Logon events (Event ID 4624)<BR>
- AppLocker logs to find what processes are created<BR>
- PowerShell logs to find PowerShell scripts which have been executed<BR>
- RDP Client Saved Servers, which indicates what servers the user typically RDP's in to		    
This script is useful for fingerprinting a server to see who connects to this server (from where), and where users on this server connect to. You can also use it to find Powershell scripts and executables which are typically run, and then use this to backdoor those files.
			
Other Examples:

	Search for event ID 4648/4624 in Security event log
		-Explicit Credential Logons (Event ID 4648)
			Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful for identifying normal authentication patterns. Other actions that will trigger this include any runas action.
			
		-Logon events (Event ID 4624)
			Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do network logons in to the server, what accounts RDP in, what accounts log in locally, etc...
	
References/Resources:

- <https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/host/Get-ComputerDetails.ps1>

---------
## Remote Access Apps

Coming Soon

---------

## Egress Testing

The below script connects to a public website "allports.exposed" and checks ports 1-1024 TCP.

PowerShell (one liner)

	1..1024 | % {$test= new-object system.Net.Sockets.TcpClient; 
	$wait = $test.beginConnect("allports.exposed",$_,$null,$null); 
	($wait.asyncwaithandle.waitone(250,$false)); if($test.Connected)
	{echo "$_ open"}else{echo "$_ closed"}} | select-string " "

Source:<BR>
- <http://www.blackhillsinfosec.com/?p=4811> 

---

## Proxies

INTERNET_OPEN_TYPE_PRECONFIG looks at the registry values ProxyEnable, ProxyServer, and ProxyOverride. 

These values are located under "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings".

<https://msdn.microsoft.com/en-us/library/windows/desktop/aa383996(v=vs.85).aspx> 

---
