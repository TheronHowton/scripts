<#

    .SYNOPSIS
    Download file from Azure Storage BLOB, and execute it.

    .DESCRIPTION
    Accopmplishes the following:
      - Checks for the existance of various folders and if they don't exist, it creates them.
      - Clears the ACLs of each folder and adds SYSTEM and possibly BUILTIN\Administrators with Full Control
      - Configures a Scheduled Task 
      - Downloads files from Azure Storage BLOB for use with the Scheduled Task.

    To modify a previously deployed scheduled task, update $OldScheduleTaskName, $ScheduleTaskName and the XML under #Scheduled Task XML.

    To modify the output log location, udpate $LogFilePath.

    To mofify the location of the scripts used by the scheduled task, update $ScriptFilePath and $SolutionFolder.

    If the Solution script used by the Scheduled Task has been updated, modify $Script.

    If the Azure Storage Account has been changed, modify the following accordingly:
        $AzureEndpoint
        $AzureSharedAccessSignature
        $AzureFileShare

    .PARAMETER

    .EXAMPLE

    .NOTES
    Original Author: Alex Ã˜. T. Hansen
    Current Implementation Author: Theron Howton
    Date: 2021-02-24
    Last Updated: 

    Version 1.0
#>

[CmdletBinding()]
    
Param
(
    #Run Script In Debugger Mode
    [parameter(Mandatory = $false)][bool]$DebugMode = $false
)
################################################
<# Functions - Start #>

Function Write-Log {
    [CmdletBinding()]
    
    Param
    (
        [parameter(Mandatory = $true)][string]$File,
        [parameter(Mandatory = $true)][string]$Text,
        [parameter(Mandatory = $true)][string][ValidateSet("Information", "Error", "Warning")]$Status
    )

    #Construct output.
    $Output = ("[" + (((Get-Date).ToShortDateString()) + "][" + (Get-Date).ToLongTimeString()) + "][" + $Status + "] " + $Text);
    
    #Output.
    $Output | Out-File -Encoding UTF8 -Force -FilePath $File -Append;
    Return Write-Output $Output;
}
Function Test-ScheduleTask {
    [CmdletBinding()]
    
    Param
    (
        [parameter(Mandatory = $true)][string]$Name
    )

    #Create a new schedule object.
    $Schedule = New-Object -com Schedule.Service;
    
    #Connect to the store.
    $Schedule.Connect();

    #Get schedule tak folders.
    $Task = $Schedule.GetFolder("\").GetTasks(0) | Where-Object { $_.Name -like $Name -and $_.Enabled -eq $true };

    #If the task exists and is enabled.
    If ($Task) {
        #Return true.
        Return $true;
    }
    #If the task doesn't exist.
    Else {
        #Return false.
        Return $false;
    }
}

<# Functions - End #>
################################################

<# Variables and Inputs - Start#>
$LogFilePath = "C:\Logs\Intune Management"
$ScriptFilePath = "C:\Windows\System32\Intune Management"
$SolutionFolder = "ReACL_PhysicalDrive_for_Interactive_Access"
$DebugModeOutput = "Dev"
$LogFile = ("$LogFilePath\" + "ReACL_PhysicalDrive_for_Interactive_Access-" + ((Get-Date).ToString("yyyyMMdd") + ".log"));

#Azure variables
$AzureEndpoint = 'https://ulmsdiagnosticlogs.file.core.usgovcloudapi.net';
$AzureSharedAccessSignature = '?sv=2019-10-10&ss=bfqt&srt=sco&sp=rwdlacup&se=2021-09-15T01:36:58Z&st=2020-09-14T17:36:58Z&spr=https&sig=Z1lRdxf%2BSOFCfSkhfI8GfJgs1fFawQgDYwOxqcZ0Kq4%3D';
$AzureFileShare = "bootholedetection-config";

#Scheduled Tasks
$OldScheduleTaskName = "Null";
$ScheduleTaskName = "324MGMT- Security_Microsoft-Windows-Security-Auditing_6416_V1.0";

#Scheduled Task XML
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2021-02-23T13:14:18.8938588</Date>
    <Author>Administrator</Author>
    <URI>\Event Viewer Tasks\Security_Microsoft-Windows-Security-Auditing_6416</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=6416]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "C:\Windows\System32\Intune Management\ReACL_PhysicalDrive_for_Interactive_Access\reacl_physicaldrive_for_interactive_access.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
"@ | Out-File -FilePath ("$ScheduleTaskName" + ".xml");             

#Script package and apps
$Script = "ReACL_PhysicalDrive_for_Interactive_Access.ps1";
$app1 = "WDevList.exe";
$app2 = "WDevSec.exe";

<# Variables and Inputs - End#>
################################################
<# Main - Start #>

#Create solution folders

#Create Intune Management log folder
If (!(Test-Path $LogFilePath)) {
    New-Item -ItemType Directory -Path $LogFilePath -Force | Out-Null;
    Write-Log -File $LogFile -Status Information -Text "'$LogFilePath' logs folder created.";
}

#ACL Intune Management log folder
If (Test-Path $LogFilePath) {
    $acl = Get-Acl $LogFilePath;
    $acl.SetAccessRuleProtection($true, $false);
    $AccessRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow");
    $accessRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow");
    $acl.AddAccessRule($AccessRule1);
    $acl.AddAccessRule($AccessRule2);
    $acl | Set-Acl $LogFilePath
    Write-Log -File $LogFile -Status Information -Text "'$LogFilePath' logs folder ACLed.";
}

#Clear variables
$acl = $null;
$AccessRule = $null;

#Create Intune Management scripts folder
If (!(Test-Path $ScriptFilePath)) {
    New-Item -ItemType Directory -Path $ScriptFilePath -Force;
    Write-Log -File $LogFile -Status Information -Text "'$ScriptFilePath' scripts folder created.";
}

#ACL Intune Management scripts folder
If (Test-Path $ScriptFilePath) {
    $acl = Get-Acl $ScriptFilePath;
    $acl.SetAccessRuleProtection($true, $false);
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow");
    $acl.AddAccessRule($AccessRule);
    $acl | Set-Acl $ScriptFilePath;
    Write-Log -File $LogFile -Status Information -Text "'$ScriptFilePath' scripts folder ACLed.";
}

#Create Debugmode folder if required
If ($DebugMode) {
    New-Item -ItemType Directory -Force -Path $LogFilePath\$DebugMode  | Out-Null;
    $Dev = $LogFilePath + "\" + $DebugModeOutput;
}

Write-Log -File $LogFile -Status Information -Text "Finished with solution folder creation.";

#Get hostname for logging
$Hostname = Invoke-Command { hostname };
$Hostname = $Hostname.ToUpper();

#Get public IP for logging
$PublicIP = ((Invoke-RestMethod "http://ipinfo.io/json").IP);

#Write computer info to the log file
Write-Log -File $LogFile -Status Information -Text ("Hostname: " + $Hostname);
Write-Log -File $LogFile -Status Information -Text ("PublicIP: " + $PublicIP);

################################################
#Begin configuration of solution

Write-Log -File $LogFile -Status Information -Text "Starting download request for solution files from Azure Storage.";

#Get temporary location.
$Path = $ScriptFilePath;

If ($DebugMode) {
    $Path = "$Dev";
}

#Remove existing from $Path and request new script/apps from Azure Storage.
Remove-Item ($Path + "\" + $Script) -ErrorAction Ignore;
Remove-Item ($Path + "\" + $App1) -ErrorAction Ignore;
Remove-Item ($Path + "\" + $App2) -ErrorAction Ignore;
Invoke-WebRequest ($AzureEndpoint + "/" + $AzureFileShare + "/" + $Script + $AzureSharedAccessSignature) -OutFile ($Path + "\" + $Script);
Invoke-WebRequest ($AzureEndpoint + "/" + $AzureFileShare + "/" + $app1 + $AzureSharedAccessSignature) -OutFile ($Path + "\" + $app1);
Invoke-WebRequest ($AzureEndpoint + "/" + $AzureFileShare + "/" + $app2 + $AzureSharedAccessSignature) -OutFile ($Path + "\" + $app2);

#See if the script and apps were downloaded as expected.
$files = $Script, $app1, $app2;

ForEach ($file in $files) {

    If (Test-Path -Path $Path\$file) {
        #Write out to the log file.
        Write-Log -File $LogFile -Status Information -Text "Finished downloading '$file' to '$Path'.";
    }
    Else {
        #Write out to the log file.
        Write-Log -File $LogFile -Status Error -Text "$Error[0]";
    }
}

#Write out to the log file.
Write-Log -File $LogFile -Status Information -Text "Finished download request for solution files.";

#Write out to the log file.
Write-Log -File $LogFile -Status Information -Text "Starting configuration of solution for $Hostname.";

#Check if the Old scheduled task exists. If so, remove it.
If (Test-ScheduleTask -Name $OldScheduleTaskName) {
    #Write out to the log file.
    Write-Log -File $LogFile -Status Warning -Text "Removing '$OldScheduleTaskName' scheduled task.";

    #Remove old scheduled task.
    UnRegister-ScheduledTask -TaskName $OldScheduleTaskName -Confirm:$false;
}
Else {
    #Write out to the log file.
    Write-Log -File $LogFile -Status Warning -Text "Previous scheduled task '$OldScheduleTaskName' not present.";
}

#Check if the scheduled task exists.
If (!(Test-ScheduleTask -Name $ScheduleTaskName)) {
    #Write out to the log file.
    Write-Log -File $LogFile -Status Information -Text "Scheduled task '$ScheduleTaskName' doesn't exist.";
    Write-Log -File $LogFile -Status Information -Text "Creating scheduled task '$ScheduleTaskName'.";

    #Add schedule task.
    Register-ScheduledTask -Xml (Get-Content ($ScheduleTaskName + ".xml") | Out-String) -TaskName "$ScheduleTaskName" -TaskPath "\Event Viewer Tasks\" | Out-Null;

    #Write out to the log file.
    Write-Log -File $LogFile -Status Information -Text "Removing scheduled task '$ScheduleTaskName' XML file.";

    #Remove XML file.
    Remove-Item ($ScheduleTaskName + ".xml");
}
Else {
    #Write out to the log file.
    Write-Log -File $LogFile -Status Information -Text "Scheduled task '$ScheduleTaskName' already exists.";
}


#Write out to the log file.
Write-Log -File $LogFile -Status Information -Text "Stopping ReACL_PhysicalDrive_for_Interactive_Access solution configuration for $Hostname.";

<# Main - End #>
################################################
