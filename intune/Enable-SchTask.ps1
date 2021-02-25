

$schTask1 = "324MGMT- Security_Microsoft-Windows-Security-Auditing_6416_V1.0"
$schTaskPath1 = "\Event Viewer Tasks\"

$schTask1Status = (Get-ScheduledTask -TaskName $schTask1 -TaskPath $schTaskPath1).State

If($schTask1Status -ne 'Ready'){
    Enable-ScheduledTask -TaskName $schTask1 -TaskPath $schTaskPath1}

