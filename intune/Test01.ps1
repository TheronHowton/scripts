$ScriptFilePath = "C:\Program Files\Intune Management"
$LogFilePath = "C:\Logs\Intune Management"

New-Item -ItemType Directory -Force -Path $ScriptFilePath  | Out-Null;
New-Item -ItemType Directory -Force -Path $LogFilePath  | Out-Null;