[CmdletBinding()]
param(
    [string]$PublishDirectory = (Join-Path $PSScriptRoot "..\publish"),
    [switch]$ForceConfig
)

$ErrorActionPreference = "Stop"
$serviceName = "AntiCryptoMinerd"
$root = Join-Path $env:ProgramData "anti-crypto-minerd"
$binaryRoot = Join-Path $root "app"
$configPath = Join-Path $root "config.json"
$sourceRoot = Split-Path $PSScriptRoot -Parent

if (-not (Test-Path (Join-Path $PublishDirectory "AntiCryptoMinerd.exe"))) {
    throw "Publish output was not found. Run: dotnet publish .\src\AntiCryptoMinerd\AntiCryptoMinerd.csproj -c Release -r win-x64 --self-contained true -o .\publish"
}

New-Item -ItemType Directory -Path $root, $binaryRoot, (Join-Path $root "logs"), (Join-Path $root "quarantine") -Force | Out-Null
Copy-Item -Path (Join-Path $PublishDirectory "*") -Destination $binaryRoot -Recurse -Force
if ($ForceConfig -or -not (Test-Path $configPath)) {
    Copy-Item -Path (Join-Path $sourceRoot "config.json.example") -Destination $configPath -Force
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

$exe = Join-Path $binaryRoot "AntiCryptoMinerd.exe"
& sc.exe create $serviceName binPath= "`"$exe`"" start= auto obj= "NT SERVICE\$serviceName" password= "" | Out-Null
& sc.exe description $serviceName "Detects and contains suspected cryptocurrency miners." | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
& icacls.exe $root /grant "NT SERVICE\$serviceName:(OI)(CI)M" /T /C | Out-Null

try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($serviceName)) { New-EventLog -LogName Application -Source $serviceName }
} catch { Write-Warning "Could not pre-create Event Log source: $($_.Exception.Message)" }

Start-Service -Name $serviceName
Write-Host "Installed $serviceName. Edit $configPath and restart the service to apply changes."
