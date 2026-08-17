[CmdletBinding(SupportsShouldProcess)]
param([switch]$KeepData)

$ErrorActionPreference = "Stop"
$serviceName = "AntiCryptoMinerd"
$root = Join-Path $env:ProgramData "anti-crypto-minerd"

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Stopped") { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
}
if (-not $KeepData -and (Test-Path $root) -and $PSCmdlet.ShouldProcess($root, "Remove installed application data")) {
    Remove-Item -Path $root -Recurse -Force
}
Write-Host "Uninstalled $serviceName."
