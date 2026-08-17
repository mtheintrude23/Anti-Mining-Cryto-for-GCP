# anti-crypto-minerd for Windows Server

Native `.NET 8` Windows Service port for Windows Server 2019, 2022, and 2025. Code comments are English; this guide is Vietnamese. The service performs independent periodic scans, aggregates confidence per detection, logs locally and to Windows Event Log, then optionally sends Discord notifications and remediates process-backed findings.

## Kien truc

`SecurityWorker` la orchestration loop. Moi detector nhan chung `ScanContext` (cau hinh, logger, GCP client, hostname) va tra ve `DetectionAlert`; cac detector chay song song qua `Task.WhenAll`. `ConfigProvider` theo doi `config.json` bang `FileSystemWatcher`; reload loi giu lai cau hinh hop le truoc do.

| Linux module | Windows implementation |
| --- | --- |
| `daemon_core` | `Services/SecurityWorker`, `Core/ScanContext` |
| `process_inspector` | `Detectors/ProcessInspector` qua WMI `Win32_Process` |
| `network_inspector` | `Detectors/NetworkInspector` qua `Get-NetTCPConnection` |
| `fim_monitor` | `Detectors/PersistenceMonitor` (Startup watcher, Registry/Task/Service diff) |
| `rootkit_detector` | `Detectors/DriverInspector` (`Win32_SystemDriver`) |
| `container_inspector` | `Detectors/ContainerInspector` (`docker ps`, optional) |
| `ebpf_monitor` | `Detectors/SysmonTelemetryMonitor` (optional Sysmon Event ID 1) |
| `discord_notifier` | `Services/DiscordNotifier` (`HttpClient`) |
| `gcp_control` | `Infrastructure/GcpMetadataClient` |
| `remediation_engine` | `Services/RemediationEngine` |

## Build

Tren may Windows co .NET SDK 8:

```powershell
git clone <repository-url>
cd anti-crypto-minerd-windows
dotnet restore .\AntiCryptoMinerd.Windows.sln
dotnet publish .\src\AntiCryptoMinerd\AntiCryptoMinerd.csproj -c Release -r win-x64 --self-contained true -o .\publish
```

Luu y: target `win-x64` phu hop cho Windows Server x64. Doi sang `win-arm64` neu VM ARM64.

## Cai dat va van hanh

Mo PowerShell **Run as Administrator**, sau khi publish:

```powershell
.\scripts\install.ps1 -PublishDirectory .\publish
notepad "$env:ProgramData\anti-crypto-minerd\config.json"
Restart-Service AntiCryptoMinerd
Get-Service AntiCryptoMinerd
Get-Content "$env:ProgramData\anti-crypto-minerd\logs\anti-crypto-minerd.log" -Tail 100 -Wait
```

Script dang ky native service voi Virtual Service Account `NT SERVICE\AntiCryptoMinerd`, cap Modify permission chi tren thu muc du lieu rieng, va cau hinh service recovery. Khong can NSSM. Config duoc reload khi file thay doi; restart chi can khi cap nhat binary hoac ACL.

Mac dinh `dryRun=true`. Chi dat `dryRun=false` sau khi da kiem tra allowlist va Discord webhook. `gcpDeleteSelf` mac dinh tat. Khi bat, service chi goi DELETE sau finding confidence 100 va dung metadata cua chinh VM hoac override config da validate theo format GCP.

Go cai dat, giu log/quarantine/config:

```powershell
.\scripts\uninstall.ps1 -KeepData
```

Go va xoa du lieu (PowerShell se yeu cau xac nhan neu `-Confirm`):

```powershell
.\scripts\uninstall.ps1 -Confirm
```

## Cau hinh

Sao chep `config.json.example` thanh `C:\ProgramData\anti-crypto-minerd\config.json` khi khong dung installer. Khong commit webhook URL hoac token. `allowlist` match process name, mot phan executable path, hoac publisher subject. `blacklistIps` nhan IP don le va CIDR IPv4/IPv6. `poolPorts` la remote ports duoc coi la pool mining.

## Remediation an toan

Remediation chi ap dung cho alert gan voi PID va executable path. Truoc khi `Kill` va quarantine, engine tu choi binary duoi `C:\Windows\System32` / `C:\Windows\SysWOW64` va tu choi binary Microsoft-signed co chain hop le. File bi quarantine duoc doi ten theo timestamp/PID va ACL bi rut quyen nhom thong dung. Tat ca action duoc ghi file log, Event Log va Discord alert.

## Operational boundaries

- Day la user-mode service. No khong co kernel-level visibility hoac anti-rootkit assurance thuc su. Driver/ETW-level adversary co the an process, connection, file, hoac event.
- Sysmon Event ID 1 la telemetry tuy chon, khong phai ETW session thay the day du eBPF. Cai Sysmon va bat `enableSysmonTelemetry` de co process creation telemetry gan realtime.
- `Get-NetTCPConnection`, WMI, Event Log, Registry, va Docker co the bi gioi han boi quyen, policy, hoac component chua cai. Moi loi duoc catch va ghi log, khong lam dung main loop.
- Authenticode chain validation giam false positive nhung khong thay the WDAC, Defender, EDR, audit, hoac quy trinh incident response. Entropy va mining signature la heuristic.
- GCP self-delete la hanh dong pha huy. Chi bat sau khi test `dryRun`, su dung service account co quyen thap nhat, va xac nhan project/zone/instance.
