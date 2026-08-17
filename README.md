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

Mac dinh `dry_run=true`. Chi dat `dry_run=false` sau khi da kiem tra allowlist va Discord webhook. `gcp_shutdown_self` mac dinh tat. Khi bat, service goi Compute Engine `instances.stop` sau finding confidence 100, dung metadata cua chinh VM hoac override config da validate theo format GCP. Lenh nay dung instance, khong xoa VM hay persistent disk.

`gcp_delete_self` mac dinh tat va **manh hon**: khi bat, service goi `instances.delete` tren chinh VM sau finding confidence 100 — xoa han instance (va boot disk, tru khi disk duoc cau hinh rieng voi `autoDelete=false` ben ngoai service nay). Hanh dong nay khong the hoan tac. Chi bat sau khi da chay `dry_run` du lau de xac nhan khong co false positive tren workload nay, va service account chi nen co quyen toi thieu can thiet (`compute.instances.delete` tren chinh instance, khong hon).

### Xac nhan truoc khi tu dung/xoa may (gcp_shutdown_require_confirmation)

Mac dinh `gcp_shutdown_require_confirmation=false`: khi dieu kien kich hoat (stop hoac delete), service hanh dong ngay, khong cho ai xac nhan. Neu muon them mot buoc xac nhan thu cong (mot Administrator tren may phai go lenh trong X giay truoc khi hanh dong duoc thuc hien), dat `gcp_shutdown_require_confirmation=true` va cau hinh `gcp_shutdown_confirm_timeout_seconds`; chi tiet co che nam trong `Services/ShutdownConfirmationGate.cs`.

**Luu y ve rui ro:** ca `gcp_shutdown_self` va dac biet `gcp_delete_self` deu dua tren heuristic (entropy, cong pool, ten tien trinh, v.v.), khong phai bang chung chac chan 100%. False positive khi tat xac nhan nghia la mat VM (va du lieu chua backup) ma khong ai kip can thiep. Neu VM nay co du lieu quan trong khong the mat, nen: (1) bat autoDelete=false cho boot disk qua GCP truoc, hoac (2) giu snapshot dinh ky ngoai service nay, hoac (3) bat lai `gcp_shutdown_require_confirmation`.

### Quyen IAM de goi duoc API xoa/dung (bat buoc, ngoai pham vi code)

`gcp_delete_self`/`gcp_shutdown_self` chi la cau hinh — de VM thuc su goi duoc `instances.delete`/`instances.stop`, service account gan vao VM phai co quyen IAM tuong ung. Day la lop kiem soat truy cap thuc su cua co che nay (khong phai username/password, vi day la Windows Service chay nen, khong co nguoi dang nhap). Xem huong dan tao custom role + IAM Condition gioi han moi VM chi xoa duoc chinh no tai `docs/gcp-iam-setup.md`.

Go cai dat, giu log/quarantine/config:

```powershell
.\scripts\uninstall.ps1 -KeepData
```

Go va xoa du lieu (PowerShell se yeu cau xac nhan neu `-Confirm`):

```powershell
.\scripts\uninstall.ps1 -Confirm
```

## Cau hinh

Sao chep `config.json.example` thanh `C:\ProgramData\anti-crypto-minerd\config.json` khi khong dung installer. `allowlist` match process name, mot phan executable path, hoac publisher subject. `blacklistIps` nhan IP don le va CIDR IPv4/IPv6. `poolPorts` la remote ports duoc coi la pool mining.

### Bao ve webhook_url (khong luu plaintext)

Khong ghi Discord webhook URL dang plaintext vao `config.json`. Tren chinh may se chay service (PowerShell **Run as Administrator**):

```powershell
.\publish\AntiCryptoMinerd.exe --protect-webhook "https://discord.com/api/webhooks/..."
```

Lenh nay in ra mot chuoi dang `dpapi:<base64>`. Dan chuoi do vao truong `webhook_url` trong `config.json`. Gia tri duoc ma hoa bang Windows DPAPI, gan voi chinh may (`DataProtectionScope.LocalMachine`) — copy file `config.json` sang may khac hoac doc no boi user khong phai Administrator/SYSTEM tren may nay se khong giai ma duoc. `install.ps1` sinh ra tu `config.json.example` van la placeholder rong; hay chay lenh tren va dan gia tri ma hoa vao ngay sau khi cai dat, truoc khi bat `dry_run=false`.

`install.ps1` cung tu dong siet ACL rieng cho `config.json`: tat ke thua quyen tu `%ProgramData%`, chi cap quyen cho `SYSTEM`, `Administrators`, va virtual account `NT SERVICE\AntiCryptoMinerd`. User dang nhap thong thuong (kho co quyen Administrator) se khong doc duoc file nay, ke ca khi da co quyen tren thu muc `anti-crypto-minerd` noi chua log/quarantine.

## Remediation an toan

Remediation chi ap dung cho alert gan voi PID va executable path. Truoc khi `Kill` va quarantine, engine tu choi binary duoi `C:\Windows\System32` / `C:\Windows\SysWOW64` va tu choi binary Microsoft-signed co chain hop le. File bi quarantine duoc doi ten theo timestamp/PID va ACL bi rut quyen nhom thong dung. Tat ca action duoc ghi file log, Event Log va Discord alert.

## Operational boundaries

- Day la user-mode service. No khong co kernel-level visibility hoac anti-rootkit assurance thuc su. Driver/ETW-level adversary co the an process, connection, file, hoac event.
- Sysmon Event ID 1 la telemetry tuy chon, khong phai ETW session thay the day du eBPF. Cai Sysmon va bat `enableSysmonTelemetry` de co process creation telemetry gan realtime.
- `Get-NetTCPConnection`, WMI, Event Log, Registry, va Docker co the bi gioi han boi quyen, policy, hoac component chua cai. Moi loi duoc catch va ghi log, khong lam dung main loop.
- Authenticode chain validation giam false positive nhung khong thay the WDAC, Defender, EDR, audit, hoac quy trinh incident response. Entropy va mining signature la heuristic.
- GCP self-shutdown lam dung VM va co the lam gian doan workload. Chi bat sau khi test `dry_run`, su dung service account co quyen toi thieu cho `compute.instances.stop`, va xac nhan project/zone/instance.
