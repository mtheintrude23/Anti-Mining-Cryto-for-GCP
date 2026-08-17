# 🛡️ Anti-Crypto-MinerD for Windows

> Native `.NET 8` Windows Service for detecting suspicious
> cryptocurrency-mining activity on Windows Server.

**Supported:** Windows Server 2019 · 2022 · 2025  
**Runtime:** .NET 8 · Native Windows Service · `win-x64` / `win-arm64`

---

## ✨ FEATURES

- 🔎 Process & executable inspection
- 🌐 Network connection monitoring
- ⛏️ Mining pool detection
- 🚫 IP / CIDR blacklist
- 🧩 Persistence monitoring
- ⚙️ Registry / Task / Service monitoring
- 🖥️ Driver inspection
- 🐳 Docker container inspection
- 📡 Optional Sysmon telemetry
- 🎯 Confidence-based detection
- 📝 Local + Windows Event Log
- 🔔 Discord notifications
- 🧹 Process remediation & quarantine
- ☁️ Optional Google Cloud VM control

> ⚠️ Heuristic detection only. This is NOT a kernel-level anti-rootkit or EDR solution.

---

# 🏗️ ARCHITECTURE

```text
                         ┌──────────────────────┐
                         │   SecurityWorker     │
                         │  Orchestration Loop  │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │     ScanContext      │
                         │ Config / Logger / GCP│
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
       │   Process   │       │   Network   │       │ Persistence │
       │  Inspector  │       │  Inspector  │       │   Monitor   │
       └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │    DetectionAlert    │
                         │   Confidence Score   │
                         └──────────┬───────────┘
                                    │
                   ┌────────────────┼────────────────┐
                   ▼                ▼                ▼
              📝 Logging       🔔 Discord       🧹 Remediation
                                                      │
                                                      ▼
                                                 ☁️ GCP Control
```

Các detector chạy song song bằng `Task.WhenAll`.

---

# 🔄 MODULE MAPPING

| 🐧 Linux Module | 🪟 Windows Implementation |
|---|---|
| `daemon_core` | `SecurityWorker` + `ScanContext` |
| `process_inspector` | `ProcessInspector` |
| `network_inspector` | `NetworkInspector` |
| `fim_monitor` | `PersistenceMonitor` |
| `rootkit_detector` | `DriverInspector` |
| `container_inspector` | `ContainerInspector` |
| `ebpf_monitor` | `SysmonTelemetryMonitor` |
| `discord_notifier` | `DiscordNotifier` |
| `gcp_control` | `GcpMetadataClient` |
| `remediation_engine` | `RemediationEngine` |

---

# 🚀 BUILD

## 📋 Requirements

- Windows Server 2019+
- .NET SDK 8
- PowerShell
- Administrator privileges

## 📦 Publish

```powershell
git clone <repository-url>
cd anti-crypto-minerd-windows

dotnet restore .\AntiCryptoMinerd.Windows.sln

dotnet publish `
  .\src\AntiCryptoMinerd\AntiCryptoMinerd.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -o .\publish
```

## 🖥️ ARM64

```powershell
dotnet publish `
  .\src\AntiCryptoMinerd\AntiCryptoMinerd.csproj `
  -c Release `
  -r win-arm64 `
  --self-contained true `
  -o .\publish
```

---

# ⚙️ INSTALLATION

> 🔐 Run PowerShell as Administrator.

```powershell
.\scripts\install.ps1 -PublishDirectory .\publish
```

### 📝 Configure

```powershell
notepad "$env:ProgramData\anti-crypto-minerd\config.json"
```

### 🔄 Restart

```powershell
Restart-Service AntiCryptoMinerd
```

### 🔎 Check Service

```powershell
Get-Service AntiCryptoMinerd
```

### 📜 Live Logs

```powershell
Get-Content `
  "$env:ProgramData\anti-crypto-minerd\logs\anti-crypto-minerd.log" `
  -Tail 100 -Wait
```

---

# 🔐 SERVICE SECURITY

Service sử dụng Virtual Service Account:

```text
NT SERVICE\AntiCryptoMinerd
```

Quyền `Modify` chỉ được cấp trên data directory riêng.

- ❌ Không cần NSSM
- ❌ Không chạy bằng Administrator account
- ❌ Không dùng shared credentials

Service được cấu hình Windows Service Recovery để tự khởi động lại khi gặp lỗi.

---

# 🧪 DRY RUN

Mặc định:

```json
{
  "dry_run": true
}
```

Recommended workflow:

```text
dry_run=true
     │
     ▼
  🔎 Monitor
     │
     ▼
📋 Review Alerts
     │
     ▼
⚙️ Tune Allowlist
     │
     ▼
🧪 Test Remediation
     │
     ▼
dry_run=false
```

⚠️ Không bật remediation ngay trên production workload chưa được kiểm thử.

---

# ☁️ GOOGLE CLOUD CONTROL

## 🛑 Shutdown VM

```json
{
  "gcp_shutdown_self": true
}
```

Service gọi:

```text
Google Compute Engine
        │
        └── instances.stop
```

VM được STOP, không bị xóa.

## 💀 Delete VM

```json
{
  "gcp_delete_self": true
}
```

Service gọi:

```text
Google Compute Engine
        │
        └── instances.delete
```

> 🚨 DESTRUCTIVE ACTION

Instance sẽ bị xóa. Boot disk có thể bị xóa tùy cấu hình `autoDelete`.

⚠️ Hành động này không thể hoàn tác.

---

# 🛡️ SHUTDOWN CONFIRMATION

Có thể yêu cầu Administrator xác nhận trước khi shutdown/delete:

```json
{
  "gcp_shutdown_require_confirmation": true,
  "gcp_shutdown_confirm_timeout_seconds": 60
}
```

Flow:

```text
🚨 Finding
    │
    ▼
🎯 Confidence = 100%
    │
    ▼
⚠️ Confirmation Required
    │
    ├── ✅ Confirm
    │      │
    │      ▼
    │   ☁️ Shutdown/Delete
    │
    └── ❌ Timeout
           │
           ▼
        🛑 No Action
```

---

# 🔑 GCP IAM

Service Account phải có quyền IAM tương ứng.

Khuyến nghị sử dụng Least Privilege:

```text
Service Account
      │
      ├── compute.instances.stop
      │
      └── compute.instances.delete
              │
              ▼
       IAM Condition
              │
              ▼
      Only authorized VM
```

Chi tiết:

```text
docs/gcp-iam-setup.md
```

---

# 🔔 DISCORD NOTIFICATIONS

❌ Không lưu Discord webhook dưới dạng plaintext.

## 🔐 Protect Webhook

```powershell
.\publish\AntiCryptoMinerd.exe `
  --protect-webhook `
  "https://discord.com/api/webhooks/..."
```

Output:

```text
dpapi:<base64>
```

Đưa giá trị vào:

```json
{
  "webhook_url": "dpapi:<base64>"
}
```

Webhook sử dụng:

```text
Windows DPAPI
DataProtectionScope.LocalMachine
```

---

# 🔒 CONFIGURATION ACL

Config:

```text
C:\ProgramData\anti-crypto-minerd\config.json
```

ACL:

```text
SYSTEM
Administrators
NT SERVICE\AntiCryptoMinerd
```

User thông thường không được phép đọc configuration chứa secret.

---

# 🧹 REMEDIATION

Remediation chỉ áp dụng cho alert có:

```text
PID
+
Executable Path
```

Safety checks:

```text
             🚨 Suspicious Process
                      │
                      ▼
             🔎 Executable Check
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
     System32      SysWOW64   Microsoft Signed
          │           │           │
          └───────────┴───────────┘
                      │
                      ▼
                    ❌ Reject

              Unknown / Suspicious
                      │
                      ▼
                   🛑 Kill
                      │
                      ▼
                📦 Quarantine
```

Quarantine:

- 🕒 Timestamp
- 🆔 PID
- 🔒 Restricted ACL
- 📝 Audit Log
- 🔔 Discord Alert

---

# 📡 SYSMON TELEMETRY

Sysmon Event ID `1` cung cấp process creation telemetry.

Enable:

```json
{
  "enableSysmonTelemetry": true
}
```

> ℹ️ Sysmon telemetry không thay thế full ETW monitoring.

---

# 🐳 DOCKER DETECTION

Nếu Docker được cài đặt:

```text
docker ps
```

được sử dụng để kiểm tra container đang chạy.

Docker không tồn tại hoặc command thất bại sẽ không làm main loop crash.

---

# 🧩 PERSISTENCE MONITORING

Theo dõi:

```text
┌──────────────────────────┐
│ 🚀 Startup               │
├──────────────────────────┤
│ 📝 Registry              │
├──────────────────────────┤
│ ⏰ Scheduled Tasks       │
├──────────────────────────┤
│ ⚙️ Windows Services      │
└──────────────────────────┘
```

Các thay đổi đáng ngờ được đưa vào detection pipeline.

---

# 🌐 NETWORK DETECTION

Sử dụng:

```text
Get-NetTCPConnection
```

## 🚫 Blacklisted IP

```text
192.0.2.10
2001:db8::10
```

## 🌐 CIDR

```text
192.0.2.0/24
2001:db8::/32
```

## ⛏️ Mining Pool Ports

```text
poolPorts
```

Remote port nằm trong danh sách có thể được xem là mining indicator.

---

# 📝 LOGGING

```text
C:\ProgramData\anti-crypto-minerd\
│
├── 📄 config.json
│
├── 📁 logs\
│   └── 📄 anti-crypto-minerd.log
│
└── 📁 quarantine\
```

Logs được ghi tới:

- 📝 Local file
- 🪟 Windows Event Log
- 🔔 Discord
- 🧾 Remediation audit

---

# 🗑️ UNINSTALL

## 📦 Giữ config / logs / quarantine

```powershell
.\scripts\uninstall.ps1 -KeepData
```

## 🗑️ Xóa toàn bộ data

```powershell
.\scripts\uninstall.ps1 -Confirm
```

---

# ⚠️ OPERATIONAL BOUNDARIES

Anti-Crypto-MinerD là **user-mode security service**.

Không đảm bảo phát hiện được:

- ❌ Kernel rootkits
- ❌ Hidden drivers
- ❌ ETW tampering
- ❌ Process hiding
- ❌ Kernel-level network hiding
- ❌ Advanced fileless malware

Attacker có quyền kernel có thể che giấu:

```text
Process
Connection
File
Event
Driver
Telemetry
```

---

# 🛡️ DEFENSE IN DEPTH

Không nên sử dụng Anti-Crypto-MinerD như lớp bảo vệ duy nhất.

```text
                    🪟 Windows Server
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
       🛡️ Defender       🔎 EDR        📊 Sysmon
            │              │              │
            └──────────────┼──────────────┘
                           ▼
                    🔐 WDAC / Policy
                           │
                           ▼
                 🛡️ Anti-Crypto-MinerD
                           │
                           ▼
                  📋 Incident Response
```

Entropy, mining signatures và network indicators đều là **heuristics**.

Không có heuristic nào đảm bảo 100% chính xác.

---

# 🚨 SELF-SHUTDOWN / SELF-DELETE WARNING

`gcp_shutdown_self` và đặc biệt `gcp_delete_self` có thể gây mất VM nếu detection là false positive.

Trước khi bật production:

- [ ] 🧪 Chạy `dry_run=true`
- [ ] 🔎 Kiểm tra alerts
- [ ] 📋 Xây dựng allowlist
- [ ] 🧠 Kiểm tra workload hợp lệ
- [ ] 🧪 Test trên VM riêng
- [ ] 💾 Thiết lập backup / snapshot
- [ ] 🔑 Kiểm tra IAM Conditions
- [ ] 🔐 Dùng least-privilege Service Account
- [ ] 🛡️ Cân nhắc bật confirmation gate

> 🔴 KHÔNG bật `gcp_delete_self=true` trên workload quan trọng nếu chưa kiểm thử đầy đủ.

---

# 📌 RECOMMENDED PRODUCTION SETUP

```text
                 dry_run=true
                       │
                       ▼
                  🔎 Monitor
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     Tune Allowlist  Verify      Discord
                    Detection     Alerts
          │            │            │
          └────────────┼────────────┘
                       ▼
                    Stable?
                       │
                      YES
                       │
                       ▼
                dry_run=false
                       │
                       ▼
                🧹 Remediation
                       │
                       ▼
               🛑 Optional Shutdown
                       │
                       ▼
                💀 Delete = Last Resort
```

---

# 📄 LICENSE

See the repository license file for licensing terms.

---

# 🛡️ SECURITY PHILOSOPHY

> **Detect first. Verify second. Remediate third. Destroy only as a last resort.**

```text
🔎 Visibility
      │
      ▼
📋 Evidence
      │
      ▼
🎯 Confidence
      │
      ▼
🧹 Controlled Remediation
      │
      ▼
☁️ Optional GCP Action
```

> **Security first. Automation second. Destructive actions last.**
