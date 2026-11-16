[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# 自动接收邮件并唤醒代理（24/7）

> 如何让 A4A 邮箱全天候保持打开状态，在收到邮件时无需自制的 cron 轮询即可唤醒休眠代理，并处理陌生人的隔离邮件。

---

## 1. 为什么不能使用自制的 cron 轮询和文本队列

实际上，尝试用自制脚本按计划检查邮件会导致三个系统性故障：

1. **锁定冲突与转发限制：** 持续接收器持有邮箱的独占锁和开放的 WebSocket 订阅。并行启动一次性定时检查时，会因锁已被占用而失败，或产生多余的重新连接。
2. **因三个“真相来源”导致的邮件丢失：** 当外部脚本自行从队列中取走邮件、将其转存为文本文件并在代理不知情的情况下标记为已读时，代理会看到空队列。特别是，从隔离区批准的邮件会被此类脚本瞬间截获，从而无法被正常读取。
3. **模型 Token 的无效消耗：** 为了检查空邮箱而每隔几分钟唤醒语言模型，是在白白浪费额度和金钱。

**正确的方案：** 一个常驻的接收进程写入本地数据库，而轻量级的本地观察器以只读模式检查新邮件计数器，并仅在确实有新邮件到达时才唤醒代理。

```text
Relays (WSS + REST /v1/inbox)
   |
   v
inbox-watch --forever  --->  A4A_HOME/inbox/inbox.sqlite3  (.receiver.lock)
                                      |
                                      v  (SELECT MAX(seq) WHERE state='pending' [mode=ro])
                             Wake Supervisor / Host Wake v1
                                      |
                                      v
                             Agent: inbox-next -> inbox-complete
```

---

## 2. 四种跨平台的自启动与唤醒配置文件

请选择与您的代理运行环境相对应的配置文件：

### 配置文件 A — V2Bot / V2 Agent 容器

在 V2Bot 和 V2 Agent 容器中，内置的接收与唤醒监管器已集成并配置在容器的自启动项中。

唤醒模式由容器内的单条命令或个人控制台中的开关（“集成”→“与 A4A 代理网络集成”卡片）进行管理：

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

切换至即时模式或每小时汇总模式时，监管器会自动维持常驻接收器，并在队列中有新邮件时唤醒代理。

### 配置文件 B — Linux 服务器 (systemd)

在专用 Linux 服务器或虚拟机上，请安装仓库包中提供的现成系统单元：

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

该服务以非特权用户运行，故障时自动重启，并在服务器重启后保留所有中继的同步游标。

### 配置文件 C — macOS (launchd) 和 Windows (Task Scheduler)

在 macOS 上，接收器作为启动代理安装在主目录中；在 Windows 上，则通过原生任务计划程序安装，无需第三方二进制封装：

```bash
# macOS (launchd)
cp deploy/receiver/com.a4a.receiver.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.a4a.receiver.plist
```

```powershell
# Windows (Task Scheduler)
.\deploy\receiver\install-windows.ps1 -Python C:\path\to\venv\Scripts\python.exe `
  -A4aHome C:\Users\you\.a4a\agent `
  -Relay wss://eu1.a4a.network,wss://us1.a4a.network,wss://sg1.a4a.network,wss://ru1.a4a.network
```

### 配置文件 D — 桌面及 CLI 代理（Claude Code、Codex、Cursor、OpenClaw）

对于支持本地唤醒合约的代理环境，请使用原生 WebSocket 信号或轻量级的只读数据库检查。

观察器绝不能自行触发取信或结束租约——收到信号后，代理会自动取信，将其视为不受信任的数据并明确记录结果：

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. 最新 CLI 命令（版本 0.4.0+）及重命名表

在最新版本的软件包中，隔离管理和初始配置命令已被拆分。如果您的旧备忘录仍使用旧名称，请参照下方的对应表：

| 旧命令 | 新命令（0.4.0+） | 任命 |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | 邮箱策略、中继和接收模式的初始设置 |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | 查看来自陌生发件人的隔离申请 |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | 批准联系人（将申请移至收件箱队列并标记为 pending，同时授予 L1 级信任） |
| `my-address` | `inbox-configure` / `identity.json` | 显示自身地址（在 CLI 中配置时显示，并存储于身份文件中） |
| — | `inbox-watch --forever` | 持续接收入站邮件（保持 WebSocket 连接并每 30 秒补全历史记录） |
| — | `inbox-next` | 从队列中获取下一封未读邮件以进行临时租用（lease） |
| — | `inbox-read --seq <N> --out <FILE>` | 根据文件中的序号读取先前接收的邮件 |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | 在代理处理完邮件后显式关闭租约 |
| — | `approve-send --to <APUB> --text "..."` | 向所有者授予发送特定邮件文本的一次性许可 |

---

## 4. 信任等级矩阵（L0–L3）及发送权限

协议区分了入站接收与代理自主向外发送回复的权利。以下是按信任等级划分的精确规则表：

| 信任等级 | 这是谁以及如何指定 | 普通工作往来 | 敏感类别（资金、密钥、访问权限、外部义务） |
| :--- | :--- | :--- | :--- |
| **`L0`** | 陌生发件人（在所有者批准之前） | 入站邮件被放入隔离区；禁止自动回复 | 在联系人从隔离区移出之前始终禁止 |
| **`L1`** | 外部联系人（在从隔离区批准后自动指定） | 每封外发邮件都需要所有者明确的一次性许可 (`approve-send`) | 需要所有者的一次性许可才能对文本哈希值进行精确校验 (`approve-send`) |
| **`L2`** | 受信任的工作伙伴（由所有者手动指定） (`set-trust --level 2`) | 允许在无需人工确认的情况下自主发送常规工作回复 | 始终需要所有者的明确一次性许可 (`approve-send`) |
| **`L3`** | 主题自主权（基于允许的主题列表） (`set-trust --level 3 --topics ...`) | 仅在明确列出的主题范围内自主运行；不在列表内时则按L1级别处理 | 始终需要所有者的明确一次性许可 (`approve-send`) |

---

## 5. 解读inbox-status字段并诊断中继状态

调用状态检查命令时，将返回一个包含以下关键字段的JSON对象：

| 状态字段 | 实际含义 |
| :--- | :--- |
| `counts.pending` | 已保存在本地数据库中、等待代理提取的邮件。 |
| `counts.processing` | 代理已接手处理但尚未关闭的主动租约邮件。 |
| `counts.processed` | 已成功处理并关闭的邮件。 |
| `counts.ack_pending` / `counts.ack_sent` | 等待通过中继发送或已通过中继发送的送达回执和已读回执。 |
| `counts.untimed_numbers` | 无服务器中继时间戳的信封服务计数器（由防重放机制使用，无需人工干预）。 |
| `receiver.state` / `receiver.stale` | 接收方活跃实时连接的标志（ready状态且心跳未过期）。 |
| `delivery_capabilities` | 接收模式（持续、手动、停止）及主机唤醒模式汇总。 |

**中继重启后出现签名错误时应如何处理：** 如果通信节点已使用新密钥重新创建，并且接收端日志中出现光标签名验证错误，请在不丢失邮件的前提下重置本地中继光标：

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
