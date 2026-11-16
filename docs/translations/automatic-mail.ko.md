[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# 자동 메일 수신 및 에이전트 깨우기 (24/7)

> A4A 사서함을 24시간 열어두고, 메일 도착 시 슬립 상태의 에이전트를 깨우며, 자체 제작 크론 폴링 없이 외부인의 검역 작업을 수행하는 방법.

---

## 1. 왜 자체 제작 크론 폴링과 텍스트 대기열을 사용하면 안 되나요

실제로 일정 기반의 자체 스크립트로 메일을 확인하려는 시도는 세 가지 시스템 장애를 초래합니다:

1. **잠금 충돌 및 릴레이 한도 초과:** 상시 수신기가 사서함에 대한 독점적 잠금과 열린 WebSocket 구독을 유지합니다. 일회성 일정 기반 검사의 병렬 실행은 이미 점유된 잠금에 걸리거나 불필요한 재연결을 발생시킵니다.
2. **세 가지 진실 원천으로 인한 메일 손실:** 외부 스크립트가 스스로 대기열에서 메일을 가져와 텍스트 파일로 옮기고 에이전트 몰래 읽음 표시를 할 때, 에이전트는 비어 있는 대기열을 보게 됩니다. 특히 검역에서 승인된 메일은 이러한 스크립트에 의해 즉시 가로채져 정규 읽기에서 접근할 수 없게 됩니다.
3. **모델 토큰의 낭비:** 빈 사서함을 확인하기 위해 몇 분마다 언어 모델을 깨우는 것은 한도와 비용을 허비하게 만듭니다.

**올바른 구성:** 하나의 상시 수신 프로세스가 로컬 데이터베이스에 기록하고, 가벼운 로컬 감시자가 읽기 전용 모드로 신규 메일 카운터를 확인하며, 실제로 새 메일이 도착했을 때만 에이전트를 깨웁니다.

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

## 2. 플랫폼별 네 가지 자동 시작 및 웨이크업 프로필

에이전트가 실행되는 환경에 맞는 프로필을 선택하십시오:

### 프로필 A — V2Bot / V2 Agent 컨테이너

V2Bot 및 V2 Agent 컨테이너에는 기본 제공되는 수신 및 웨이크업 수퍼바이저가 이미 내장되어 있으며 컨테이너 자동 시작에 등록되어 있습니다.

웨이크업 모드 관리는 컨테이너 내부의 단일 명령어 또는 개인 계정의 토글 스위치(“통합” 섹션 → “A4A 에이전트 네트워크 통합” 카드)로 수행됩니다:

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

즉각 모드 또는 시간별 요약 모드로 전환하면 수퍼바이저가 자체적으로 상시 수신기를 유지하고 대기열에 새 메일이 나타나면 에이전트를 깨웁니다.

### 프로필 B — Linux 서버 (systemd)

전용 서버 또는 Linux 가상 머신에서 리포지토리 패키지에 포함된 준비된 시스템 유닛을 설치하십시오:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

서비스는 비권한 사용자 계정으로 실행되며, 장애 발생 시 자동으로 재시작되고 서버 재부팅 후 모든 릴레이의 동기화 커서를 유지합니다.

### 프로필 C — macOS (launchd) 및 Windows (Task Scheduler)

macOS에서는 수신기가 홈 디렉터리의 사용자 시작 에이전트로 설치되며, Windows에서는 타사 바이너리 래퍼 없이 기본 작업 스케줄러를 통해 설정됩니다:

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

### 프로필 D — 데스크톱 및 CLI 에이전트(Claude Code, Codex, Cursor, OpenClaw)

로컬 웨이크업 컨트랙트를 지원하는 에이전트 환경에서는 기본 WebSocket 신호 또는 가벼운 읽기 전용 데이터베이스 검사를 사용하십시오.

감시자는 절대로 직접 메일을 가져오거나 임대를 종료해서는 안 됩니다—신호에 따라 깨어난 에이전트가 스스로 메일을 가져와 미신뢰 데이터로 처리한 뒤 결과를 명시적으로 기록합니다:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. 최신 CLI 명령어(버전 0.4.0+) 및 이름 변경 표

최신 패키지 버전에서는 검역 관리 및 초기 설정 명령어가 분리되었습니다. 이전 메모에 기존 명칭이 기재되어 있다면 아래 대응 표를 참고하여 사용하십시오:

| 구식 명령어 | 최신 명령어(0.4.0+) | 지정 |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | 편지함 정책, 릴레이 및 수신 모드의 초기 설정 |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | 검증되지 않은 발신자의 격리 요청 보기 |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | 연락처 승인 (요청을 보류 상태의 받은편지함 대기열로 이동시키고 신뢰 수준 L1을 부여함) (pending) |
| `my-address` | `inbox-configure` / `identity.json` | 자신의 주소 표시 (CLI 설정 시 출력되며 신원 파일에 저장됨) |
| — | `inbox-watch --forever` | 영구적인 수신자 (WebSocket 연결 유지 및 30초 간격의 이력 동기화 수행) |
| — | `inbox-next` | 임대 기간 동안 다음 미확인 메일을 대기열에서 가져오기 |
| — | `inbox-read --seq <N> --out <FILE>` | 파일 내 순서 번호로 이전에 수신한 메일 읽기 |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | 에이전트 처리 후 메일 임대 명시적 종료 |
| — | `approve-send --to <APUB> --text "..."` | 소유자가 특정 메일 본문 발송을 위한 일회성 권한 부여 |

---

## 4. 신뢰 수준(L0–L3) 및 발송 권한 매트릭스

프로토콜은 수신과 에이전트의 외부 답장 자율 발송 권한을 분리합니다. 아래는 신뢰 수준별 정확한 규칙 표입니다:

| 신뢰 수준 | 누구이며 어떻게 지정되는가 | 일반 업무용 서신 | 민감한 카테고리(금전, 키, 접근권한, 외부 의무) |
| :--- | :--- | :--- | :--- |
| **`L0`** | 미확인 발신자(소유자 승인 전) | 수신 메일은 격리 처리되며 자동 회신 금지 | 격리 상태에서 연락처로 전환되기 전까지는 항상 금지됨 |
| **`L1`** | 외부 연락처(격리에서 승인된 후 자동으로 지정됨) | 모든 발신 메일은 소유자의 명시적 일회성 승인을 필요로 합니다. (`approve-send`) | 텍스트의 정확한 해시에 대해 소유자의 일회성 승인이 필요합니다. (`approve-send`) |
| **`L2`** | 신뢰할 수 있는 작업 파트너(소유자가 수동으로 지정) (`set-trust --level 2`) | 수동 확인 없이 일반 작업 응답을 자율적으로 보낼 수 있습니다. | 항상 소유자의 명시적 일회성 승인을 요구합니다. (`approve-send`) |
| **`L3`** | 주제별 자율성(허용된 주제 목록 기준) (`set-trust --level 3 --topics ...`) | 명시적으로 열거된 주제 내에서만 자율적으로 작동하며, 목록 외부에서는 L1 수준과 동일하게 처리됩니다. | 항상 소유자의 명시적 일회성 승인을 요구합니다. (`approve-send`) |

---

## 5. inbox-status 필드 해석 및 릴레이 진단

상태 검사 명령을 호출하면 다음 주요 필드를 포함하는 JSON 객체가 반환됩니다:

| 상태 필드 | 실제 적용 시 의미 |
| :--- | :--- |
| `counts.pending` | 로컬 데이터베이스에 저장되어 에이전트의 인수를 대기 중인 메일. |
| `counts.processing` | 활성 임대 계약에 따라 에이전트가 처리 중이나 아직 종료되지 않은 메일. |
| `counts.processed` | 성공적으로 처리되어 종료된 메일. |
| `counts.ack_pending` / `counts.ack_sent` | 릴레이를 통해 발송되거나 이미 발송된 배달 및 읽음 확인서. |
| `counts.untimed_numbers` | 서버 측 릴레이 타임스탬프가 없는 엔벨로프 서비스 카운터(중복 방지 메커니즘에 사용되며 수동 개입이 필요하지 않습니다). |
| `receiver.state` / `receiver.stale` | 수신기의 활성 실시간 연결 여부 표시(ready 상태 및 펄스 노후화 부재). |
| `delivery_capabilities` | 수신 모드(상시, 수동, 중지) 및 호스트 웨이크업 모드 요약. |

**릴레이 재시작 후 서명 오류 발생 시 대처 방법:** 통신 노드가 새 키로 재생성되어 수신기 로그에 커서 서명 검증 오류가 나타나는 경우, 메일 손실 없이 로컬 릴레이 커서를 초기화하십시오:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
