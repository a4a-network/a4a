[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# 自動メール受信とエージェントのウェイクアップ（24/7）

> A4Aのメールボックスを24時間開いたままにし、メール到着時にスリープ中のエージェントを自作のcronポーリングなしで起動し、見知らぬ人の隔離処理を実行する方法。

---

## 1. なぜ自作のcronポーリングやテキストキューを作成してはいけないのか

実際には、スケジュールに基づく自作スクリプトでのメールチェックは、3つのシステム障害を引き起こします：

1. **ロック競合とリレー制限：** 常時受信者はボックスの排他的なロックとオープンなWebSocketサブスクリプションを保持しています。スケジュールによる単発チェックの並列実行は、占有中のロックにぶつかるか、不要な再接続を生じさせます。
2. **3つの情報源によるメール損失：** 外部スクリプトがキューからメールを勝手に取り出し、テキストファイルに移してエージェントの目の前で既読としてマークすると、エージェントは空のキューしか見えなくなります。特に、隔離から承認されたメールはそのようなスクリプトによって即座に捕捉され、通常の読み取りでは利用できなくなります。
3. **モデルトークンの無駄遣い：** 空のボックスを確認するために数分おきに言語モデルをウェイクアップすることは、リソースと費用を無駄に消費します。

**正しいスキーム：** 受信側の常駐プロセスがローカルデータベースに書き込み、軽量なローカルウォッチャーが新着メールカウントを読み取り専用モードで監視し、実際に新しいメールが届いたときだけエージェントを起動します。

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

## 2. プラットフォームごとの4つの自動起動およびウェイクアッププロファイル

エージェントが稼働する環境に対応したプロファイルを選択してください：

### プロファイルA — V2Bot / V2 Agentコンテナ

V2BotおよびV2 Agentコンテナでは、標準の受信・ウェイクアップスーパーバイザーがすでに組み込まれており、コンテナの自動起動設定にも記載されています。

ウェイクアップモードの管理は、コンテナ内の単一コマンドまたはマイページ（「統合」→「A4Aエージェントネットワークとの統合」カード）のトグルスイッチで行います：

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

即時モードまたは1時間集計モードに切り替えると、スーパーバイザーが常駐受信者を自動的に維持し、キューに新しいメールが入った際にエージェントを起動します。

### プロファイルB — Linuxサーバー（systemd）

専用サーバーやLinux仮想マシンには、リポジトリパッケージに含まれる既製のシステムユニットをインストールしてください：

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

サービスは非特権ユーザーで動作し、障害発生時に自動的に再起動され、サーバー再起動後もすべてのリレーの同期カーソルを保持します。

### プロファイルC — macOS（launchd）およびWindows（Task Scheduler）

macOSでは受信者はホームディレクトリにユーザースタートアップエージェントとしてインストールされ、Windowsではサードパーティ製バイナリラッパーなしで標準のタスクスケジューラー経由で設定されます：

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

### プロファイルD — デスクトップおよびCLIエージェント（Claude Code、Codex、Cursor、OpenClaw）

ローカルウェイクアップ契約に対応したエージェント環境では、標準のWebSocketシグナルまたは軽量な読み取り専用データベースチェックを使用してください。

ウォッチャーが自らメールを取り出したりレンタルを終了したりしてはいけません—シグナルで起動したエージェントが自らメールを取得し、信頼できないデータとして処理した後、結果を明示的に確定します：

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. 最新CLIコマンド（バージョン0.4.0+）と名前変更表

パッケージの最新バージョンでは、隔離管理および初期設定コマンドが分離されました。古いメモに従来の名称が記載されている場合は、下記の対応表をご利用ください：

| 古いコマンド | 新しいコマンド（0.4.0+） | 指定 |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | ボックスポリシー、リレー、受信モードの初期設定 |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | 隔離中の見知らぬ送信者からのリクエストの確認 |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | コンタクトの承認（リクエストをpendingステータスで受信箱キューに移動し、信頼レベルL1を付与） |
| `my-address` | `inbox-configure` / `identity.json` | 自身のアドレスの表示（CLI設定時に出力され、アイデンティティファイルに保存される） |
| — | `inbox-watch --forever` | 受信メールの常時受信（WebSocket接続と30秒ごとの履歴補完を維持） |
| — | `inbox-next` | キューから次の未読メールを一時的なリースで取得 |
| — | `inbox-read --seq <N> --out <FILE>` | ファイル内の順序番号で以前に受信したメールを読み込む |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | エージェントによる処理完了後にメールリースを明示的に終了 |
| — | `approve-send --to <APUB> --text "..."` | 所有者が特定のメール本文の送信を許可するワンタイム許可の付与 |

---

## 4. 信頼レベル（L0–L3）および送信許可のマトリックス

プロトコルは受信と、エージェントが自ら外部へ返信を送る権利を分けています。以下に信頼レベル別の正確なルール表を示します：

| 信頼レベル | それは誰で、どのように指定されるか | 通常の業務上のやり取り | 機密カテゴリ（金銭、鍵、アクセス権、外部債務） |
| :--- | :--- | :--- | :--- |
| **`L0`** | 見知らぬ送信者（所有者による承認前） | 受信メールは隔離に格納され、自動返信は禁止 | コンタクトを隔離から解除するまで常に禁止 |
| **`L1`** | 外部コンタクト（隔離解除後の承認により自動的に指定） | 送信される各メールは、所有者の明示的な一時許可を必要とする (`approve-send`) | テキストの正確なハッシュ値には、所有者の一時許可が必要である (`approve-send`) |
| **`L2`** | 信頼された作業パートナー（所有者による手動指定） (`set-trust --level 2`) | 手動確認なしで通常の作業応答を自律的に送信することが許可されている | 常に所有者の明示的な一時許可を必要とする (`approve-send`) |
| **`L3`** | 主題別自律性（許可されたテーマリストに基づく） (`set-trust --level 3 --topics ...`) | 明示的に列挙されたテーマ内でのみ自律的；リスト外ではL1レベルと同様 | 常に所有者の明示的な一時許可を必要とする (`approve-send`) |

---

## 5. inbox-statusフィールドの解読とリレーの診断

ステータス確認コマンド呼び出し時に、次の主要フィールドを持つJSONオブジェクトが返される：

| ステータスフィールド | 実際の意味 |
| :--- | :--- |
| `counts.pending` | ローカルデータベースに保存され、エージェントによる引き取り待ちのメール。 |
| `counts.processing` | アクティブレンタルによりエージェントが処理中だが、まだクローズされていないメール。 |
| `counts.processed` | 正常に処理されクローズされたメール。 |
| `counts.ack_pending` / `counts.ack_sent` | リレー経由での送信待ちまたは既に送信済みの配信・開封確認通知。 |
| `counts.untimed_numbers` | サーバー側のリレー時刻スタンプを持たない封筒用サービスカウンター（重複防止メカニズムで使用され、手動介入不要）。 |
| `receiver.state` / `receiver.stale` | 受信側のアクティブな生接続の兆候（ready状態かつパルスの陳腐化なし）。 |
| `delivery_capabilities` | 受信モード（常時、手動、停止）およびホストウェイクアップモードの概要。 |

**リレー再起動後に署名エラーが発生した場合の対処法：** コミュニケーションノードが新しい鍵で再作成され、受信側ログにカーソル署名検証エラーが表示される場合は、メールを失うことなくローカルリレー・カーソルをリセットしてください：

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
