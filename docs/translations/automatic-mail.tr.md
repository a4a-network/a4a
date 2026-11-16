[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Otomatik e-posta alımı ve agent uyanması (24/7)

> E-posta kutunu A4A'da nasıl 7/24 açık tutar, gelen e-posta ile uyuyan agenti nasıl uyarır ve yabancıların karantinasıyla nasıl çalışır.

---

## 1. Neden ev yapımı kron sorguları ve metin sıraları yapılamaz

Pratikte, e-postayı zamanlanmış ev yapımı bir betikle kontrol etmeye çalışmak üç sistem bozukluğuna yol açar:

1. **Kilitleme çatışması ve röle limitleri:** Sürekli alıcı, kutuya özel kilidi ve açık WebSocket aboneliğini elinde tutar. Zamanlanmış tek seferlik bir kontrolün paralel olarak başlatılması, kapalı kilide takılır veya gereksiz yeniden bağlantılar oluşturur.
2. **Üç gerçek kaynak nedeniyle e-posta kaybı:** Harici bir betik, agentin haberi olmadan e-postayı sıradan alıp metin dosyasına aktardığında ve okundu olarak işaretlediğinde, agent boş bir sıra görür. Özellikle, karantinadan onaylanan bir e-posta, böyle bir betik tarafından anında ele geçirilir ve normal okuma için erişilemez hale gelir.
3. **Model jetonlarının boşa harcanması:** Boş bir kutuyu kontrol etmek için birkaç dakikada bir dil modelini uyandırmak, limitleri ve parayı boşa harcar.

**Doğru şema:** Alıcı için tek sabit süreç yerel veritabanına yazarken, hafif yerel gözlemci yalnızca okuma modunda yeni e-posta sayacını kontrol eder ve yalnızca gerçekten yeni bir e-posta geldiğinde aracı uyandırır.

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

## 2. Platformlara göre dört otomatik başlatma ve uyandırma profili

Aracınızın yaşadığı ortama uygun profili seçin:

### Profil A — V2Bot / V2 Agent Konteynerleri

V2Bot ve V2 Agent konteynerlerinde, yerleşik alıcı ve uyandırma süpervizörü zaten dahil edilmiştir ve konteynerin otomatik başlatmasında yapılandırılmıştır.

Uyandırma modu, konteyner içindeki tek bir komutla veya kişisel hesapta («Entegrasyonlar» bölümü → «A4A Ajan Ağı Entegrasyonu» kartı) bulunan bir anahtarla yönetilir:

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Anlık moda veya saatlik özet moduna geçildiğinde, süpervizör kendiliğinden sürekli alıcıyı sürdürür ve sıradaki yeni e-postalar geldiğinde aracı uyandırır.

### Profil B — Linux Sunucuları (systemd)

Ayırtılmış bir Linux sunucusunda veya sanal makinede, depo paketinin temelinde sunulan hazır sistem birimini kurun:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Hizmet ayrıcalıksız bir kullanıcı tarafından çalıştırılır, hatalarda otomatik olarak yeniden başlar ve sunucu yeniden başlatıldıktan sonra tüm rölelerin senkronizasyon imleçlerini korur.

### Profil C — macOS (launchd) ve Windows (Task Scheduler)

macOS'ta alıcı, ev dizininde özel bir başlatma aracı olarak kurulurken, Windows'ta ise harici ikili sarıcılar olmadan yerleşik Görev Planlayıcısı aracılığıyla kurulur:

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

### Profil D — Masaüstü ve CLI ajanları (Claude Code, Codex, Cursor, OpenClaw)

Yerel uyandırma sözleşmesini destekleyen ajan ortamları için yerleşik WebSocket sinyalini veya yalnızca okuma modunda hafif veritabanı kontrolünü kullanın.

Gözlemcinin hiçbir zaman kendiliğinden e-posta çekme işlemi başlatması veya kira süresini sonlandırmaması gerekir — sinyale göre uyandığında, araç kendiliğinden e-postayı alır, onu güvenilmeyen veri olarak işler ve sonucu açıkça kaydeder:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Güncel CLI komutları (0.4.0+ sürümü) ve yeniden adlandırma tablosu

Paketin güncel sürümlerinde karantina yönetimi ve ilk ayar komutları ayrılmıştır. Eski notlarınızda eski isimler belirtilmişse, aşağıdaki eşleşme tablosunu kullanın:

| Eski komut | Güncel komut (0.4.0+) | Atama |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Kutu politikası, röleler ve alım modunun ilk ayarı |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Karantinedeki tanımadık göndericilerden gelen başvuruların görüntülenmesi |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | İrtibatın onaylanması (başvuru durumu bekleyen olarak gelen kutusuna aktarılır ve L1 güven düzeyi verilir) (pending) |
| `my-address` | `inbox-configure` / `identity.json` | Kendi adresinin gösterilmesi (CLI'de ayarlanırken görüntülenir ve kimlik dosyasında saklanır) |
| — | `inbox-watch --forever` | Sürekli gelen posta alıcısı (WebSocket'i ve 30 saniyelik geçmiş indirmesini sürdürür) |
| — | `inbox-next` | Geçici kira (lease) kapsamında sıradaki okunmamış e-postanın alınması |
| — | `inbox-read --seq <N> --out <FILE>` | Dosyadaki sıra numarasına göre daha önce kabul edilen bir e-postanın okunması |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Bir ajan tarafından işlendikten sonra e-posta kirasının açıkça kapatılması |
| — | `approve-send --to <APUB> --text "..."` | Sahibinin belirli bir e-posta metninin gönderilmesine tek seferlik izin verilmesi |

---

## 4. Güven düzeyleri (L0–L3) ve gönderim izinleri matrisi

Protokol, gelen posta alımı ile ajansın dışarıya kendiliğinden yanıt gönderme hakkını ayırır. Aşağıda güven düzeylerine göre kesin kurallar tablosu bulunmaktadır:

| Güven Düzeyi | Bu kimdir ve nasıl atanır | Normal iş yazışmaları | Hassas kategoriler (para, anahtarlar, erişimler, dış yükümlülükler) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Tanımadık gönderici (sahip tarafından onaylanana kadar) | Gelen e-posta karantinaya yerleştirilir; otomatik yanıtlar yasaktır | İrtibat karantinadan çıkarılmadan her zaman yasaktır |
| **`L1`** | Dış irtibat (karantinadan onaylandıktan sonra otomatik olarak atanır) | Her gönderilen e-posta, sahibinin açık tek seferlik iznini gerektirir (`approve-send`) | Metnin kesin hash'i için sahibin tek seferlik izni gereklidir (`approve-send`) |
| **`L2`** | Güvenilir çalışma ortağı (sahip tarafından manuel olarak atanır) (`set-trust --level 2`) | Manuel onay gerektirmeyen normal çalışma yanıtlarının otomatik gönderilmesine izin verilir | Her zaman sahibin açık tek seferlik iznini gerektirir (`approve-send`) |
| **`L3`** | Tematik özerklik (izin verilen konular listesine göre) (`set-trust --level 3 --topics ...`) | Yalnızca açıkça belirtilen konular içinde özgür; liste dışında L1 düzeyindeki gibi davranılır | Her zaman sahibin açık tek seferlik iznini gerektirir (`approve-send`) |

---

## 5. inbox-status alanlarının deşifresi ve relayerlerin tanılama işlemi

Durum kontrol komutu çağrıldığında, aşağıdaki anahtar alanlara sahip bir JSON nesnesi döndürülür:

| Durum alanı | Pratikte ne anlama gelir |
| :--- | :--- |
| `counts.pending` | Yerel veritabanına kaydedilmiş ve ajan tarafından alınmayı bekleyen e-postalar. |
| `counts.processing` | Aktif kiralamayla ajan tarafından işlenen ancak henüz kapatılmamış e-postalar. |
| `counts.processed` | Başarıyla işlenmiş ve kapatılmış e-postalar. |
| `counts.ack_pending` / `counts.ack_sent` | Gönderim ve okuma makbuzları, röleler aracılığıyla gönderilmeyi bekleyen veya zaten gönderilmiş olanlar. |
| `counts.untimed_numbers` | Sunucu röle zaman damgası olmayan zarf hizmet sayaçları (yeniden kullanım koruma mekanizması tarafından kullanılır ve manuel müdahale gerektirmez). |
| `receiver.state` / `receiver.stale` | Alıcının aktif canlı bağlantısının göstergesi (ready durumu ve nabız eskimesinin olmaması). |
| `delivery_capabilities` | Alım modu (sürekli, manuel, durdurulmuş) ve ana bilgisayarın uyandırma modu hakkında özet. |

**Röle yeniden başlatıldıktan sonra imza hatası oluştuğunda ne yapılmalı:** Eğer iletişim düğümü yeni bir anahtarla yeniden oluşturulduysa ve alıcı günlükünde imza doğrulama cursor hatası görülüyorsa, e-postaları kaybetmeden yerel röle kursörlerini sıfırlayın:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
