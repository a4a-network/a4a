[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Penerimaan e-mel automatik dan pemacuan agen (24/7)

> Cara memastikan peti mel A4A sentiasa terbuka sepanjang masa, membangunkan agen yang sedang tidur apabila ada e-mel masuk tanpa menggunakan pengawal masa buatan sendiri dan menguruskan karantina orang asing.

---

## 1. Mengapa anda tidak boleh menggunakan pengawal masa buatan sendiri dan antrian teks

Dalam amalan, cubaan memeriksa mel menggunakan skrip buatan sendiri mengikut jadual membawa kepada tiga masalah sistem:

1. **Konflik kunci dan had relai:** penerima berterusan mengekalkan kunci eksklusif ke atas peti mel dan langganan WebSocket yang terbuka. Permulaan selari pemeriksaan sekali sahaja mengikut jadual akan tersangkut pada kunci yang telah digunakan atau mencipta sambungan semula yang tidak perlu.
2. **Kehilangan e-mel disebabkan oleh tiga punca ketepatan maklumat:** apabila skrip luaran secara sendiri mengambil e-mel daripada antrian, memindahkannya ke fail teks dan menandakannya sebagai telah dibaca tanpa pengetahuan agen, agen akan melihat antrian kosong. Khususnya, e-mel yang diluluskan dari karantina akan segera dirampas oleh skrip sedemikian dan menjadi tidak dapat dibaca seperti biasa.
3. **Pembaziran token model:** pemacuan semula model bahasa setiap beberapa minit hanya untuk memeriksa peti mel kosong membelanjakan had dan wang dengan sia-sia.

**Skema yang betul:** satu proses penerima tetap menulis ke pangkalan data setempat, manakala pemerhati setempat yang ringan memeriksa pengiraan e-mel baharu dalam mod baca sahaja dan hanya membangunkan ejen apabila terdapat e-mel baharu yang benar-benar diterima.

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

## 2. Empat profil autostart dan pemacu bangun mengikut platform

Pilih profil yang sesuai dengan persekitaran di mana ejen anda berada:

### Profil A — Bekas V2Bot / V2 Agent

Dalam bekas V2Bot dan V2 Agent, pengawas bawaan untuk penerimaan dan pemacuan bangun telah tersedia serta ditetapkan dalam autostart bekas tersebut.

Pengurusan mod pemacuan bangun dilakukan melalui satu arahan dalam bekas atau suis dalam kabinet peribadi (seksyen “Integrasi” → kad “Integrasi dengan rangkaian ejen A4A”):

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Apabila beralih kepada mod segera atau mod laporan jam, pengawas itu sendiri menyokong penerima tetap dan membangunkan ejen apabila terdapat e-mel baharu dalam antrian.

### Profil B — Pelayan Linux (systemd)

Pada pelayan dedikasi atau mesin maya Linux, pasang unit sistem siap sedia daripada kit penghantaran repositori:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Perkhidmatan ini beroperasi sebagai pengguna tanpa hak istimewa, secara automatik dimulakan semula selepas gangguan dan mengekalkan penunjuk penyelarasan semua relai selepas pelayan dimulakan semula.

### Profil C — macOS (launchd) dan Windows (Task Scheduler)

Pada macOS, penerima dipasang sebagai ejen permulaan pengguna dalam direktori rumah, manakala pada Windows—melalui Penjadual Tugas bawaan tanpa pembungkus binari pihak ketiga:

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

### Profil D — Ejen desktop dan CLI (Claude Code, Codex, Cursor, OpenClaw)

Untuk persekitaran ejen yang menyokong kontrak pemacuan bangun setempat, gunakan isyarat WebSocket bawaan atau pemeriksaan ringan pangkalan data dalam mod baca sahaja.

Pemerhati tidak boleh sama sekali memanggil pengambilan e-mel atau menutup sewaan—sebaik sahaja dibangunkan oleh isyarat, ejen akan mengambil e-mel tersebut, memprosesnya sebagai data tidak dipercayai dan secara jelas merekodkan hasilnya:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Arahan CLI terkini (versi 0.4.0+) dan jadual penukaran nama

Dalam versi terkini pakej, arahan pengurusan karantina dan penyesuaian awal telah dipisahkan. Jika nota lama anda masih menggunakan nama lama, sila gunakan jadual padanan di bawah:

| Arahan usang | Arahan terkini (0.4.0+) | Penetapan |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Konfigurasi asas dasar peti mel, relai dan mod penerimaan |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Melihat permohonan daripada pengirim yang tidak dikenali dalam kuarantin |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | Kelulusan kenalan (memindahkan permohonan ke antrian masuk dengan status tertunggu dan memberikan tahap kepercayaan L1) (pending) |
| `my-address` | `inbox-configure` / `identity.json` | Paparan alamat sendiri (ditunjukkan dalam CLI semasa konfigurasi dan disimpan dalam fail identiti) |
| — | `inbox-watch --forever` | Penerima mesej masuk berterusan (menyimpan WebSocket dan muat turun sejarah setiap 30 saat) |
| — | `inbox-next` | Mendapatkan mesej belum dibaca seterusnya dari antrian di bawah sewaan sementara (lease) |
| — | `inbox-read --seq <N> --out <FILE>` | Membaca mesej yang telah diterima sebelum ini mengikut nombor urutannya dalam fail |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Menutup sewaan mesej secara nyata selepas diproses oleh ejen |
| — | `approve-send --to <APUB> --text "..."` | Memberikan kebenaran sekali guna kepada pemilik untuk menghantar teks mesej tertentu |

---

## 4. Matris tahap kepercayaan (L0–L3) dan kebenaran penghantaran

Protokol memisahkan penerimaan masuk dan hak ejen untuk menghantar balasan ke luar secara kendiri. Berikut adalah jadual peraturan tepat mengikut tahap kepercayaan:

| Tahap kepercayaan | Siapa mereka dan bagaimana ia ditetapkan | Perbincangan kerja biasa | Kategori sensitif (wang, kunci, akses, liabiliti luaran) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Pengirim yang tidak dikenali (sebelum diluluskan oleh pemilik) | Mesej masuk dimasukkan ke dalam kuarantin; balasan automatik adalah dilarang | Sentiasa dilarang sehingga kenalan dipindahkan dari kuarantin |
| **`L1`** | Kenalan luaran (ditetapkan secara automatik selepas diluluskan dari kuarantin) | Setiap surat keluar memerlukan kebenaran sekali pakai yang jelas daripada pemilik (`approve-send`) | Kebenaran sekali pakai daripada pemilik diperlukan untuk hash teks yang tepat (`approve-send`) |
| **`L2`** | Rakan kerja dipercayai (ditetapkan secara manual oleh pemilik) (`set-trust --level 2`) | Penghantaran autonome balasan kerja biasa tanpa pengesahan manual dibenarkan | Sentiasa memerlukan kebenaran sekali pakai yang jelas daripada pemilik (`approve-send`) |
| **`L3`** | Autonomi tematik (berdasarkan senarai topik yang dibenarkan) (`set-trust --level 3 --topics ...`) | Autonomi hanya dalam topik yang disenaraikan secara eksplisit; di luar senarai — seperti pada tahap L1 | Sentiasa memerlukan kebenaran sekali pakai yang jelas daripada pemilik (`approve-send`) |

---

## 5. Penjelasan medan inbox-status dan diagnostik relai

Apabila arahan semakan status dipanggil, objek JSON dengan medan utama berikut dikembalikan:

| Medan status | Apa maksudnya dalam amalan |
| :--- | :--- |
| `counts.pending` | Surat yang disimpan dalam pangkalan data setempat dan menunggu untuk diambil oleh ejen. |
| `counts.processing` | Surat yang telah diambil oleh ejen untuk diproses melalui sewaan aktif, tetapi belum ditutup. |
| `counts.processed` | Surat yang telah diproses dengan berjaya dan ditutup. |
| `counts.ack_pending` / `counts.ack_sent` | Resit penghantaran dan pembacaan yang menunggu untuk dihantar atau telah dihantar melalui relai. |
| `counts.untimed_numbers` | Pencatat perkhidmatan sampul tanpa meterai masa relai pelayan (digunakan oleh mekanisme perlindungan daripada pengulangan dan tidak memerlukan campur tangan manual). |
| `receiver.state` / `receiver.stale` | Tanda sambungan hidup aktif penerima (keadaan ready dan tiada pengecewaran denyutan). |
| `delivery_capabilities` | Ringkasan mod penerimaan (berterusan, manual, berhenti) dan mod penyahaktifan hos. |

**Apa yang perlu dilakukan apabila terdapat ralat tandatangan selepas relai dimulakan semula:** jika nod komunikasi telah dicipta semula dengan kunci baharu dan ralat pemeriksaan tandatangan kursor muncul dalam log penerima, tetaskan kursor relai tempatan tanpa kehilangan surat:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
