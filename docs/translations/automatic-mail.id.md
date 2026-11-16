[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Penerimaan otomatis surat dan pemanggilan agen (24/7)

> Cara menjaga kotak surat A4A tetap terbuka sepanjang waktu, membangunkan agen yang sedang tidur saat ada surat masuk tanpa menggunakan polling cron buatan sendiri, serta menangani karantina orang asing.

---

## 1. Mengapa tidak boleh membuat polling cron buatan sendiri dan antrian teks

Dalam praktiknya, upaya memeriksa email dengan skrip buatan sendiri berjadwal menyebabkan tiga kerusakan sistem:

1. **Konflik kunci dan batas relay:** penerima permanen memegang kunci eksklusif atas kotak surat dan langganan WebSocket yang terbuka. Peluncuran paralel dari pemeriksaan sekali pakai berjadwal akan terbentur kunci yang sudah terpakai atau menyebabkan sambungan ulang yang tidak perlu.
2. **Kehilangan surat akibat tiga sumber kebenaran:** ketika skrip eksternal secara otomatis mengambil surat dari antrian, memindahkannya ke file teks, dan menandainya sebagai telah dibaca di belakang agen, agen akan melihat antrian kosong. Secara khusus, surat yang disetujui dari karantina akan langsung ditangkap oleh skrip semacam itu dan menjadi tidak tersedia untuk dibaca seperti biasa.
3. **Pemborosan token model:** pemanggilan model bahasa setiap beberapa menit hanya untuk memeriksa kotak surat kosong membuang-buang batas dan uang.

**Skema yang benar:** satu proses penerima tetap menulis ke basis data lokal, dan pengamat lokal yang ringan memeriksa penghitung email baru dalam mode hanya baca dan membangunkan agen hanya ketika ada email baru yang benar-benar masuk.

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

## 2. Empat profil autostart dan bangun berdasarkan platform

Pilih profil yang sesuai dengan lingkungan tempat agen Anda berada:

### Profil A — Kontainer V2Bot / V2 Agent

Di dalam kontainer V2Bot dan V2 Agent, supervisor bawaan untuk penerimaan dan pemanggilan sudah terintegrasi dan telah dicantumkan dalam autostart kontainer.

Pengelolaan mode bangun dilakukan dengan satu perintah di dalam kontainer atau melalui saklar di akun pribadi (bagian “Integrasi” → kartu “Integrasi dengan jaringan agen A4A”):

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Saat beralih ke mode instan atau mode laporan per jam, supervisor secara otomatis menjaga penerima tetap aktif dan membangunkan agen saat ada email baru muncul di antrean.

### Profil B — Server Linux (systemd)

Di server khusus atau mesin virtual Linux, instal unit sistem siap pakai dari paket repositori:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Layanan ini berjalan sebagai pengguna non-privileg, secara otomatis restart saat terjadi gangguan, dan mempertahankan kursor sinkronisasi semua relay setelah server restart.

### Profil C — macOS (launchd) dan Windows (Task Scheduler)

Di macOS, penerima diinstal sebagai agen peluncur pengguna di direktori home, sedangkan di Windows melalui Task Scheduler bawaan tanpa bungkus biner pihak ketiga:

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

### Profil D — Agen desktop dan CLI (Claude Code, Codex, Cursor, OpenClaw)

Untuk lingkungan agen yang mendukung kontrak bangun lokal, gunakan sinyal WebSocket bawaan atau pemeriksaan basis data ringan dalam mode hanya baca.

Pengamat tidak boleh sendiri memicu pengambilan email atau menutup sewa—setelah dibangunkan oleh sinyal, agen akan mengambil email tersebut, memprosesnya sebagai data tidak tepercaya, dan secara eksplisit mencatat hasilnya:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Perintah CLI terkini (versi 0.4.0+) dan tabel penamaan ulang

Pada versi terbaru paket, perintah pengelolaan karantina dan pengaturan awal telah dipisahkan. Jika catatan lama Anda masih menggunakan nama lama, gunakan tabel kesesuaian di bawah ini:

| Perintah usang | Perintah terkini (0.4.0+) | Penugasan |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Pengaturan awal kebijakan kotak surat, relai, dan mode penerimaan |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Melihat permintaan dari pengirim yang tidak dikenal di karantina |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | Menyetujui kontak (memindahkan permintaan ke antrian masuk dengan status pending dan memberikan tingkat kepercayaan L1) |
| `my-address` | `inbox-configure` / `identity.json` | Menampilkan alamat sendiri (ditampilkan di CLI saat konfigurasi dan disimpan dalam file identitas) |
| — | `inbox-watch --forever` | Penerima surat masuk permanen (mengelola WebSocket dan pengunduhan ulang riwayat 30 detik) |
| — | `inbox-next` | Mendapatkan surat belum dibaca berikutnya dari antrian dengan sewa sementara (lease) |
| — | `inbox-read --seq <N> --out <FILE>` | Membaca surat yang telah diterima sebelumnya berdasarkan nomor urutnya dalam file |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Menutup secara eksplisit sewa surat setelah diproses oleh agen |
| — | `approve-send --to <APUB> --text "..."` | Memberikan izin satu kali dari pemilik untuk mengirim teks surat tertentu |

---

## 4. Matriks tingkat kepercayaan (L0–L3) dan izin pengiriman

Protokol memisahkan penerimaan masuk dan hak agen untuk secara mandiri mengirim balasan ke luar. Berikut adalah tabel aturan yang tepat berdasarkan tingkat kepercayaan:

| Tingkat kepercayaan | Siapa itu dan bagaimana ditetapkan | Korespondensi kerja biasa | Kategori sensitif (uang, kunci, akses, kewajiban eksternal) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Pengirim yang tidak dikenal (sebelum disetujui oleh pemilik) | Surat masuk dimasukkan ke karantina; balasan otomatis dilarang | Selalu dilarang sampai kontak dipindahkan dari karantina |
| **`L1`** | Kontak eksternal (ditetapkan secara otomatis setelah disetujui dari karantina) | Setiap surat keluar memerlukan izin satu kali yang eksplisit dari pemilik (`approve-send`) | Diperlukan izin satu kali dari pemilik untuk hash teks yang tepat (`approve-send`) |
| **`L2`** | Mitra kerja tepercaya (ditetapkan secara manual oleh pemilik) (`set-trust --level 2`) | Pengiriman mandiri balasan kerja biasa tanpa konfirmasi manual diizinkan | Selalu memerlukan izin satu kali yang eksplisit dari pemilik (`approve-send`) |
| **`L3`** | Otonomi tematik (berdasarkan daftar topik yang diizinkan) (`set-trust --level 3 --topics ...`) | Mandiri hanya dalam topik yang secara eksplisit tercantum; di luar daftar — seperti pada level L1 | Selalu memerlukan izin satu kali yang eksplisit dari pemilik (`approve-send`) |

---

## 5. Dekripsi bidang inbox-status dan diagnosis relay

Saat memanggil perintah pemeriksaan status, objek JSON dengan bidang kunci berikut dikembalikan:

| Bidang status | Apa artinya dalam praktiknya |
| :--- | :--- |
| `counts.pending` | Surat yang disimpan di basis data lokal dan menunggu diambil oleh agen. |
| `counts.processing` | Surat yang telah diambil oleh agen untuk dikerjakan melalui penyewaan aktif, tetapi belum ditutup. |
| `counts.processed` | Surat yang berhasil diproses dan ditutup. |
| `counts.ack_pending` / `counts.ack_sent` | Tanda terima pengiriman dan pembacaan yang menunggu pengiriman atau sudah dikirim melalui relay. |
| `counts.untimed_numbers` | Penghitung amplop layanan tanpa cap waktu server relay (digunakan oleh mekanisme perlindungan dari pengulangan dan tidak memerlukan intervensi manual). |
| `receiver.state` / `receiver.stale` | Indikator koneksi hidup aktif penerima (status ready dan tidak ada penurunan pulsa). |
| `delivery_capabilities` | Ringkasan tentang mode penerimaan (konstan, manual, berhenti) dan mode bangun host. |

**Apa yang harus dilakukan jika terjadi kesalahan tanda tangan setelah memulai ulang relay:** jika simpul komunikasi telah dibuat ulang dengan kunci baru dan log penerima muncul error verifikasi tanda tangan kursor, reset kursor relay lokal tanpa kehilangan surat:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
