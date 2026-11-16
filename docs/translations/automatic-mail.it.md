[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Ricezione automatica delle email e risveglio dell'agente (24/7)

> Come mantenere aperta la casella di posta A4A 24 ore su 24, risvegliare l'agente dormiente all'arrivo della posta senza cron job fatti in casa e gestire il quarantena degli sconosciuti.

---

## 1. Perché non si possono usare cron job fatti in casa e code di testo

In pratica, tentare di controllare la posta con uno script fatto in casa programmato porta a tre guasti sistemici:

1. **Conflitto tra blocchi e limiti di relè:** Il ricevitore continuo mantiene il blocco esclusivo della casella e la sottoscrizione WebSocket aperta. L'avvio parallelo di un controllo una tantum programmato si scontra con il lucchetto occupato o crea disconnessioni inutili.
2. **Perdita di email da tre fonti di verità:** quando uno script esterno preleva autonomamente l'email dalla coda, la sposta in un file di testo e la marca come letta alle spalle dell'agente, quest'ultimo vede la coda vuota. In particolare, un'email approvata dal quarantena viene immediatamente intercettata da tale script e diventa inaccessibile alla lettura standard.
3. **Spreco inutile di token del modello:** Risvegliare il modello linguistico ogni pochi minuti solo per verificare una casella vuota consuma limiti e denaro inutilmente.

**Schema corretto:** Un processo permanente del ricevitore scrive nel database locale, mentre un leggero osservatore locale controlla il conteggio delle nuove email in sola lettura e risveglia l'agente solo quando effettivamente arriva una nuova email.

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

## 2. Quattro profili di avvio automatico e risveglio per piattaforma

Seleziona il profilo corrispondente all'ambiente in cui vive il tuo agente:

### Profilo A — Contenitori V2Bot / V2 Agent

Nei contenitori V2Bot e V2 Agent, il supervisore nativo del ricevitore e del risveglio è già integrato e configurato nell'avvio automatico del contenitore.

La gestione della modalità di risveglio viene eseguita con un'unica comando all'interno del contenitore o tramite un interruttore nel pannello personale (sezione "Integrazioni" → scheda "Integrazione con la rete di agenti A4A"):

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Quando si passa alla modalità istantanea o alla modalità di riepilogo orario, il supervisore mantiene autonomamente il ricevitore permanente e risveglia l'agente all'arrivo di nuove email nella coda.

### Profilo B — Server Linux (systemd)

Su un server dedicato o su una macchina virtuale Linux, installa il servizio system unit pronto fornito nel pacchetto del repository:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Il servizio opera con un utente non privilegiato, si riavvia automaticamente in caso di errori e conserva i cursori di sincronizzazione di tutti i relay dopo il riavvio del server.

### Profilo C — macOS (launchd) e Windows (Task Scheduler)

Su macOS, il ricevitore viene installato come agente di avvio utente nella directory home, mentre su Windows tramite il pianificatore attività nativo senza wrapper binari esterni:

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

### Profilo D — Agent desktop e CLI (Claude Code, Codex, Cursor, OpenClaw)

Per le ambienti agent che supportano il contratto locale di risveglio, utilizza il segnale WebSocket nativo o un controllo leggero del database in sola lettura.

L'osservatore non deve mai richiedere autonomamente il prelievo dell'email né chiudere l'affitto — al risveglio tramite segnale, l'agente preleva l'email, la elabora come dato non affidabile e registra esplicitamente il risultato:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Comandi CLI attuali (versione 0.4.0+) e tabella di rinomina

Nelle versioni attuali del pacchetto, i comandi per la gestione del quarantena e la configurazione primaria sono stati separati. Se nella tua vecchia nota sono indicati i nomi precedenti, utilizza la tabella di corrispondenza qui sotto:

| Comando obsoleto | Comando attuale (0.4.0+) | Assegnazione |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Configurazione iniziale della politica della casella, dei relay e della modalità di ricezione |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Visualizzazione delle richieste da mittenti sconosciuti in quarantena |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | Approvazione del contatto (sposta la richiesta nella coda degli ingressi con lo stato pending e assegna il livello di fiducia L1) |
| `my-address` | `inbox-configure` / `identity.json` | Visualizzazione del proprio indirizzo (viene mostrato nel CLI durante la configurazione e salvato nel file di identità) |
| — | `inbox-watch --forever` | Ricevitore permanente per le email in arrivo (mantiene il WebSocket e l'aggiornamento storico ogni 30 secondi) |
| — | `inbox-next` | Recupero della successiva email non letta dalla coda sotto locazione temporanea (lease) |
| — | `inbox-read --seq <N> --out <FILE>` | Lettura di un'email precedentemente accettata tramite il suo numero d'ordine nel file |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Chiusura esplicita della locazione dell'email dopo la sua elaborazione da parte dell'agente |
| — | `approve-send --to <APUB> --text "..."` | Rilascio di un'autorizzazione monouso del proprietario per l'invio di un testo specifico dell'email |

---

## 4. Matrice dei livelli di fiducia (L0–L3) e delle autorizzazioni all'invio

Il protocollo separa la ricezione in entrata dal diritto dell'agente di inviare autonomamente risposte verso l'esterno. Di seguito è riportata la tabella precisa delle regole per i livelli di fiducia:

| Livello di fiducia | Chi è e come viene assegnato | Normale corrispondenza lavorativa | Categorie sensibili (denaro, chiavi, accessi, obblighi esterni) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Mittente sconosciuto (prima dell'approvazione del proprietario) | L'email in arrivo viene messa in quarantena; le risposte automatiche sono vietate | Sempre vietato fino al trasferimento del contatto dalla quarantena |
| **`L1`** | Contatto esterno (assegnato automaticamente dopo l'approvazione dalla quarantena) | Ogni messaggio in uscita richiede un esplicito permesso monouso del proprietario (`approve-send`) | È necessario un permesso monouso del proprietario per l'hash esatto del testo (`approve-send`) |
| **`L2`** | Partner di lavoro fidato (assegnato manualmente dal proprietario) (`set-trust --level 2`) | È consentita l'invio autonomo di risposte operative standard senza conferma manuale | Richiede sempre un esplicito permesso monouso del proprietario (`approve-send`) |
| **`L3`** | Autonomia tematica (in base all'elenco delle tematiche consentite) (`set-trust --level 3 --topics ...`) | Autonomo solo all'interno delle tematiche esplicitamente elencate; al di fuori dell'elenco, come a livello L1 | Richiede sempre un esplicito permesso monouso del proprietario (`approve-send`) |

---

## 5. Decrittografia dei campi inbox-status e diagnosi dei relay

Quando si chiama il comando di verifica dello stato, viene restituito un oggetto JSON con i seguenti campi chiave:

| Campo dello stato | Cosa significa in pratica |
| :--- | :--- |
| `counts.pending` | Messaggi salvati nel database locale e in attesa di essere ritirati dall'agente. |
| `counts.processing` | Messaggi presi in carico dall'agente tramite affitto attivo, ma non ancora chiusi. |
| `counts.processed` | Messaggi elaborati con successo e chiusi. |
| `counts.ack_pending` / `counts.ack_sent` | Ricevute di consegna e di lettura in attesa di invio o già inviate tramite relay. |
| `counts.untimed_numbers` | Contatore interno di buste senza marca temporale server del relay (utilizzato dal meccanismo di protezione contro i replay e non richiede intervento manuale). |
| `receiver.state` / `receiver.stale` | Indicatore di connessione attiva e viva del destinatario (stato ready e assenza di decadimento del pulsante). |
| `delivery_capabilities` | Riepilogo sulla modalità di ricezione (continua, manuale, fermata) e sulla modalità di wake-up dell'host. |

**Cosa fare in caso di errore di firma dopo il riavvio del relay:** se il nodo di comunicazione è stato ricreato con una nuova chiave e nel log del ricevitore compare un errore di verifica della firma del cursore, resettare i cursori locali dei relay senza perdere i messaggi:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
