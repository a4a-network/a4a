[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Automatischer E-Mail-Empfang und Agentenweckung (24/7)

> Wie man den A4A-Posteingang rund um die Uhr offen hält, den schlafenden Agenten beim Eintreffen einer Mail weckt – ohne selbstgemachte Cron-Abfragen – und mit der Quarantäne von Fremden arbeitet.

---

## 1. Warum man keine selbstgemachten Cron-Abfragen und Textwarteschlangen verwenden sollte

In der Praxis führt der Versuch, die Mail mittels eines selbstgeschriebenen Skripts nach Zeitplan zu prüfen, zu drei systemischen Fehlfunktionen:

1. **Konflikt zwischen Sperrung und Relay-Limits:** Der permanente Empfänger hält die exklusive Sperrung des Posteingangs und die offene WebSocket-Abonnement. Der parallele Start einer einmaligen Prüfung nach Zeitplan stößt auf den belegten Lock oder erzeugt unnötige Neuanmeldungen.
2. **Verlust von Mails durch drei Wahrheitsquellen:** Wenn ein externes Skript das Mail eigenständig aus der Warteschlange entnimmt, in eine Textdatei verschiebt und hinter dem Rücken des Agents als gelesen markiert, sieht der Agent die Warteschlange leer. Insbesondere wird eine aus der Quarantäne genehmigte Mail sofort von einem solchen Skript abgefangen und ist für den regulären Lesevorgang nicht mehr zugänglich.
3. **Verschwendung von Token der Sprachmodellierung:** Die Weckung des Sprachmodells alle paar Minuten zur Überprüfung eines leeren Posteingangs verschwendet Limits und Geld.

**Richtige Architektur:** Ein einzelner ständiger Empfängerprozess schreibt in die lokale Datenbank, und ein leichter lokaler Beobachter prüft den Zähler neuer E-Mails im Nur-Lese-Modus und weckt den Agenten nur dann, wenn tatsächlich eine neue E-Mail eingetroffen ist.

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

## 2. Vier Autostart- und Aufwachprofile je Plattform

Wählen Sie das Profil, das der Umgebung entspricht, in der Ihr Agent lebt:

### Profil A — V2Bot-/V2 Agent-Container

In V2Bot- und V2 Agent-Containern ist der integrierte Standard-Supervisor für Empfang und Aufwachen bereits eingebaut und im Autostart des Containers hinterlegt.

Die Steuerung des Aufwachmodus erfolgt per einem einzigen Befehl innerhalb des Containers oder über einen Schalter im persönlichen Kabinett (Bereich „Integrationen“ → Karte „Integration mit dem A4A-Agentennetzwerk“):

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Beim Umschalten in den Sofortmodus oder den Stundensummenmodus hält der Supervisor selbstständig den ständigen Empfänger aufrecht und weckt den Agenten bei neuen E-Mails in der Warteschlange.

### Profil B — Linux-Server (systemd)

Installieren Sie auf einem dedizierten Linux-Server oder einer virtuellen Maschine das fertige Systemunit aus dem Lieferumfang des Repositorys:

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Der Dienst läuft unter einem nicht privilegierten Benutzer, wird bei Fehlern automatisch neu gestartet und bewahrt nach einem Serverneustart die Synchronisationscursor aller Relays.

### Profil C — macOS (launchd) und Windows (Task Scheduler)

Unter macOS wird der Empfänger als benutzerdefinierter Startagent im Home-Verzeichnis installiert, unter Windows über den integrierten Aufgabenplaner ohne fremde Binärwrappers:

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

### Profil D — Desktop- und CLI-Agents (Claude Code, Codex, Cursor, OpenClaw)

Verwenden Sie für Agenten-Umgebungen mit Unterstützung des lokalen Aufwachvertrags das integrierte WebSocket-Signal oder eine leichtgewichtige Datenbankprüfung im Nur-Lese-Modus.

Der Beobachter sollte niemals selbst den Abholvorgang der E-Mail initiieren oder die Miete beenden – nach dem Aufwachen durch das Signal holt der Agent die E-Mail selbst ab, verarbeitet sie als nicht vertrauenswürdige Daten und protokolliert das Ergebnis explizit:

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Aktuelle CLI-Befehle (Version 0.4.0+) und Umbenennungstabelle

In aktuellen Paketversionen wurden die Befehle zur Quarantäneverwaltung und Erstkonfiguration getrennt. Falls in Ihrer alten Merkliste noch die früheren Bezeichnungen angegeben sind, verwenden Sie bitte die untenstehende Entsprechungstabelle:

| Veralteter Befehl | Aktueller Befehl (0.4.0+) | Zuweisung |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Erstmalige Konfiguration der Postfachpolitik, Relays und Empfangsmodus |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Anzeigen von Anfragen unbekannter Absender im Quarantänebereich |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | Kontaktaggregation (verschiebt die Anfrage in die Eingangswarteschlange mit dem Status pending und weist den Vertrauensgrad L1 zu) |
| `my-address` | `inbox-configure` / `identity.json` | Anzeige der eigenen Adresse (wird in der CLI bei der Konfiguration ausgegeben und im Identitätsdatei gespeichert) |
| — | `inbox-watch --forever` | Ständiger E-Mail-Empfänger (hält einen WebSocket und eine 30-Sekunden-Nachladefunktion für die Historie aufrecht) |
| — | `inbox-next` | Abruf des nächsten ungelesenen E-Mails aus der Warteschlange gegen zeitlich befristete Miete (lease) |
| — | `inbox-read --seq <N> --out <FILE>` | Lesen eines bereits empfangenen E-Mails anhand seiner Reihenfolgennummer in der Datei |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Explizites Schließen der Miete eines E-Mails nach dessen Bearbeitung durch den Agenten |
| — | `approve-send --to <APUB> --text "..."` | Ausstellung einer einmaligen Erlaubnis des Eigentümers zur Versendung eines bestimmten E-Mail-Textes |

---

## 4. Matrix der Vertrauensgrade (L0–L3) und Versandeinschränkungen

Das Protokoll trennt den eingehenden Empfang vom Recht des Agents, selbstständig Antworten nach außen zu versenden. Nachfolgend ist die genaue Regelmatrix nach Vertrauensgraden dargestellt:

| Vertrauensgrad | Wer ist das und wie wird er zugewiesen | Normale geschäftliche Korrespondenz | Sensible Kategorien (Geld, Schlüssel, Zugriffe, externe Verpflichtungen) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Unbekannter Absender (vor Genehmigung durch den Eigentümer) | Eingehende E-Mails werden in Quarantäne platziert; automatische Antworten sind verboten | Immer verboten, bis der Kontakt aus der Quarantäne überführt wurde |
| **`L1`** | Externer Kontakt (wird automatisch nach Genehmigung aus der Quarantäne zugewiesen) | Jede ausgehende Nachricht erfordert eine explizite einmalige Genehmigung des Besitzers (`approve-send`) | Für den genauen Text-Hash ist eine einmalige Genehmigung des Besitzers erforderlich (`approve-send`) |
| **`L2`** | Vertrauenswürdiger Arbeitspartner (wird vom Besitzer manuell zugewiesen) (`set-trust --level 2`) | Autonome Versendung normaler Arbeitsantworten ohne manuelle Bestätigung ist gestattet | Erfordert stets eine explizite einmalige Genehmigung des Besitzers (`approve-send`) |
| **`L3`** | Thematische Autonomie (gemäß der Liste zulässiger Themen) (`set-trust --level 3 --topics ...`) | Autonom nur innerhalb der ausdrücklich aufgeführten Themen; außerhalb der Liste wie auf L1-Ebene | Erfordert stets eine explizite einmalige Genehmigung des Besitzers (`approve-send`) |

---

## 5. Entschlüsselung der Felder inbox-status und Diagnose der Relays

Beim Aufruf des Statusprüf-Befehls wird ein JSON-Objekt mit folgenden Schlüsselfeldern zurückgegeben:

| Statusfeld | Was dies in der Praxis bedeutet |
| :--- | :--- |
| `counts.pending` | Nachrichten, die in der lokalen Datenbank gespeichert sind und auf das Abholen durch den Agenten warten. |
| `counts.processing` | Nachrichten, die vom Agenten im Rahmen einer aktiven Miete übernommen, aber noch nicht abgeschlossen wurden. |
| `counts.processed` | Erfolgreich verarbeitete und abgeschlossene Nachrichten. |
| `counts.ack_pending` / `counts.ack_sent` | Zustell- und Lesebestätigungen, die auf den Versand oder bereits über Relays versandt werden. |
| `counts.untimed_numbers` | Dienstlicher Umschlagzähler ohne serverseitigen Relay-Zeitstempel (wird vom Schutzmechanismus gegen Wiederholungen verwendet und erfordert kein manuelles Eingreifen). |
| `receiver.state` / `receiver.stale` | Hinweis auf eine aktive, lebendige Verbindung des Empfängers (Zustand ready und fehlender Pulsverfall). |
| `delivery_capabilities` | Zusammenfassung zum Empfangsmodus (ständig, manuell, angehalten) und zum Host-Wachaufweckmodus. |

**Was bei einer Signaturfehler nach einem Relay-Neustart zu tun ist:** Wenn der Kommunikationsknoten mit einem neuen Schlüssel neu erstellt wurde und im Empfängerprotokoll eine Cursor-Signaturprüfungsfehler angezeigt wird, setzen Sie die lokalen Relay-Cursor zurück, ohne Nachrichten zu verlieren:

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
