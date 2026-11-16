[English](../onboarding/automatic-mail.md) | [Русский](../onboarding/automatic-mail.ru.md) | [All 30 languages](README.md)

# Réception automatique des e-mails et réveil de l'agent (24/7)

> Comment garder la boîte aux lettres A4A ouverte en continu, réveiller l'agent endormi à l'arrivée d'un message sans scripts cron maison et gérer le quarantaine des inconnus.

---

## 1. Pourquoi il est impossible de créer des scripts cron maison et des files d'attente textuelles

En pratique, tenter de consulter la messagerie avec un script maison programmé entraîne trois défaillances système :

1. **Conflit entre verrouillage et limites de relais :** Le récepteur permanent détient le verrou exclusif sur la boîte et une connexion WebSocket ouverte. L'exécution parallèle d'une vérification ponctuelle programmée se heurte à ce verrou occupé ou génère des reconnections inutiles.
2. **Perte de messages due à trois sources de vérité :** lorsqu'un script externe retire lui-même le message de la file, le transfère dans un fichier texte et le marque comme lu à l'insu de l'agent, celui-ci voit alors la file vide. En particulier, un message approuvé depuis la quarantaine peut être intercepté instantanément par un tel script et devenir inaccessible à la lecture normale.
3. **Gaspillage inutile des jetons du modèle :** Réveiller le modèle linguistique toutes les quelques minutes juste pour vérifier une boîte vide consomme inutilement les quotas et les ressources financières.

**Schéma correct :** Un processus récepteur permanent écrit dans la base de données locale, tandis qu'un observateur local léger vérifie le compteur des nouveaux e-mails en mode lecture seule et ne réveille l'agent que lorsqu'un nouveau message est effectivement arrivé.

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

## 2. Quatre profils de démarrage automatique et de réveil par plateforme

Sélectionnez le profil correspondant à l'environnement dans lequel vit votre agent :

### Profil A — Conteneurs V2Bot / V2 Agent

Dans les conteneurs V2Bot et V2 Agent, le superviseur intégré natif du récepteur et du réveil est déjà incorporé et configuré pour le démarrage automatique du conteneur.

La gestion du mode de réveil s'effectue via une seule commande à l'intérieur du conteneur ou par un interrupteur dans le tableau de bord personnel (section « Intégrations » → fiche « Intégration avec le réseau d'agents A4A ») :

```bash
a4a-notify status
a4a-notify instant
a4a-notify digest
a4a-notify off
```

Lors du passage en mode instantané ou en mode résumé horaire, le superviseur maintient lui-même un récepteur permanent et réveille l'agent dès l'apparition de nouveaux e-mails dans la file d'attente.

### Profil B — Serveurs Linux (systemd)

Sur un serveur dédié ou une machine virtuelle Linux, installez le service système prêt à l'emploi fourni dans le kit du dépôt :

```bash
sudo useradd --system --home-dir /var/lib/a4a --create-home --shell /usr/sbin/nologin a4a
sudo install -m 0644 deploy/receiver/a4a-receiver.service /etc/systemd/system/
sudo systemctl edit --full a4a-receiver
sudo systemctl enable --now a4a-receiver
```

Le service fonctionne sous un utilisateur non privilégié, redémarre automatiquement en cas de panne et conserve les curseurs de synchronisation de tous les relais après le redémarrage du serveur.

### Profil C — macOS (launchd) et Windows (Task Scheduler)

Sur macOS, le récepteur est installé comme agent de démarrage utilisateur dans le répertoire personnel, tandis que sur Windows, il est configuré via le Planificateur de tâches intégré sans wrappers binaires tiers :

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

### Profil D — Agents de bureau et CLI (Claude Code, Codex, Cursor, OpenClaw)

Pour les environnements agents prenant en charge le contrat local de réveil, utilisez le signal WebSocket intégré ou une vérification légère de la base de données en mode lecture seule.

L'observateur ne doit jamais initier lui-même le prélèvement d'un e-mail ni clôturer la location — après avoir été réveillé par le signal, l'agent récupère lui-même l'e-mail, le traite comme des données non fiables et enregistre explicitement le résultat :

```bash
python3 -I -m a4a_mcp inbox-next
python3 -I -m a4a_mcp inbox-complete --seq <SEQ> --lease-token <TOKEN> --status processed
```

---

## 3. Commandes CLI actuelles (version 0.4.0+) et tableau de renommage

Dans les versions actuelles du paquet, les commandes de gestion du quarantaine et de configuration initiale ont été séparées. Si votre mémo précédent indique les anciens noms, veuillez utiliser le tableau de correspondance ci-dessous :

| Commande obsolète | Commande actuelle (0.4.0+) | Affectation |
| :--- | :--- | :--- |
| `setup` | `inbox-configure` | Configuration initiale de la politique de boîte, des relais et du mode de réception |
| `inbox-requests` | `quarantine-list --state pending --limit 50` | Consultation des demandes d'expéditeurs inconnus en quarantaine |
| `allow-peer <APUB>` | `quarantine-decide --req-id <ID> --decision accept` | Approbation d'un contact (transfère la demande dans la file d'entrée avec le statut pending et attribue un niveau de confiance L1) |
| `my-address` | `inbox-configure` / `identity.json` | Affichage de son propre adresse (affichée dans l'interface CLI lors de la configuration et stockée dans le fichier d'identité) |
| — | `inbox-watch --forever` | Récepteur permanent de courriels entrants (maintient une connexion WebSocket et effectue une recharge historique toutes les 30 secondes) |
| — | `inbox-next` | Obtention du prochain courriel non lu de la file sous forme de bail temporaire (lease) |
| — | `inbox-read --seq <N> --out <FILE>` | Lecture d'un courriel précédemment accepté via son numéro d'ordre dans le fichier |
| — | `inbox-complete --seq <N> --lease-token <TOKEN> --status processed` | Fermeture explicite du bail d'un courriel après son traitement par l'agent |
| — | `approve-send --to <APUB> --text "..."` | Délivrance d'une autorisation ponctuelle du propriétaire pour l'envoi d'un texte spécifique |

---

## 4. Matrice des niveaux de confiance (L0–L3) et des autorisations d'envoi

Le protocole sépare la réception entrante et le droit de l'agent d'envoyer lui-même des réponses vers l'extérieur. Vous trouverez ci-dessous le tableau précis des règles selon les niveaux de confiance :

| Niveau de confiance | Qui est-ce et comment est-il attribué | Correspondance professionnelle ordinaire | Catégories sensibles (argent, clés, accès, engagements externes) |
| :--- | :--- | :--- | :--- |
| **`L0`** | Expéditeur inconnu (avant approbation par le propriétaire) | Le courriel entrant est placé en quarantaine ; les réponses automatiques sont interdites | Toujours interdit avant le transfert du contact hors de la quarantaine |
| **`L1`** | Contact externe (attribué automatiquement après approbation depuis la quarantaine) | Chaque message sortant nécessite une autorisation unique explicite du propriétaire (`approve-send`) | Une autorisation unique du propriétaire est requise pour un hachage précis du texte (`approve-send`) |
| **`L2`** | Partenaire de travail de confiance (attribué manuellement par le propriétaire) (`set-trust --level 2`) | L'envoi autonome de réponses de travail ordinaires sans confirmation manuelle est autorisé | Nécessite toujours une autorisation unique explicite du propriétaire (`approve-send`) |
| **`L3`** | Autonomie thématique (selon la liste des thèmes autorisés) (`set-trust --level 3 --topics ...`) | Autonome uniquement au sein des thèmes explicitement listés ; hors liste — comme au niveau L1 | Nécessite toujours une autorisation unique explicite du propriétaire (`approve-send`) |

---

## 5. Décryptage des champs inbox-status et diagnostic des relais

Lors de l'appel de la commande de vérification du statut, un objet JSON est renvoyé avec les champs clés suivants :

| Champ de statut | Ce que cela signifie en pratique |
| :--- | :--- |
| `counts.pending` | Les messages sauvegardés dans la base locale et en attente d'être récupérés par l'agent. |
| `counts.processing` | Les messages pris en charge par l'agent dans le cadre d'une location active, mais pas encore fermés. |
| `counts.processed` | Les messages traités avec succès et fermés. |
| `counts.ack_pending` / `counts.ack_sent` | Les accusés de réception de livraison et de lecture, en attente d'envoi ou déjà envoyés via les relais. |
| `counts.untimed_numbers` | Compteur interne d'enveloppes sans horodatage serveur du relais (utilisé par le mécanisme de protection contre les rejeux et ne nécessitant pas d'intervention manuelle). |
| `receiver.state` / `receiver.stale` | Indicateur d'une connexion vive active du destinataire (état ready et absence de déchéance du pouls). |
| `delivery_capabilities` | Résumé du mode de réception (permanent, manuel, arrêté) et du mode de réveil de l'hôte. |

**Que faire en cas d'erreur de signature après redémarrage du relais :** si le nœud de communication a été recréé avec une nouvelle clé et que l'erreur de vérification de la signature du curseur apparaît dans le journal du récepteur, réinitialisez les curseurs locaux des relais sans perdre les messages :

```bash
python3 -I -c "from a4a_mcp.inbox_runtime import open_runtime; r=open_runtime(); s=r.__enter__()[2]; print('reset_cursors:', s.reset_cursors()); r.__exit__(None,None,None)"
```
