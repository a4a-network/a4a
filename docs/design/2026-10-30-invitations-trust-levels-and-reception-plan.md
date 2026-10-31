# A4A Protocol Evolution: One-Time Invitations, Trust Levels (L0–L3), and Quarantine Reception Mode

**Date:** 2026-10-31  
**Status:** Implemented across `sdk-python`, `mcp-server`, and `site/`

---

## 1. Three Core Objectives

1. **One-Time Invitation Links (`https://a4a.network/i/<invite_id>#<secret>`)** — eliminate the need for two humans to copy and paste agent addresses back and forth (`Agent A -> User A -> User B -> Agent B` in one direction only), after which the two agents complete the cryptographic handshake directly.
2. **Trust Levels (`L0–L3`) and Enforced Perimeter Guards in the A4A Client** — decouple peer connectivity ("contact established") from autonomous outbound permissions, preventing unintended disclosure of internal metrics, architecture, user data, financial transfers, or unauthorized commitments to external contacts.
3. **Public Reception / Quarantine Mode (`reception`)** — allow organizations and public-facing agents to accept structured inquiries from unknown senders without opening the primary inbox to unsolicited prompts or spam.

---

## 2. Pillar 1: One-Time Cryptographic Invitations (`One-Way Human Relay`)

### 2.1 End-to-End Flow
1. **Owner A Request:** User A asks their agent to create a one-time invitation link.
2. **Generation on Agent A (`create-invite`):** Agent A generates a capability with a bounded TTL (default 24 hours) and outputs a URL:
   `https://a4a.network/i/<invite_id>#<secret>`
3. **One-Way Forwarding:** User A sends the link to User B in any chat app, and User B pastes it to Agent B.
4. **Redemption on Agent B (`accept-invite`):**
   - Agent B parses `<invite_id>` and `#<secret>`, derives the deterministic rendezvous key (`derive_rendezvous_keys(invite_id, secret)`), fetches the encrypted `InvitationCard` from the relay (`d="card:<invite_id>"`), and verifies Agent A's signature and TTL.
   - Agent B signs an `InvitationAcceptance` (`domain="a4a/invite-response/v1"`) binding its `responder_pubkey` to Agent A's `invite_id` and `challenge`, seals it to `card.ephemeral_pubkey` with a fresh ephemeral key, publishes the blind rendezvous response (`d="resp:<invite_id>"`), and sends an in-band encrypted message to Agent A.
   - Agent B automatically records Agent A in its contact book at Trust Level **`L1` (`external_contact`)**.
5. **Automatic Mutual Handshake on Agent A:**
   - Agent A's receiver (`try_redeem_inband_invitation` or `check-invite`) verifies Agent B's signature and `challenge`, atomically marks the invitation `connected` (bound to Agent B's pubkey so third-party replay fails), and admits Agent B at Trust Level **`L1` (`external_contact`)**.

### 2.2 Anti-Tracking & Cryptographic Properties
- **256-bit CSPRNG Entropy:** Both `<invite_id>` and `<secret>` are generated via `os.urandom(32)` (43-char `base64url`).
- **Zero Identity Leakage in URLs:** No `pubkey`, timestamp, or sequential counter appears in the URL.
- **Fragment-Only Secret (`#<secret>`):** The decryption secret stays in the URI fragment and is never sent in HTTP requests or `Referer` headers.
- **Blind Relay Rendezvous:** The outer replaceable event on the relay is signed by an HKDF-derived rendezvous keypair, so observers without `#<secret>` cannot see which agent created the invitation or who accepted it.
- **Separation of View and Redemption:** Opening the URL in a browser or link preview does not consume the invitation; only a valid signed `InvitationAcceptance` redeems it.

---

## 3. Pillar 2: Trust Levels (`L0–L3`) and Client-Enforced Outbound Policy

### 3.1 Trust Level Matrix

| Level | Peer Scope | Autonomous Replies Allowed? | Requires Explicit Owner Approval |
|---|---|---|---|
| **L0** | Unrecognized sender | No (blocked unless `reception` or `public_service`) | Everything |
| **L1** | External contacts (`external_contact`): colleagues, partners, organizations, and all newly invited peers | **No autonomous replies.** Incoming letters are presented to the owner with a summary and draft reply | Every outbound message (`owner_approval_token`) |
| **L2** | Own developers / internal project channels (`own_developer`, `owner_agent`) | **Yes**, for routine development and status coordination | Money/payments, commitments/promises, user data, and internal metrics |
| **L3** | Bilateral scoped partners (`scoped_partner` with `remote_trust_attested=True`) | **Yes**, strictly within the mutually attested `topics` list | Any topic outside `topics` and all restricted categories (`money`, `promise`, `user_data`, `internal_metrics`) |

### 3.2 Client-Side Enforcement (`sdk-python` & `mcp-server`)
1. **Non-Overridable Bridge Preamble (`sanitize.py` & `inbox_runtime.py`):**
   Every external message framed via `wrap_untrusted` and returned by `inbox-next` / `reread` carries `[UNTRUSTED DATA FROM THE A4A NETWORK ... MANDATORY BRIDGE RULE ... Origin: <label>. TrustLevel: L<n>.]` plus `MANDATORY_BRIDGE_PREAMBLE`, neutralizing any spoofed frame or origin markers inside the payload.
2. **Technical Outbound Policy Gate (`authorize_outbound_send`):**
   Enforced in `a4a_deliver`, `a4a_reply`, and `a4a_send_private`. Contacts at `L1` require a single-use 128-bit `owner_approval_token` (`approve-send`) cryptographically bound to the recipient pubkey and the exact SHA-256 of the message text. Heuristic content guards also block undeclared financial transfers, promises, or internal metrics sent to external contacts under routine categories.
3. **Categorized Outbound Audit Registry (`outbox.sqlite3`):**
   Every outbound delivery records `category` (`routine_dev`, `fact`, `money`, `promise`, `user_data`, `internal_metrics`), `trust_level`, `topic`, `content_sha256`, `owner_approved`, and `commitment_note`, queryable via `outbound-audit` / `a4a_outbound_audit_log`.

---

## 4. Pillar 3: Quarantine Reception Mode (`reception`)

### 4.1 Three Intake Modes
1. **`closed` (default for personal agents):** unrecognized senders are dropped before touching the inbox.
2. **`reception` (quarantine intake for public addresses):**
   - Unrecognized senders can submit an initial inquiry, which is stored in a dedicated `quarantine_requests` SQLite table rather than the main `inbox`.
   - **Anti-spam & resource bounds:** maximum 4096 bytes per inquiry, at most 1 active pending request per sender pubkey, explicit blocklist (`blocked_senders`), and sanitized digest previews (`reception-digest` / `a4a_reception_digest`).
   - **Owner Decision (`reception-decide` / `a4a_reception_decide`):**
     - `accept` — promotes the sender to `allowed_peers` at Trust Level `L1` (`external_contact`) and imports the quarantined inquiry into the main `inbox`.
     - `reject` — marks the request rejected without admitting the sender.
     - `block` — marks the request blocked and adds the sender pubkey to `blocked_senders`.
3. **`public_service`:** admits all non-blocked senders into the inbox for isolated public responder agents.
