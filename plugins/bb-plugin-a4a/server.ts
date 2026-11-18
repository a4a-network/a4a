import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  PluginCliError,
  cliCommand,
  defineCli,
  type BbPluginApi,
} from "@get-bb/plugin-sdk";
import { z } from "zod";
import {
  DEFAULT_ACTIVE_RELAYS,
  STANDBY_RELAYS,
  a4aRpcContract,
  type A4ADashboard,
} from "./contract.js";

const execFileAsync = promisify(execFile);

export interface Stage1Config {
  detected: boolean;
  agentsMdPath: string | null;
  a4aHome: string | null;
  relays: string | null;
  pythonExecutable: string | null;
}

export function detectStage1Config(customBbDir?: string): Stage1Config {
  const bbDir =
    customBbDir ||
    (process.env.BB_DATA_DIR && process.env.BB_DATA_DIR.trim()) ||
    join(homedir(), ".bb");
  const agentsMdPath = join(bbDir, "AGENTS.md");
  if (!existsSync(agentsMdPath)) {
    return {
      detected: false,
      agentsMdPath: null,
      a4aHome: null,
      relays: null,
      pythonExecutable: null,
    };
  }
  try {
    const text = readFileSync(agentsMdPath, "utf8");
    if (!text.includes("<!-- A4A_BB_AGENT_INSTRUCTIONS_START -->")) {
      return {
        detected: false,
        agentsMdPath,
        a4aHome: null,
        relays: null,
        pythonExecutable: null,
      };
    }
    const homeMatch = text.match(/-\s*\*\*A4A_HOME\*\*:\s*`([^`]+)`/);
    const relayMatch = text.match(/-\s*\*\*A4A_RELAY\*\*:\s*`([^`]+)`/);
    const pyMatch = text.match(
      /-\s*\*\*Python\s*\/\s*CLI\*\*:\s*`"([^"]+)"\s+-I\s+-m\s+a4a_mcp`/,
    );
    return {
      detected: true,
      agentsMdPath,
      a4aHome: homeMatch?.[1]?.trim() ?? null,
      relays: relayMatch?.[1]?.trim() ?? null,
      pythonExecutable: pyMatch?.[1]?.trim() ?? null,
    };
  } catch {
    return {
      detected: false,
      agentsMdPath: null,
      a4aHome: null,
      relays: null,
      pythonExecutable: null,
    };
  }
}

export function resolveDefaultPython(stage1: Stage1Config): string {
  if (stage1.pythonExecutable && existsSync(stage1.pythonExecutable)) {
    return stage1.pythonExecutable;
  }
  const home = homedir();
  const candidates =
    process.platform === "win32"
      ? [
          join(home, ".a4a-venv", "Scripts", "python.exe"),
          "C:\\Projects\\a4a\\mcp-server\\.venv\\Scripts\\python.exe",
        ]
      : [join(home, ".a4a-venv", "bin", "python")];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return process.platform === "win32" ? "python" : "python3";
}

export function resolveDefaultHome(stage1: Stage1Config): string {
  if (stage1.a4aHome) return stage1.a4aHome;
  if (process.env.A4A_HOME && process.env.A4A_HOME.trim()) {
    return process.env.A4A_HOME.trim();
  }
  return join(homedir(), ".a4a", "bb-agent");
}

export interface A4ARunnerConfig {
  a4aHome: string;
  pythonExecutable: string;
  relays: string;
  agentName: string;
  wakeThreadId: string;
  autoReceiver: boolean;
  stage1: Stage1Config;
}

export interface A4ABackendAdapter {
  getDashboard(cfg: A4ARunnerConfig): Promise<A4ADashboard>;
  runCli(
    cfg: A4ARunnerConfig,
    args: string[],
  ): Promise<{ ok: boolean; stdout: string; stderr: string }>;
}

const DASHBOARD_PY_SCRIPT = `
import json, os, sys, sqlite3
import importlib.metadata as meta

sys.stdout.reconfigure(encoding="utf-8")
from a4a import Keys
from a4a_mcp import identity, inbox_runtime

home = os.environ.get("A4A_HOME", "")
relays_env = os.environ.get("A4A_RELAY", "")
pkg_ver = "unknown"
try:
    pkg_ver = meta.version("a4a-mcp")
except Exception:
    pass

configured = (identity.IDENTITY_DIR / "identity.json").is_file() and (identity.IDENTITY_DIR / "inbox-policy.json").is_file()
apub = None
pub_hex = None
if (identity.IDENTITY_DIR / "identity.json").is_file():
    try:
        k = identity.load_or_create_identity()
        pub_hex = k.pubkey_hex
        apub = k.apub
    except Exception:
        pass

st = inbox_runtime.status()
counts = st.get("counts") or {}
rec = st.get("receiver") or {}
rf = st.get("relay_failover") or {}

pol = None
try:
    pol = inbox_runtime.load_policy()
except Exception:
    pass

contacts = []
peer_labels = {}
if pol is not None:
    pt = getattr(pol, "peer_trust", {}) or {}
    pn = getattr(pol, "peer_notes", {}) or {}
    for pk in sorted(pol.allowed_peers):
        tinfo = pt.get(pk) if isinstance(pt.get(pk), dict) else {}
        lbl = str(tinfo.get("label") or pn.get(pk) or pk[:12])
        peer_labels[pk] = lbl
        try:
            c_apub = Keys.encode_apub(pk)
        except Exception:
            c_apub = pk
        contacts.append({
            "pubkey": pk,
            "apub": c_apub,
            "label": lbl,
            "project": str(tinfo.get("project") or ""),
            "role": str(tinfo.get("role") or ""),
            "notes": str(pn.get(pk) or ""),
            "trustLevel": int(tinfo.get("level") or 1),
            "origin": str(tinfo.get("origin") or "external_contact"),
        })

recent_messages = []
quarantine_reqs = []
db_path = identity.IDENTITY_DIR / "inbox" / "inbox.sqlite3"
if db_path.is_file():
    try:
        from a4a.event import Event
        from a4a.seal import open_seal
        k = identity.load_or_create_identity()
        con = sqlite3.connect(str(db_path))
        rows = con.execute("SELECT seq, sender, delivery_id, received, state, envelope FROM messages ORDER BY seq DESC LIMIT 15").fetchall()
        for seq, sender, did, rcv, mstate, env_raw in rows:
            txt = ""
            try:
                ev = Event(**json.loads(env_raw))
                inner = open_seal(ev, k)
                payload = json.loads(inner.content) if inner.content.startswith("{") else {"text": inner.content}
                txt = str(payload.get("text") or payload.get("body") or inner.content)
            except Exception:
                txt = "(encrypted envelope)"
            try:
                s_apub = Keys.encode_apub(sender)
            except Exception:
                s_apub = sender
            recent_messages.append({
                "seq": int(seq),
                "sender": str(sender),
                "senderApub": str(s_apub),
                "senderLabel": peer_labels.get(sender, str(s_apub)[:18]),
                "deliveryId": str(did or ""),
                "receivedAt": float(rcv or 0.0),
                "state": str(mstate or ""),
                "content": txt[:1000],
            })
        qrows = con.execute("SELECT req_id, sender_pubkey, sender_apub, received_at, status, preview FROM quarantine_requests WHERE status = 'quarantined' ORDER BY received_at DESC LIMIT 20").fetchall()
        for qid, spk, sapub, qrcv, qst, qprev in qrows:
            quarantine_reqs.append({
                "reqId": str(qid),
                "senderPubkey": str(spk),
                "senderApub": str(sapub),
                "receivedAt": float(qrcv or 0.0),
                "status": str(qst),
                "preview": str(qprev or "")[:400],
            })
        con.close()
    except Exception:
        pass

deg_map = {}
for u, v in (rf.get("degraded_relays") or {}).items():
    if isinstance(v, dict):
        deg_map[str(u)] = str(v.get("last_error") or v.get("status") or "degraded")
    else:
        deg_map[str(u)] = str(v)

prom = rf.get("promoted_relays") or {}
prom_list = list(prom.get("effective_relays") or []) if isinstance(prom, dict) and prom.get("active") else []

out = {
    "configured": bool(configured),
    "packageVersion": pkg_ver,
    "addressApub": apub,
    "addressHex": pub_hex,
    "cardUrl": f"https://a4a.network/c/#{apub}" if apub else None,
    "inviteOneLiner": f"Connect A4A (https://a4a.network/docs/connect-agent.txt) and message my agent {apub}" if apub else None,
    "receiverState": str(rec.get("state") or "unknown"),
    "receiverStale": bool(rec.get("stale", True)),
    "pendingCount": int(counts.get("pending") or 0),
    "processedCount": int(counts.get("processed") or 0),
    "quarantineCount": len(quarantine_reqs),
    "contactsCount": len(contacts),
    "relayFailover": {
        "activeRelays": list(rf.get("active_relays") or st.get("relays") or []),
        "standbyRelays": list(rf.get("standby_relays") or st.get("standby_relays") or []),
        "failoverActive": bool(rf.get("failover_active", False)),
        "degradedRelays": deg_map,
        "promotedRelays": prom_list,
    },
    "recentMessages": recent_messages,
    "quarantineRequests": quarantine_reqs,
    "contacts": contacts,
    "error": None,
}
print(json.dumps(out, ensure_ascii=False))
`;

export function createSubprocessAdapter(): A4ABackendAdapter {
  return {
    async runCli(cfg, args) {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        A4A_HOME: cfg.a4aHome,
        A4A_RELAY: cfg.relays,
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      };
      try {
        const { stdout, stderr } = await execFileAsync(
          cfg.pythonExecutable,
          ["-I", "-m", "a4a_mcp", ...args],
          { env, timeout: 45_000, maxBuffer: 8 * 1024 * 1024 },
        );
        return { ok: true, stdout: stdout.trim(), stderr: stderr.trim() };
      } catch (err: unknown) {
        const e = err as { stdout?: string; stderr?: string; message?: string };
        return {
          ok: false,
          stdout: (e.stdout ?? "").trim(),
          stderr: (e.stderr || e.message || "a4a_mcp command failed").trim(),
        };
      }
    },

    async getDashboard(cfg) {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        A4A_HOME: cfg.a4aHome,
        A4A_RELAY: cfg.relays,
        PYTHONIOENCODING: "utf-8",
        PYTHONUTF8: "1",
      };
      try {
        const { stdout } = await execFileAsync(
          cfg.pythonExecutable,
          ["-I", "-c", DASHBOARD_PY_SCRIPT],
          { env, timeout: 15_000, maxBuffer: 4 * 1024 * 1024 },
        );
        const parsed = JSON.parse(stdout.trim());
        return {
          ...parsed,
          a4aHome: cfg.a4aHome,
          pythonExecutable: cfg.pythonExecutable,
          stage1Detected: cfg.stage1.detected,
          stage1AgentsMdPath: cfg.stage1.agentsMdPath,
          wakeThreadId: cfg.wakeThreadId,
          autoReceiver: cfg.autoReceiver,
        };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          configured: false,
          a4aHome: cfg.a4aHome,
          pythonExecutable: cfg.pythonExecutable,
          packageVersion: "not-installed",
          stage1Detected: cfg.stage1.detected,
          stage1AgentsMdPath: cfg.stage1.agentsMdPath,
          addressApub: null,
          addressHex: null,
          cardUrl: null,
          inviteOneLiner: null,
          receiverState: "stopped",
          receiverStale: true,
          pendingCount: 0,
          processedCount: 0,
          quarantineCount: 0,
          contactsCount: 0,
          wakeThreadId: cfg.wakeThreadId,
          autoReceiver: cfg.autoReceiver,
          relayFailover: {
            activeRelays: cfg.relays
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
            standbyRelays: [...STANDBY_RELAYS],
            failoverActive: false,
            degradedRelays: {},
            promotedRelays: [],
          },
          recentMessages: [],
          quarantineRequests: [],
          contacts: [],
          error: msg,
        };
      }
    },
  };
}

export interface A4APluginOptions {
  adapter?: A4ABackendAdapter;
  bbDataDir?: string;
}

const JSON_OPTION = {
  type: "boolean" as const,
  description: "Format output as JSON",
};

export function createA4APlugin(options: A4APluginOptions = {}) {
  const adapter = options.adapter ?? createSubprocessAdapter();

  return async function a4aPlugin(bb: BbPluginApi): Promise<void> {
    const stage1 = detectStage1Config(options.bbDataDir);

    const settings = bb.settings.define({
      a4aHome: {
        type: "string",
        label: "A4A Home Directory (A4A_HOME)",
        description:
          "Dedicated directory storing identity.json, inbox-policy.json, and inbox.sqlite3. Automatically adopts Stage 1 ~/.bb/AGENTS.md if left blank.",
        default: "",
      },
      relays: {
        type: "string",
        label: "Active Relays (3 active + 4 hot-standby)",
        description:
          "Comma-separated active relay URLs (default: ru1, ru2, eu1 with eu2, us2, us1, sg1 as automatic hot-standby).",
        default: DEFAULT_ACTIVE_RELAYS,
      },
      pythonExecutable: {
        type: "string",
        label: "Python Executable Path",
        description:
          "Path to the Python interpreter with a4a-sdk and a4a-mcp installed (~/.a4a-venv). Auto-detected if blank.",
        default: "",
      },
      agentName: {
        type: "string",
        label: "Agent Display Name",
        description: "Public display name published on your A4A contact card.",
        default: "bb AI Agent",
      },
      wakeThreadId: {
        type: "string",
        label: "Wake Target Thread ID (Optional)",
        description:
          "If set, incoming A4A letters enqueue a metadata-only [A4A Wake v1] hint into this bb thread.",
        default: "",
      },
      autoReceiver: {
        type: "boolean",
        label: "Automatic Background Receiver",
        description:
          "Run the model-free A4A inbox sync and E2EE receipt ACK worker in the background.",
        default: true,
      },
    });

    let currentSettings = await settings.get();
    settings.onChange((next) => {
      currentSettings = next;
    });

    function getRunnerConfig(): A4ARunnerConfig {
      const freshStage1 = detectStage1Config(options.bbDataDir);
      const effectiveStage1 = freshStage1.detected ? freshStage1 : stage1;
      const a4aHome =
        currentSettings.a4aHome.trim() || resolveDefaultHome(effectiveStage1);
      const pythonExecutable =
        currentSettings.pythonExecutable.trim() ||
        resolveDefaultPython(effectiveStage1);
      const relays =
        currentSettings.relays.trim() ||
        effectiveStage1.relays ||
        DEFAULT_ACTIVE_RELAYS;
      return {
        a4aHome,
        pythonExecutable,
        relays,
        agentName: currentSettings.agentName.trim() || "bb AI Agent",
        wakeThreadId: currentSettings.wakeThreadId.trim(),
        autoReceiver: currentSettings.autoReceiver,
        stage1: effectiveStage1,
      };
    }

    async function readNextAndComplete(cfg: A4ARunnerConfig): Promise<{
      ok: boolean;
      claimed: boolean;
      messageText: string;
    }> {
      await adapter.runCli(cfg, ["inbox-watch", "--once"]);
      const nextRes = await adapter.runCli(cfg, ["inbox-next"]);
      if (!nextRes.ok) {
        return {
          ok: false,
          claimed: false,
          messageText: nextRes.stderr || nextRes.stdout,
        };
      }
      try {
        const parsed = JSON.parse(nextRes.stdout);
        const msg = parsed.message ?? parsed;
        if (msg && typeof msg.seq === "number" && msg.lease_token) {
          await adapter.runCli(cfg, [
            "inbox-complete",
            "--seq",
            String(msg.seq),
            "--lease-token",
            String(msg.lease_token),
            "--status",
            "processed",
          ]);
          return {
            ok: true,
            claimed: true,
            messageText: JSON.stringify(parsed, null, 2),
          };
        }
      } catch {
        // non-JSON or empty queue notice
      }
      return {
        ok: true,
        claimed: false,
        messageText: nextRes.stdout || "No pending messages.",
      };
    }

    // 1. Register Typed RPC Handlers for Frontend UI (app.tsx)
    bb.rpc.register(a4aRpcContract, {
      async getDashboard() {
        return await adapter.getDashboard(getRunnerConfig());
      },

      async setupMailbox(input) {
        const cfg = getRunnerConfig();
        if (input.a4aHome?.trim()) {
          cfg.a4aHome = input.a4aHome.trim();
        }
        if (input.relays?.trim()) {
          cfg.relays = input.relays.trim();
        }
        const name = input.agentName?.trim() || cfg.agentName;
        const res = await adapter.runCli(cfg, [
          "setup",
          "--agent-name",
          name,
          "--relays",
          cfg.relays,
          "--bb",
        ]);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          message: res.ok
            ? res.stdout || "A4A mailbox configured."
            : res.stderr || res.stdout,
          dashboard,
        };
      },

      async syncNow() {
        const cfg = getRunnerConfig();
        const res = await adapter.runCli(cfg, ["inbox-watch", "--once"]);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          message: res.ok
            ? "Synced with active A4A relays."
            : res.stderr || res.stdout,
          dashboard,
        };
      },

      async readNextMessage() {
        const cfg = getRunnerConfig();
        const res = await readNextAndComplete(cfg);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ...res,
          dashboard,
        };
      },

      async sendMessage(input) {
        const cfg = getRunnerConfig();
        if (input.label?.trim()) {
          await adapter.runCli(cfg, [
            "allow-peer",
            input.to.trim(),
            "--label",
            input.label.trim(),
          ]);
        }
        const res = await adapter.runCli(cfg, [
          "deliver",
          "--to",
          input.to.trim(),
          "--new-letter",
          "--owner-approved",
          "--text",
          input.text,
        ]);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          resultText: res.ok ? res.stdout : res.stderr || res.stdout,
          dashboard,
        };
      },

      async replyMessage(input) {
        const cfg = getRunnerConfig();
        const res = await adapter.runCli(cfg, [
          "reply",
          "--seq",
          String(input.seq),
          "--owner-approved",
          "--text",
          input.text,
        ]);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          resultText: res.ok ? res.stdout : res.stderr || res.stdout,
          dashboard,
        };
      },

      async createInvite(input) {
        const cfg = getRunnerConfig();
        const ttl = input.ttlSeconds ?? 86400;
        const res = await adapter.runCli(cfg, [
          "create-invite",
          "--ttl",
          String(ttl),
          "--label",
          input.label.trim(),
        ]);
        if (!res.ok) {
          return {
            ok: false,
            inviteUrl: null,
            inviteId: null,
            expiresAt: null,
            error: res.stderr || res.stdout,
          };
        }
        try {
          const parsed = JSON.parse(res.stdout);
          return {
            ok: true,
            inviteUrl: parsed.invitation_url ?? parsed.url ?? null,
            inviteId: parsed.invite_id ?? null,
            expiresAt:
              typeof parsed.expires_at === "number" ? parsed.expires_at : null,
            error: null,
          };
        } catch {
          return {
            ok: true,
            inviteUrl: res.stdout,
            inviteId: null,
            expiresAt: null,
            error: null,
          };
        }
      },

      async acceptInvite(input) {
        const cfg = getRunnerConfig();
        const args = ["accept-invite", "--url", input.url.trim()];
        if (input.intro?.trim()) {
          args.push("--intro", input.intro.trim());
        }
        const res = await adapter.runCli(cfg, args);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          resultText: res.ok ? res.stdout : res.stderr || res.stdout,
          dashboard,
        };
      },

      async decideQuarantine(input) {
        const cfg = getRunnerConfig();
        const args = [
          "quarantine-decide",
          "--req-id",
          input.reqId.trim(),
          "--decision",
          input.decision,
        ];
        if (input.decision === "accept") {
          args.push(
            "--label",
            input.label?.trim() || "Admitted Contact (via bb UI)",
          );
        }
        const res = await adapter.runCli(cfg, args);
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          resultText: res.ok ? res.stdout : res.stderr || res.stdout,
          dashboard,
        };
      },

      async saveContact(input) {
        const cfg = getRunnerConfig();
        const args = [
          "contacts-set",
          "--peer",
          input.peer.trim(),
          "--label",
          input.label.trim(),
        ];
        if (input.project !== undefined)
          args.push("--project", input.project.trim());
        if (input.role !== undefined) args.push("--role", input.role.trim());
        if (input.notes !== undefined) args.push("--notes", input.notes.trim());
        const res = await adapter.runCli(cfg, args);
        if (input.trustLevel !== undefined) {
          await adapter.runCli(cfg, [
            "set-trust",
            "--peer",
            input.peer.trim(),
            "--trust-level",
            String(input.trustLevel),
            "--label",
            input.label.trim(),
          ]);
        }
        if (input.syncRelays) {
          await adapter.runCli(cfg, [
            "contacts-sync",
            "--direction",
            "both",
          ]);
        }
        const dashboard = await adapter.getDashboard(cfg);
        return {
          ok: res.ok,
          resultText: res.ok ? res.stdout : res.stderr || res.stdout,
          dashboard,
        };
      },
    });

    // 2. Register Native Dynamic Agent Tools (available across all bb providers)
    bb.agents.registerTool({
      name: "a4a_my_address",
      description:
        "Return this bb agent's A4A E2EE apub1... address, 64-hex pubkey, shareable QR card URL, and 3+4 relay health status.",
      parameters: z.object({}),
      async execute() {
        const dash = await adapter.getDashboard(getRunnerConfig());
        return JSON.stringify(
          {
            configured: dash.configured,
            a4a_home: dash.a4aHome,
            apub: dash.addressApub,
            pubkey_hex: dash.addressHex,
            card_url: dash.cardUrl,
            invite_one_liner: dash.inviteOneLiner,
            relay_failover: dash.relayFailover,
          },
          null,
          2,
        );
      },
    });

    bb.agents.registerTool({
      name: "a4a_inbox_status",
      description:
        "Inspect local A4A inbox queue counts (pending, processed, quarantine) and 3+4 relay failover state.",
      parameters: z.object({
        sync_first: z.boolean().optional(),
      }),
      async execute(params) {
        const cfg = getRunnerConfig();
        if (params.sync_first) {
          await adapter.runCli(cfg, ["inbox-watch", "--once"]);
        }
        const dash = await adapter.getDashboard(cfg);
        return JSON.stringify(
          {
            configured: dash.configured,
            receiver_state: dash.receiverState,
            receiver_stale: dash.receiverStale,
            pending_count: dash.pendingCount,
            processed_count: dash.processedCount,
            quarantine_count: dash.quarantineCount,
            contacts_count: dash.contactsCount,
            relay_failover: dash.relayFailover,
          },
          null,
          2,
        );
      },
    });

    bb.agents.registerTool({
      name: "a4a_inbox_read",
      description:
        "Sync waiting letters from the A4A relays, claim and decrypt the next pending letter, and complete the lease with an E2EE receipt ACK.",
      parameters: z.object({}),
      async execute() {
        const res = await readNextAndComplete(getRunnerConfig());
        return res.messageText;
      },
    });

    bb.agents.registerTool({
      name: "a4a_deliver",
      description:
        "Send a new end-to-end encrypted A4A private message to a recipient apub1... or 64-hex address.",
      parameters: z.object({
        to_pubkey: z.string().min(10),
        text: z.string().min(1),
        label: z.string().optional(),
      }),
      async execute(params) {
        const cfg = getRunnerConfig();
        if (params.label?.trim()) {
          await adapter.runCli(cfg, [
            "allow-peer",
            params.to_pubkey.trim(),
            "--label",
            params.label.trim(),
          ]);
        }
        const res = await adapter.runCli(cfg, [
          "deliver",
          "--to",
          params.to_pubkey.trim(),
          "--new-letter",
          "--text",
          params.text,
        ]);
        return res.ok ? res.stdout : `Error: ${res.stderr || res.stdout}`;
      },
    });

    bb.agents.registerTool({
      name: "a4a_reply",
      description:
        "Reply to a received A4A inbox message by its sequence number (seq) with cryptographic thread binding.",
      parameters: z.object({
        seq: z.number().int().positive(),
        text: z.string().min(1),
      }),
      async execute(params) {
        const cfg = getRunnerConfig();
        const res = await adapter.runCli(cfg, [
          "reply",
          "--seq",
          String(params.seq),
          "--text",
          params.text,
        ]);
        return res.ok ? res.stdout : `Error: ${res.stderr || res.stdout}`;
      },
    });

    bb.agents.registerTool({
      name: "a4a_invite",
      description:
        "Create a one-time expiring A4A invitation link (action='create') or redeem an invitation URL (action='accept').",
      parameters: z.object({
        action: z.enum(["create", "accept"]),
        label: z.string().optional(),
        ttl_seconds: z.number().int().optional(),
        url: z.string().optional(),
        intro: z.string().optional(),
      }),
      async execute(params) {
        const cfg = getRunnerConfig();
        if (params.action === "create") {
          const label = params.label?.trim() || "Colleague (via bb)";
          const ttl = params.ttl_seconds ?? 86400;
          const res = await adapter.runCli(cfg, [
            "create-invite",
            "--ttl",
            String(ttl),
            "--label",
            label,
          ]);
          return res.ok ? res.stdout : `Error: ${res.stderr || res.stdout}`;
        }
        if (!params.url?.trim()) {
          return "Error: url is required when action='accept'";
        }
        const args = ["accept-invite", "--url", params.url.trim()];
        if (params.intro?.trim()) args.push("--intro", params.intro.trim());
        const res = await adapter.runCli(cfg, args);
        return res.ok ? res.stdout : `Error: ${res.stderr || res.stdout}`;
      },
    });

    bb.agents.registerTool({
      name: "a4a_contacts",
      description:
        "Manage the A4A Rich Address Book (list, set, sync) or inspect/decide L0 quarantine requests (quarantine_list, quarantine_decide).",
      parameters: z.object({
        action: z.enum([
          "list",
          "set",
          "sync",
          "quarantine_list",
          "quarantine_decide",
        ]),
        peer: z.string().optional(),
        label: z.string().optional(),
        project: z.string().optional(),
        role: z.string().optional(),
        notes: z.string().optional(),
        req_id: z.string().optional(),
        decision: z.enum(["accept", "block"]).optional(),
      }),
      async execute(params) {
        const cfg = getRunnerConfig();
        if (params.action === "list") {
          const r = await adapter.runCli(cfg, ["contacts-list"]);
          return r.ok ? r.stdout : `Error: ${r.stderr || r.stdout}`;
        }
        if (params.action === "sync") {
          const r = await adapter.runCli(cfg, [
            "contacts-sync",
            "--direction",
            "both",
          ]);
          return r.ok ? r.stdout : `Error: ${r.stderr || r.stdout}`;
        }
        if (params.action === "set") {
          if (!params.peer || !params.label) {
            return "Error: peer and label are required for action='set'";
          }
          const args = [
            "contacts-set",
            "--peer",
            params.peer.trim(),
            "--label",
            params.label.trim(),
          ];
          if (params.project) args.push("--project", params.project.trim());
          if (params.role) args.push("--role", params.role.trim());
          if (params.notes) args.push("--notes", params.notes.trim());
          const r = await adapter.runCli(cfg, args);
          return r.ok ? r.stdout : `Error: ${r.stderr || r.stdout}`;
        }
        if (params.action === "quarantine_list") {
          const r = await adapter.runCli(cfg, ["quarantine-list"]);
          return r.ok ? r.stdout : `Error: ${r.stderr || r.stdout}`;
        }
        if (!params.req_id || !params.decision) {
          return "Error: req_id and decision are required for action='quarantine_decide'";
        }
        const qArgs = [
          "quarantine-decide",
          "--req-id",
          params.req_id.trim(),
          "--decision",
          params.decision,
        ];
        if (params.decision === "accept") {
          qArgs.push("--label", params.label?.trim() || "Admitted Contact");
        }
        const qr = await adapter.runCli(cfg, qArgs);
        return qr.ok ? qr.stdout : `Error: ${qr.stderr || qr.stdout}`;
      },
    });

    // 3. Contribute Dynamic Agent Instructions (coexisting cleanly with Stage 1 AGENTS.md)
    bb.agents.contributeInstructions(() => {
      const cfg = getRunnerConfig();
      if (cfg.stage1.detected) {
        return (
          `[A4A Plugin v0.4.0 Active] Stage 1 mailbox adopted (${cfg.a4aHome}). ` +
          `Native tools available in this session: a4a_my_address, a4a_inbox_status, a4a_inbox_read, a4a_deliver, a4a_reply, a4a_invite, a4a_contacts.`
        );
      }
      return (
        `## A4A Network Mailbox (bb-plugin-a4a v0.4.0)\n` +
        `- **A4A_HOME**: \`${cfg.a4aHome}\`\n` +
        `- **A4A_RELAY**: \`${cfg.relays}\`\n` +
        `- **Native Tools**: \`a4a_my_address\`, \`a4a_inbox_status\`, \`a4a_inbox_read\`, \`a4a_deliver\`, \`a4a_reply\`, \`a4a_invite\`, \`a4a_contacts\`\n` +
        `- **CLI**: \`bb a4a status\`, \`bb a4a inbox\`, \`bb a4a send <apub> "<text>"\`, \`bb a4a reply <seq> "<text>"\``
      );
    });

    // 4. Register `bb a4a` CLI Subcommands
    bb.cli.register(
      defineCli({
        name: "a4a",
        summary: "Manage A4A E2EE mailbox, invitations, contacts, and inbox",
        description:
          "Connects bb threads to the A4A (Agent for Agent) end-to-end encrypted network.",
        commands: {
          status: cliCommand({
            summary: "Show A4A mailbox, receiver, and 3+4 relay failover status",
            options: { json: JSON_OPTION },
            async run(input) {
              const dash = await adapter.getDashboard(getRunnerConfig());
              if (input.options.json) {
                return { exitCode: 0, stdout: JSON.stringify(dash, null, 2) };
              }
              return {
                exitCode: 0,
                stdout: [
                  `A4A Configured: ${dash.configured} (version: ${dash.packageVersion})`,
                  `A4A_HOME:       ${dash.a4aHome}${dash.stage1Detected ? " (adopted from Stage 1 AGENTS.md)" : ""}`,
                  `Address (apub): ${dash.addressApub ?? "not initialized"}`,
                  `QR Card URL:    ${dash.cardUrl ?? "n/a"}`,
                  `Active Relays:  ${dash.relayFailover.activeRelays.join(", ")}`,
                  `Standby Relays: ${dash.relayFailover.standbyRelays.join(", ")}`,
                  `Queue Counts:   pending=${dash.pendingCount}, processed=${dash.processedCount}, quarantine=${dash.quarantineCount}, contacts=${dash.contactsCount}`,
                ].join("\n"),
              };
            },
          }),

          setup: cliCommand({
            summary: "Initialize or update the A4A mailbox for bb",
            options: {
              name: {
                type: "string",
                description: "Display name for the agent",
              },
              relays: {
                type: "string",
                description: "Comma-separated active relay URLs",
              },
              json: JSON_OPTION,
            },
            async run(input) {
              const cfg = getRunnerConfig();
              const agentName =
                typeof input.options.name === "string" &&
                input.options.name.trim()
                  ? input.options.name.trim()
                  : cfg.agentName;
              const relays =
                typeof input.options.relays === "string" &&
                input.options.relays.trim()
                  ? input.options.relays.trim()
                  : cfg.relays;
              const res = await adapter.runCli(cfg, [
                "setup",
                "--agent-name",
                agentName,
                "--relays",
                relays,
                "--bb",
              ]);
              if (!res.ok) {
                throw new PluginCliError(res.stderr || res.stdout, {
                  code: "a4a_setup_failed",
                });
              }
              return {
                exitCode: 0,
                stdout: input.options.json
                  ? res.stdout
                  : `A4A mailbox initialized at ${cfg.a4aHome}\n${res.stdout}`,
              };
            },
          }),

          inbox: cliCommand({
            summary: "Sync relays, claim and read the next pending A4A letter",
            options: { json: JSON_OPTION },
            async run(input) {
              const res = await readNextAndComplete(getRunnerConfig());
              if (!res.ok) {
                throw new PluginCliError(res.messageText, {
                  code: "a4a_inbox_failed",
                });
              }
              return {
                exitCode: 0,
                stdout: input.options.json
                  ? JSON.stringify(res, null, 2)
                  : res.messageText,
              };
            },
          }),

          send: cliCommand({
            summary: "Send an E2EE private message to an apub1... or hex peer",
            positionals: [
              {
                name: "to",
                description: "Recipient apub1... or 64-hex address",
                required: true,
              },
              {
                name: "text",
                description: "Message text",
                required: true,
                variadic: true,
              },
            ],
            options: {
              label: {
                type: "string",
                description: "Optional contact label if adding a new peer",
              },
              json: JSON_OPTION,
            },
            async run(input) {
              const cfg = getRunnerConfig();
              const to = String(input.positionals.to).trim();
              const text = (input.positionals.text as string[]).join(" ");
              if (
                typeof input.options.label === "string" &&
                input.options.label.trim()
              ) {
                await adapter.runCli(cfg, [
                  "allow-peer",
                  to,
                  "--label",
                  input.options.label.trim(),
                ]);
              }
              const res = await adapter.runCli(cfg, [
                "deliver",
                "--to",
                to,
                "--new-letter",
                "--owner-approved",
                "--text",
                text,
              ]);
              if (!res.ok) {
                throw new PluginCliError(res.stderr || res.stdout, {
                  code: "a4a_send_failed",
                });
              }
              return { exitCode: 0, stdout: res.stdout };
            },
          }),

          reply: cliCommand({
            summary: "Reply to an A4A inbox message by sequence number",
            positionals: [
              {
                name: "seq",
                description: "Inbox sequence number (integer)",
                required: true,
              },
              {
                name: "text",
                description: "Reply text",
                required: true,
                variadic: true,
              },
            ],
            options: { json: JSON_OPTION },
            async run(input) {
              const cfg = getRunnerConfig();
              const seq = String(input.positionals.seq).trim();
              const text = (input.positionals.text as string[]).join(" ");
              const res = await adapter.runCli(cfg, [
                "reply",
                "--seq",
                seq,
                "--owner-approved",
                "--text",
                text,
              ]);
              if (!res.ok) {
                throw new PluginCliError(res.stderr || res.stdout, {
                  code: "a4a_reply_failed",
                });
              }
              return { exitCode: 0, stdout: res.stdout };
            },
          }),

          "invite-create": cliCommand({
            summary: "Create a one-time expiring A4A invitation link",
            positionals: [
              {
                name: "label",
                description: "Mandatory contact label (Name / Project / Role)",
                required: true,
                variadic: true,
              },
            ],
            options: {
              ttl: {
                type: "string",
                description: "Expiration TTL in seconds (default: 86400)",
              },
              json: JSON_OPTION,
            },
            async run(input) {
              const cfg = getRunnerConfig();
              const label = (input.positionals.label as string[]).join(" ");
              const ttl =
                typeof input.options.ttl === "string" &&
                input.options.ttl.trim()
                  ? input.options.ttl.trim()
                  : "86400";
              const res = await adapter.runCli(cfg, [
                "create-invite",
                "--ttl",
                ttl,
                "--label",
                label,
              ]);
              if (!res.ok) {
                throw new PluginCliError(res.stderr || res.stdout, {
                  code: "a4a_invite_failed",
                });
              }
              return { exitCode: 0, stdout: res.stdout };
            },
          }),

          "invite-accept": cliCommand({
            summary: "Redeem a one-time A4A invitation URL",
            positionals: [
              {
                name: "url",
                description: "https://a4a.network/i/<id>#<secret>",
                required: true,
              },
            ],
            options: {
              intro: {
                type: "string",
                description: "Greeting message sent upon acceptance",
              },
              json: JSON_OPTION,
            },
            async run(input) {
              const cfg = getRunnerConfig();
              const args = [
                "accept-invite",
                "--url",
                String(input.positionals.url).trim(),
              ];
              if (
                typeof input.options.intro === "string" &&
                input.options.intro.trim()
              ) {
                args.push("--intro", input.options.intro.trim());
              }
              const res = await adapter.runCli(cfg, args);
              if (!res.ok) {
                throw new PluginCliError(res.stderr || res.stdout, {
                  code: "a4a_accept_failed",
                });
              }
              return { exitCode: 0, stdout: res.stdout };
            },
          }),
        },
      }),
    );

    // 5. Register Background Receiver Service
    bb.background.service("a4a-receiver", {
      async start(signal) {
        let lastCountsKey = "";
        while (!signal.aborted) {
          const cfg = getRunnerConfig();
          if (cfg.autoReceiver) {
            try {
              if (cfg.wakeThreadId) {
                await adapter.runCli(cfg, [
                  "wake-run",
                  "--adapter",
                  "bb-cli",
                  "--project-id",
                  "bb-host",
                  "--target-session-id",
                  cfg.wakeThreadId,
                  "--once",
                ]);
              } else {
                await adapter.runCli(cfg, ["inbox-watch", "--once"]);
              }
              const dash = await adapter.getDashboard(cfg);
              const key = `${dash.pendingCount}:${dash.processedCount}:${dash.quarantineCount}`;
              if (key !== lastCountsKey) {
                lastCountsKey = key;
                bb.realtime.publish("a4a:dashboard", {
                  pendingCount: dash.pendingCount,
                  quarantineCount: dash.quarantineCount,
                  processedCount: dash.processedCount,
                });
              }
            } catch {
              // ignore transient background poll errors
            }
          }
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, 15_000);
            signal.addEventListener(
              "abort",
              () => {
                clearTimeout(timer);
                resolve();
              },
              { once: true },
            );
          });
        }
      },
    });
  };
}

export default createA4APlugin();
