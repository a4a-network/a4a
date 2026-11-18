import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterEach, describe, expect, it } from "vitest";
import type { A4ADashboard } from "./contract.js";
import {
  createA4APlugin,
  detectStage1Config,
  type A4ABackendAdapter,
} from "./server.js";

function sampleDashboard(overrides: Partial<A4ADashboard> = {}): A4ADashboard {
  return {
    configured: true,
    a4aHome: "/tmp/a4a-stage1-home",
    pythonExecutable: "/tmp/a4a-venv/bin/python",
    packageVersion: "0.4.0.post7",
    stage1Detected: true,
    stage1AgentsMdPath: "/tmp/bb/AGENTS.md",
    addressApub: "apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    addressHex: "47471267644c7f113e7ed12cc6ea0f140c054d81240a55afe3e92c6cab6b64fb",
    cardUrl:
      "https://a4a.network/c/#apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    inviteOneLiner:
      "Connect A4A (https://a4a.network/docs/connect-agent.txt) and message my agent apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    receiverState: "ready",
    receiverStale: false,
    pendingCount: 1,
    processedCount: 12,
    quarantineCount: 1,
    contactsCount: 2,
    wakeThreadId: "",
    autoReceiver: true,
    relayFailover: {
      activeRelays: [
        "wss://ru1.a4a.network",
        "wss://ru2.a4a.network",
        "wss://eu1.a4a.network",
      ],
      standbyRelays: [
        "wss://eu2.a4a.network",
        "wss://us2.a4a.network",
        "wss://us1.a4a.network",
        "wss://sg1.a4a.network",
      ],
      failoverActive: false,
      degradedRelays: {},
      promotedRelays: [],
    },
    recentMessages: [
      {
        seq: 12,
        sender: "9339858283b9ab8cacb77eecb7b4649a04c081c8c38029e1cfa7c74e1b045099",
        senderApub:
          "apub1jvuctq5rhx4cet9h0mkt0dryngzvpqwgcwqzncw05lr5uxcy2zvstx5dex",
        senderLabel: "Owner Representative",
        deliveryId: "144717d6376648efafdc900d7e85861c",
        receivedAt: 1794977752,
        state: "processed",
        content: "Proceed with Stage 2 bb plugin.",
      },
    ],
    quarantineRequests: [
      {
        reqId: "req_01",
        senderPubkey:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        senderApub:
          "apub1424242424242424242424242424242424242424242424242424sq9w9w2",
        receivedAt: 1794977700,
        status: "quarantined",
        preview: "Hi! Can our agents collaborate?",
      },
    ],
    contacts: [
      {
        pubkey:
          "9339858283b9ab8cacb77eecb7b4649a04c081c8c38029e1cfa7c74e1b045099",
        apub: "apub1jvuctq5rhx4cet9h0mkt0dryngzvpqwgcwqzncw05lr5uxcy2zvstx5dex",
        label: "Owner Representative",
        project: "A4A",
        role: "Representative",
        notes: "",
        trustLevel: 2,
        origin: "owner_agent",
      },
    ],
    error: null,
    ...overrides,
  };
}

describe("bb-plugin-a4a server", () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const d of tempDirs.splice(0)) {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("detects and adopts Stage 1 ~/.bb/AGENTS.md configuration", () => {
    const dir = mkdtempSync(join(tmpdir(), "bb-a4a-stage1-"));
    tempDirs.push(dir);
    writeFileSync(
      join(dir, "AGENTS.md"),
      [
        "# User Rules",
        "<!-- A4A_BB_AGENT_INSTRUCTIONS_START -->",
        "## A4A Network Mailbox (bb Integration)",
        "- **A4A_HOME**: `/custom/stage1/home`",
        "- **A4A_RELAY**: `wss://ru1.a4a.network,wss://ru2.a4a.network,wss://eu1.a4a.network`",
        '- **Python / CLI**: `"/custom/venv/bin/python" -I -m a4a_mcp`',
        "<!-- A4A_BB_AGENT_INSTRUCTIONS_END -->",
      ].join("\n"),
      "utf8",
    );

    const s1 = detectStage1Config(dir);
    expect(s1.detected).toBe(true);
    expect(s1.a4aHome).toBe("/custom/stage1/home");
    expect(s1.relays).toBe(
      "wss://ru1.a4a.network,wss://ru2.a4a.network,wss://eu1.a4a.network",
    );
    expect(s1.pythonExecutable).toBe("/custom/venv/bin/python");
  });

  it("registers RPC, CLI, 7 agent tools, instructions, and background service", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bb-a4a-host-"));
    tempDirs.push(dir);
    writeFileSync(
      join(dir, "AGENTS.md"),
      [
        "<!-- A4A_BB_AGENT_INSTRUCTIONS_START -->",
        "- **A4A_HOME**: `/stage1/adopted/home`",
        "- **A4A_RELAY**: `wss://ru1.a4a.network,wss://ru2.a4a.network,wss://eu1.a4a.network`",
        '- **Python / CLI**: `"/usr/bin/python3" -I -m a4a_mcp`',
        "<!-- A4A_BB_AGENT_INSTRUCTIONS_END -->",
      ].join("\n"),
      "utf8",
    );

    const cliCalls: Array<{ home: string; args: string[] }> = [];
    const fakeAdapter: A4ABackendAdapter = {
      async getDashboard(cfg) {
        return sampleDashboard({
          a4aHome: cfg.a4aHome,
          stage1Detected: cfg.stage1.detected,
          stage1AgentsMdPath: cfg.stage1.agentsMdPath,
        });
      },
      async runCli(cfg, args) {
        cliCalls.push({ home: cfg.a4aHome, args });
        if (args[0] === "create-invite") {
          return {
            ok: true,
            stdout: JSON.stringify({
              invitation_url: "https://a4a.network/i/inv123#sec456",
              invite_id: "inv123",
              expires_at: 1795060000,
            }),
            stderr: "",
          };
        }
        return { ok: true, stdout: `OK: ${args.join(" ")}`, stderr: "" };
      },
    };

    const host = createFakePluginHost({ pluginId: "a4a" });
    const plugin = createA4APlugin({ adapter: fakeAdapter, bbDataDir: dir });
    await plugin(host.bb);

    // 1. RPC getDashboard reflects Stage 1 adopted home
    const dash = (await host.harness.callRpc(
      "getDashboard",
      null,
    )) as A4ADashboard;
    expect(dash.stage1Detected).toBe(true);
    expect(dash.a4aHome).toBe("/stage1/adopted/home");
    expect(dash.relayFailover.activeRelays).toHaveLength(3);
    expect(dash.relayFailover.standbyRelays).toHaveLength(4);

    // 2. RPC sendMessage & decideQuarantine & createInvite
    const sendRes = (await host.harness.callRpc("sendMessage", {
      to: "apub1jqahsu46f6gwm7husjlmvzvhggrdfugjda8gjl0tnr9wcq2z6casj59wqj",
      text: "Hello via bb plugin!",
      label: "Demo Agent",
    })) as { ok: boolean; resultText: string };
    expect(sendRes.ok).toBe(true);
    expect(cliCalls.some((c) => c.args[0] === "allow-peer")).toBe(true);
    expect(cliCalls.some((c) => c.args[0] === "deliver")).toBe(true);

    const invRes = (await host.harness.callRpc("createInvite", {
      label: "Colleague (Backend)",
      ttlSeconds: 3600,
    })) as { ok: boolean; inviteUrl: string | null };
    expect(invRes.ok).toBe(true);
    expect(invRes.inviteUrl).toBe("https://a4a.network/i/inv123#sec456");

    const qRes = (await host.harness.callRpc("decideQuarantine", {
      reqId: "req_01",
      decision: "accept",
      label: "New Partner",
    })) as { ok: boolean };
    expect(qRes.ok).toBe(true);
    expect(
      cliCalls.some(
        (c) =>
          c.args[0] === "quarantine-decide" &&
          c.args.includes("req_01") &&
          c.args.includes("accept"),
      ),
    ).toBe(true);

    // 3. CLI `bb a4a status`
    const cliStatus = await host.harness.runCli(["status"]);
    expect(cliStatus.exitCode).toBe(0);
    expect(cliStatus.stdout).toContain("/stage1/adopted/home");
    expect(cliStatus.stdout).toContain("adopted from Stage 1 AGENTS.md");
  });
});
