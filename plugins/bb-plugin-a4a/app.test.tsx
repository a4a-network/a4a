// @vitest-environment jsdom
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import type { A4ADashboard } from "./contract.js";

const app = await loadPluginApp(() => import("./app.js"));

function fixtureDashboard(): A4ADashboard {
  return {
    configured: true,
    a4aHome: "/stage1/a4a-home",
    pythonExecutable: "/stage1/venv/bin/python",
    packageVersion: "0.4.0.post7",
    stage1Detected: true,
    stage1AgentsMdPath: "/home/user/.bb/AGENTS.md",
    addressApub:
      "apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    addressHex:
      "47471267644c7f113e7ed12cc6ea0f140c054d81240a55afe3e92c6cab6b64fb",
    cardUrl:
      "https://a4a.network/c/#apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    inviteOneLiner:
      "Connect A4A (https://a4a.network/docs/connect-agent.txt) and message my agent apub1gar3yemyf3l3z0n76ykvd6s0zsxq2nvpys99ttlraykxe2mtvnasjwl686",
    receiverState: "ready",
    receiverStale: false,
    pendingCount: 1,
    processedCount: 8,
    quarantineCount: 1,
    contactsCount: 1,
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
        seq: 8,
        sender:
          "9339858283b9ab8cacb77eecb7b4649a04c081c8c38029e1cfa7c74e1b045099",
        senderApub:
          "apub1jvuctq5rhx4cet9h0mkt0dryngzvpqwgcwqzncw05lr5uxcy2zvstx5dex",
        senderLabel: "Owner Representative",
        deliveryId: "144717d6376648efafdc900d7e85861c",
        receivedAt: 1794977752,
        state: "processed",
        content: "Stage 2 GO confirmed.",
      },
    ],
    quarantineRequests: [
      {
        reqId: "q_req_1",
        senderPubkey:
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        senderApub:
          "apub1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        receivedAt: 1794977760,
        status: "quarantined",
        preview: "First-contact request from external developer.",
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
  };
}

describe("bb-plugin-a4a UI slots", () => {
  afterEach(() => {
    cleanup();
  });

  it("registers navPanel and settingsSection and renders address, relays, and tabs", async () => {
    expect(app.navPanels).toHaveLength(1);
    expect(app.navPanels[0]?.id).toBe("a4a-panel");
    expect(app.settingsSections).toHaveLength(1);
    expect(app.settingsSections[0]?.id).toBe("a4a-settings");

    const dash = fixtureDashboard();
    const slot = renderSlot(
      app.navPanels[0]!,
      { subPath: "" },
      {
        rpc: {
          getDashboard: () => dash,
          decideQuarantine: () => ({
            ok: true,
            resultText: "Admitted q_req_1 to L1",
            dashboard: { ...dash, quarantineCount: 0, quarantineRequests: [] },
          }),
        },
      },
    );

    await waitFor(() => {
      expect(screen.getByTestId("a4a-apub").textContent).toBe(dash.addressApub);
    });

    expect(
      screen.getByText(/Stage 1 configuration automatically adopted/i),
    ).toBeTruthy();
    expect(screen.getByText(/Stage 2 GO confirmed\./i)).toBeTruthy();

    // Open QR Contact Card uses bb navigation
    fireEvent.click(
      screen.getByRole("button", { name: "Open QR Contact Card" }),
    );
    expect(slot.navigateCalls).toEqual([
      { method: "openUrl", url: dash.cardUrl },
    ]);

    // Switch to Quarantine tab and accept L0 request
    fireEvent.click(screen.getByRole("tab", { name: /Quarantine L0/i }));
    expect(
      screen.getByText(/First-contact request from external developer\./i),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Accept to L1" }));
    await waitFor(() => {
      expect(
        slot.rpcCalls.some((c) => c.method === "decideQuarantine"),
      ).toBe(true);
    });
  });
});
