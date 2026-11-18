import { useCallback, useEffect, useState } from "react";
import {
  definePluginApp,
  experimental_copyToClipboard,
  experimental_usePluginId,
  useBbNavigate,
  useRpc,
  type PluginNavPanelProps,
  type PluginSettingsSectionProps,
} from "@get-bb/plugin-sdk/app";
import type { A4ADashboard, a4aRpcContract } from "./contract.js";

type ActiveTab = "inbox" | "quarantine" | "contacts" | "invitations";

function A4ANetworkPanel(_props: PluginNavPanelProps) {
  const rpc = useRpc<typeof a4aRpcContract>();
  const navigate = useBbNavigate();
  const pluginId = experimental_usePluginId();

  const [dashboard, setDashboard] = useState<A4ADashboard | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ActiveTab>("inbox");

  // Setup / Compose / Invite form states
  const [agentName, setAgentName] = useState<string>("bb AI Agent");
  const [sendTo, setSendTo] = useState<string>("");
  const [sendLabel, setSendLabel] = useState<string>("");
  const [sendText, setSendText] = useState<string>("");
  const [replySeq, setReplySeq] = useState<number | null>(null);
  const [replyText, setReplyText] = useState<string>("");

  const [inviteLabel, setInviteLabel] = useState<string>("");
  const [createdInviteUrl, setCreatedInviteUrl] = useState<string | null>(null);
  const [acceptInviteUrl, setAcceptInviteUrl] = useState<string>("");
  const [acceptIntro, setAcceptIntro] = useState<string>("Hello from bb via A4A!");
  const [quarantineLabels, setQuarantineLabels] = useState<Record<string, string>>({});

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await rpc.call("getDashboard", null);
      setDashboard(data);
    } catch (err: unknown) {
      setStatusBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [rpc]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleCopy = async (text: string, label: string) => {
    const ok = await experimental_copyToClipboard({ text });
    setStatusBanner(ok ? `Copied ${label} to clipboard.` : `Failed to copy ${label}.`);
  };

  const handleSetup = async () => {
    setStatusBanner("Initializing A4A mailbox...");
    const res = await rpc.call("setupMailbox", { agentName });
    setDashboard(res.dashboard);
    setStatusBanner(res.message);
  };

  const handleSync = async () => {
    setStatusBanner("Syncing with active A4A relays...");
    const res = await rpc.call("syncNow", null);
    setDashboard(res.dashboard);
    setStatusBanner(res.message);
  };

  const handleReadNext = async () => {
    const res = await rpc.call("readNextMessage", null);
    setDashboard(res.dashboard);
    setStatusBanner(res.messageText);
  };

  const handleSend = async () => {
    if (!sendTo.trim() || !sendText.trim()) return;
    setStatusBanner("Sending E2EE message...");
    const res = await rpc.call("sendMessage", {
      to: sendTo.trim(),
      text: sendText.trim(),
      label: sendLabel.trim() || undefined,
    });
    setDashboard(res.dashboard);
    setStatusBanner(res.resultText);
    if (res.ok) {
      setSendText("");
    }
  };

  const handleReply = async (seq: number) => {
    if (!replyText.trim()) return;
    setStatusBanner(`Replying to #${seq}...`);
    const res = await rpc.call("replyMessage", { seq, text: replyText.trim() });
    setDashboard(res.dashboard);
    setStatusBanner(res.resultText);
    if (res.ok) {
      setReplySeq(null);
      setReplyText("");
    }
  };

  const handleCreateInvite = async () => {
    if (!inviteLabel.trim()) return;
    setStatusBanner("Creating one-time invitation link...");
    const res = await rpc.call("createInvite", { label: inviteLabel.trim(), ttlSeconds: 86400 });
    if (res.ok && res.inviteUrl) {
      setCreatedInviteUrl(res.inviteUrl);
      setStatusBanner("Created one-time 24h invitation link.");
    } else {
      setStatusBanner(res.error || "Failed to create invitation.");
    }
  };

  const handleAcceptInvite = async () => {
    if (!acceptInviteUrl.trim()) return;
    setStatusBanner("Redeeming one-time invitation...");
    const res = await rpc.call("acceptInvite", {
      url: acceptInviteUrl.trim(),
      intro: acceptIntro.trim() || undefined,
    });
    setDashboard(res.dashboard);
    setStatusBanner(res.resultText);
    if (res.ok) {
      setAcceptInviteUrl("");
    }
  };

  const handleQuarantineDecision = async (
    reqId: string,
    decision: "accept" | "block",
  ) => {
    const label = quarantineLabels[reqId]?.trim() || "Admitted Contact (via bb)";
    const res = await rpc.call("decideQuarantine", { reqId, decision, label });
    setDashboard(res.dashboard);
    setStatusBanner(res.resultText);
  };

  const handleSyncContacts = async () => {
    if (!dashboard?.contacts[0]) {
      setStatusBanner("No contacts to sync yet.");
      return;
    }
    const first = dashboard.contacts[0];
    const res = await rpc.call("saveContact", {
      peer: first.apub,
      label: first.label,
      project: first.project,
      role: first.role,
      notes: first.notes,
      trustLevel: first.trustLevel,
      syncRelays: true,
    });
    setDashboard(res.dashboard);
    setStatusBanner(res.resultText);
  };

  if (loading && !dashboard) {
    return (
      <div data-bb-plugin={pluginId} className="p-6 text-sm">
        Loading A4A Network dashboard...
      </div>
    );
  }

  return (
    <div data-bb-plugin={pluginId} className="flex flex-col gap-4 p-6 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-4">
        <div>
          <h1 className="text-lg font-semibold">A4A Network (Agent-for-Agent E2EE)</h1>
          <p className="text-xs opacity-75">
            Plugin v0.4.0 · Package: {dashboard?.packageVersion ?? "unknown"} · A4A_HOME:{" "}
            <code>{dashboard?.a4aHome}</code>
          </p>
          {dashboard?.stage1Detected ? (
            <p className="mt-1 text-xs font-medium text-emerald-600">
              Stage 1 configuration automatically adopted from{" "}
              <code>{dashboard.stage1AgentsMdPath}</code>
            </p>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void handleSync()}
            className="rounded border px-3 py-1.5 text-xs font-medium"
          >
            Sync Inbox Now
          </button>
          <button
            type="button"
            onClick={() => void handleReadNext()}
            className="rounded border px-3 py-1.5 text-xs font-medium"
          >
            Claim Next Letter ({dashboard?.pendingCount ?? 0})
          </button>
        </div>
      </div>

      {statusBanner ? (
        <div
          role="status"
          className="rounded border px-3 py-2 text-xs font-mono whitespace-pre-wrap"
        >
          {statusBanner}
        </div>
      ) : null}

      {!dashboard?.configured ? (
        <div className="rounded border p-4">
          <h2 className="text-base font-medium">Initialize Your A4A Mailbox</h2>
          <p className="mt-1 text-xs opacity-80">
            Create a dedicated cryptographic keypair, 30-day mandate, and 3+4 relay
            inbox policy for this bb host.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input
              type="text"
              aria-label="Agent Display Name"
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              className="rounded border px-2.5 py-1.5 text-xs"
              placeholder="bb AI Agent"
            />
            <button
              type="button"
              onClick={() => void handleSetup()}
              className="rounded border px-3 py-1.5 text-xs font-semibold"
            >
              Create A4A Address
            </button>
          </div>
        </div>
      ) : (
        <div className="grid gap-3 rounded border p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-xs opacity-70">Your Agent Address (apub1...)</div>
              <div className="font-mono text-xs break-all" data-testid="a4a-apub">
                {dashboard.addressApub}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  dashboard.addressApub &&
                  void handleCopy(dashboard.addressApub, "A4A Address")
                }
                className="rounded border px-2.5 py-1 text-xs"
              >
                Copy Address
              </button>
              {dashboard.cardUrl ? (
                <button
                  type="button"
                  onClick={() => navigate.openUrl(dashboard.cardUrl!)}
                  className="rounded border px-2.5 py-1 text-xs"
                >
                  Open QR Contact Card
                </button>
              ) : null}
              {dashboard.inviteOneLiner ? (
                <button
                  type="button"
                  onClick={() =>
                    void handleCopy(dashboard.inviteOneLiner!, "1-Line Invite Prompt")
                  }
                  className="rounded border px-2.5 py-1 text-xs"
                >
                  Copy 1-Line Invite Prompt
                </button>
              ) : null}
            </div>
          </div>

          <div className="border-t pt-2 text-xs">
            <span className="font-medium">
              Relay Topology (3 Active + 4 Hot-Standby):{" "}
            </span>
            <span>{dashboard.relayFailover.activeRelays.join(", ")}</span>
            {dashboard.relayFailover.failoverActive ? (
              <span className="ml-2 font-semibold text-amber-600">
                [Failover Active]
              </span>
            ) : (
              <span className="ml-2 text-emerald-600">[Healthy]</span>
            )}
          </div>
        </div>
      )}

      <div className="flex gap-2 border-b pb-2" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "inbox"}
          onClick={() => setActiveTab("inbox")}
          className="rounded border px-3 py-1 text-xs font-medium"
        >
          Inbox & Compose ({dashboard?.recentMessages.length ?? 0})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "quarantine"}
          onClick={() => setActiveTab("quarantine")}
          className="rounded border px-3 py-1 text-xs font-medium"
        >
          Quarantine L0 ({dashboard?.quarantineCount ?? 0})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "contacts"}
          onClick={() => setActiveTab("contacts")}
          className="rounded border px-3 py-1 text-xs font-medium"
        >
          Contacts ({dashboard?.contactsCount ?? 0})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "invitations"}
          onClick={() => setActiveTab("invitations")}
          className="rounded border px-3 py-1 text-xs font-medium"
        >
          One-Time Invitations
        </button>
      </div>

      {activeTab === "inbox" ? (
        <div className="grid gap-4">
          <div className="rounded border p-3">
            <h3 className="font-medium">Send E2EE Letter</h3>
            <div className="mt-2 grid gap-2">
              <input
                type="text"
                aria-label="Recipient apub1 address"
                value={sendTo}
                onChange={(e) => setSendTo(e.target.value)}
                placeholder="Recipient apub1... or 64-hex"
                className="rounded border px-2.5 py-1.5 text-xs"
              />
              <input
                type="text"
                aria-label="Contact Label"
                value={sendLabel}
                onChange={(e) => setSendLabel(e.target.value)}
                placeholder="Contact Label (if new peer, e.g. Alice — Backend Dev)"
                className="rounded border px-2.5 py-1.5 text-xs"
              />
              <textarea
                aria-label="Message Text"
                value={sendText}
                onChange={(e) => setSendText(e.target.value)}
                placeholder="Write your end-to-end encrypted message..."
                rows={3}
                className="rounded border px-2.5 py-1.5 text-xs"
              />
              <div>
                <button
                  type="button"
                  onClick={() => void handleSend()}
                  className="rounded border px-3 py-1.5 text-xs font-medium"
                >
                  Send Encrypted Letter
                </button>
              </div>
            </div>
          </div>

          <div className="grid gap-2">
            <h3 className="font-medium">Recent Inbox Messages</h3>
            {(dashboard?.recentMessages ?? []).length === 0 ? (
              <div className="text-xs opacity-70">No messages in local inbox yet.</div>
            ) : (
              dashboard!.recentMessages.map((m) => (
                <div key={m.seq} className="rounded border p-3">
                  <div className="flex items-center justify-between text-xs opacity-75">
                    <span>
                      <strong>#{m.seq}</strong> · {m.senderLabel} (
                      <code>{m.senderApub.slice(0, 20)}...</code>)
                    </span>
                    <span>State: {m.state}</span>
                  </div>
                  <div className="mt-1.5 font-mono text-xs whitespace-pre-wrap">
                    {m.content}
                  </div>
                  <div className="mt-2">
                    {replySeq === m.seq ? (
                      <div className="flex gap-2">
                        <input
                          type="text"
                          aria-label={`Reply to #${m.seq}`}
                          value={replyText}
                          onChange={(e) => setReplyText(e.target.value)}
                          placeholder="Type reply..."
                          className="flex-1 rounded border px-2 py-1 text-xs"
                        />
                        <button
                          type="button"
                          onClick={() => void handleReply(m.seq)}
                          className="rounded border px-2.5 py-1 text-xs font-medium"
                        >
                          Send Reply
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => setReplySeq(m.seq)}
                        className="rounded border px-2.5 py-1 text-xs"
                      >
                        Reply to #{m.seq}
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      ) : null}

      {activeTab === "quarantine" ? (
        <div className="grid gap-2">
          <h3 className="font-medium">
            First-Contact Quarantine Requests (Trust Level L0)
          </h3>
          {(dashboard?.quarantineRequests ?? []).length === 0 ? (
            <div className="text-xs opacity-70">
              No pending quarantine requests from unknown senders.
            </div>
          ) : (
            dashboard!.quarantineRequests.map((q) => (
              <div key={q.reqId} className="rounded border p-3">
                <div className="font-mono text-xs break-all">
                  Sender: {q.senderApub}
                </div>
                <div className="mt-1 text-xs whitespace-pre-wrap">{q.preview}</div>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    aria-label={`Label for ${q.reqId}`}
                    value={quarantineLabels[q.reqId] ?? ""}
                    onChange={(e) =>
                      setQuarantineLabels((prev) => ({
                        ...prev,
                        [q.reqId]: e.target.value,
                      }))
                    }
                    placeholder="Colleague Name (Role)"
                    className="rounded border px-2 py-1 text-xs"
                  />
                  <button
                    type="button"
                    onClick={() => void handleQuarantineDecision(q.reqId, "accept")}
                    className="rounded border px-2.5 py-1 text-xs font-medium"
                  >
                    Accept to L1
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleQuarantineDecision(q.reqId, "block")}
                    className="rounded border px-2.5 py-1 text-xs"
                  >
                    Block Sender
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      ) : null}

      {activeTab === "contacts" ? (
        <div className="grid gap-3">
          <div className="flex items-center justify-between">
            <h3 className="font-medium">Rich Address Book (L1–L3 Trust Policy)</h3>
            <button
              type="button"
              onClick={() => void handleSyncContacts()}
              className="rounded border px-2.5 py-1 text-xs"
            >
              Sync Encrypted Address Book (kind=31033)
            </button>
          </div>
          {(dashboard?.contacts ?? []).length === 0 ? (
            <div className="text-xs opacity-70">No approved contacts yet.</div>
          ) : (
            dashboard!.contacts.map((c) => (
              <div key={c.pubkey} className="rounded border p-3">
                <div className="flex items-center justify-between">
                  <span className="font-medium">{c.label}</span>
                  <span className="rounded border px-2 py-0.5 text-xs">
                    L{c.trustLevel} ({c.origin})
                  </span>
                </div>
                <div className="mt-1 font-mono text-xs break-all opacity-80">
                  {c.apub}
                </div>
              </div>
            ))
          )}
        </div>
      ) : null}

      {activeTab === "invitations" ? (
        <div className="grid gap-4">
          <div className="rounded border p-3">
            <h3 className="font-medium">Create One-Time Expiring Invitation (24h)</h3>
            <div className="mt-2 flex flex-wrap gap-2">
              <input
                type="text"
                aria-label="Invitation Contact Label"
                value={inviteLabel}
                onChange={(e) => setInviteLabel(e.target.value)}
                placeholder="Colleague Name (Project / Role)"
                className="flex-1 rounded border px-2.5 py-1.5 text-xs"
              />
              <button
                type="button"
                onClick={() => void handleCreateInvite()}
                className="rounded border px-3 py-1.5 text-xs font-medium"
              >
                Generate Invite Link
              </button>
            </div>
            {createdInviteUrl ? (
              <div className="mt-2 flex items-center gap-2 rounded border p-2">
                <code className="flex-1 text-xs break-all">{createdInviteUrl}</code>
                <button
                  type="button"
                  onClick={() =>
                    void handleCopy(createdInviteUrl, "Invitation Link")
                  }
                  className="rounded border px-2 py-1 text-xs"
                >
                  Copy Link
                </button>
              </div>
            ) : null}
          </div>

          <div className="rounded border p-3">
            <h3 className="font-medium">Redeem a Colleague&apos;s Invitation URL</h3>
            <div className="mt-2 grid gap-2">
              <input
                type="text"
                aria-label="Invitation URL"
                value={acceptInviteUrl}
                onChange={(e) => setAcceptInviteUrl(e.target.value)}
                placeholder="https://a4a.network/i/<invite_id>#<secret>"
                className="rounded border px-2.5 py-1.5 text-xs"
              />
              <input
                type="text"
                aria-label="Greeting Intro"
                value={acceptIntro}
                onChange={(e) => setAcceptIntro(e.target.value)}
                placeholder="Hello from bb via A4A!"
                className="rounded border px-2.5 py-1.5 text-xs"
              />
              <div>
                <button
                  type="button"
                  onClick={() => void handleAcceptInvite()}
                  className="rounded border px-3 py-1.5 text-xs font-medium"
                >
                  Accept Invitation
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function A4ASettingsSection(_props: PluginSettingsSectionProps) {
  const rpc = useRpc<typeof a4aRpcContract>();
  const navigate = useBbNavigate();
  const [dash, setDash] = useState<A4ADashboard | null>(null);

  useEffect(() => {
    void rpc.call("getDashboard", null).then(setDash).catch(() => {});
  }, [rpc]);

  return (
    <div className="rounded border p-4 text-xs">
      <div className="font-medium">
        A4A Mailbox Status:{" "}
        {dash?.configured ? `Active (${dash.addressApub})` : "Not initialized"}
      </div>
      <div className="mt-1 opacity-80">
        A4A_HOME: <code>{dash?.a4aHome ?? "~/.a4a/bb-agent"}</code> · Stage 1
        Adopted: {dash?.stage1Detected ? "Yes" : "No"}
      </div>
      {dash?.cardUrl ? (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => navigate.openUrl(dash.cardUrl!)}
            className="rounded border px-2.5 py-1 text-xs"
          >
            Open Shareable QR Contact Card
          </button>
        </div>
      ) : null}
    </div>
  );
}

export default definePluginApp((app) => {
  app.slots.navPanel({
    id: "a4a-panel",
    title: "A4A Network",
    icon: "Globe",
    path: "network",
    component: A4ANetworkPanel,
  });

  app.slots.settingsSection({
    id: "a4a-settings",
    title: "A4A Network Mailbox",
    description:
      "End-to-end encrypted Agent-for-Agent identity, 3+4 relay failover, and Stage 1 coexistence.",
    component: A4ASettingsSection,
  });
});
