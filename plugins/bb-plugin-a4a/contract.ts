import { defineRpcContract } from "@get-bb/plugin-sdk";
import { z } from "zod";

export const DEFAULT_ACTIVE_RELAYS =
  "wss://ru1.a4a.network,wss://ru2.a4a.network,wss://eu1.a4a.network";

export const STANDBY_RELAYS = [
  "wss://eu2.a4a.network",
  "wss://us2.a4a.network",
  "wss://us1.a4a.network",
  "wss://sg1.a4a.network",
] as const;

export const a4aMessageSchema = z.object({
  seq: z.number(),
  sender: z.string(),
  senderApub: z.string(),
  senderLabel: z.string(),
  deliveryId: z.string(),
  receivedAt: z.number(),
  state: z.string(),
  content: z.string(),
});

export type A4AMessageItem = z.infer<typeof a4aMessageSchema>;

export const a4aQuarantineItemSchema = z.object({
  reqId: z.string(),
  senderPubkey: z.string(),
  senderApub: z.string(),
  receivedAt: z.number(),
  status: z.string(),
  preview: z.string(),
});

export type A4AQuarantineItem = z.infer<typeof a4aQuarantineItemSchema>;

export const a4aContactItemSchema = z.object({
  pubkey: z.string(),
  apub: z.string(),
  label: z.string(),
  project: z.string(),
  role: z.string(),
  notes: z.string(),
  trustLevel: z.number(),
  origin: z.string(),
});

export type A4AContactItem = z.infer<typeof a4aContactItemSchema>;

export const a4aRelayFailoverSchema = z.object({
  activeRelays: z.array(z.string()),
  standbyRelays: z.array(z.string()),
  failoverActive: z.boolean(),
  degradedRelays: z.record(z.string(), z.string()),
  promotedRelays: z.array(z.string()),
});

export type A4ARelayFailover = z.infer<typeof a4aRelayFailoverSchema>;

export const a4aDashboardSchema = z.object({
  configured: z.boolean(),
  a4aHome: z.string(),
  pythonExecutable: z.string(),
  packageVersion: z.string(),
  stage1Detected: z.boolean(),
  stage1AgentsMdPath: z.string().nullable(),
  addressApub: z.string().nullable(),
  addressHex: z.string().nullable(),
  cardUrl: z.string().nullable(),
  inviteOneLiner: z.string().nullable(),
  receiverState: z.string(),
  receiverStale: z.boolean(),
  pendingCount: z.number(),
  processedCount: z.number(),
  quarantineCount: z.number(),
  contactsCount: z.number(),
  wakeThreadId: z.string(),
  autoReceiver: z.boolean(),
  relayFailover: a4aRelayFailoverSchema,
  recentMessages: z.array(a4aMessageSchema),
  quarantineRequests: z.array(a4aQuarantineItemSchema),
  contacts: z.array(a4aContactItemSchema),
  error: z.string().nullable(),
});

export type A4ADashboard = z.infer<typeof a4aDashboardSchema>;

export const a4aRpcContract = defineRpcContract({
  getDashboard: {
    input: z.null(),
    output: a4aDashboardSchema,
  },
  setupMailbox: {
    input: z.object({
      agentName: z.string().min(1).max(120).optional(),
      relays: z.string().min(6).max(1024).optional(),
      a4aHome: z.string().max(1024).optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      message: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  syncNow: {
    input: z.null(),
    output: z.object({
      ok: z.boolean(),
      message: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  readNextMessage: {
    input: z.null(),
    output: z.object({
      ok: z.boolean(),
      claimed: z.boolean(),
      messageText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  sendMessage: {
    input: z.object({
      to: z.string().min(10).max(128),
      text: z.string().min(1).max(32768),
      label: z.string().max(200).optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      resultText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  replyMessage: {
    input: z.object({
      seq: z.number().int().positive(),
      text: z.string().min(1).max(32768),
    }),
    output: z.object({
      ok: z.boolean(),
      resultText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  createInvite: {
    input: z.object({
      label: z.string().min(1).max(200),
      ttlSeconds: z.number().int().min(60).max(604800).optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      inviteUrl: z.string().nullable(),
      inviteId: z.string().nullable(),
      expiresAt: z.number().nullable(),
      error: z.string().nullable(),
    }),
  },
  acceptInvite: {
    input: z.object({
      url: z.string().min(16).max(1024),
      intro: z.string().min(1).max(4000).optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      resultText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  decideQuarantine: {
    input: z.object({
      reqId: z.string().min(1).max(128),
      decision: z.enum(["accept", "block"]),
      label: z.string().max(200).optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      resultText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
  saveContact: {
    input: z.object({
      peer: z.string().min(10).max(128),
      label: z.string().min(1).max(200),
      project: z.string().max(120).optional(),
      role: z.string().max(120).optional(),
      notes: z.string().max(1000).optional(),
      trustLevel: z.number().int().min(1).max(3).optional(),
      syncRelays: z.boolean().optional(),
    }),
    output: z.object({
      ok: z.boolean(),
      resultText: z.string(),
      dashboard: a4aDashboardSchema,
    }),
  },
});
