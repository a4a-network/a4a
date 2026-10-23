export const DEFAULT_RELAYS: string[];
export const KIND_SEAL: 13;
export const KIND_PRIVATE_RUMOR: 14;
export const KIND_GIFT_WRAP: 1059;
export const KIND_RELAY_LIST: 10002;
export const KIND_HTTP_AUTH: 27235;
export const KIND_DELEGATION: 31000;
export const KIND_AGENT_PROFILE: 31001;
export const KIND_ACK_RECEIPT: 31034;
export const FILE_ENC_SCHEME: "a4a-chacha20poly1305-v1";

export interface A4AKeys {
  privkey_hex: string;
  pubkey_hex: string;
  asec: string;
  apub: string;
}

export interface A4AParsedContact {
  apub: string;
  pubkey_hex: string;
  relays: string[];
}

export interface A4AUnsignedEvent {
  kind: number;
  created_at?: number;
  tags?: string[][];
  content?: string;
}

export interface A4AEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface A4AFileReference {
  url: string;
  sha256: string;
  key: string;
  enc: string;
  name?: string;
  mime?: string;
  size?: number;
}

export function getPublicKeyHex(privkeyHex: string): string;
export function schnorrSign(msgHashHex: string, privkeyHex: string, auxRandHex?: string | null): string;
export function schnorrVerify(msgHashHex: string, pubkeyHex: string, sigHex: string): boolean;

export function encodeBech32(hrp: string, hexData: string): string;
export function decodeBech32(str: string): { prefix: string; hex: string; bytes: Buffer };
export function generateKeys(privkeyHex?: string | null): A4AKeys;
export function keysFromAsec(asec: string): A4AKeys;
export function parseA4AContact(input: string, defaultRelays?: string[]): A4AParsedContact | null;

export function computeEventId(ev: Omit<A4AEvent, "id" | "sig">): string;
export function signEvent(unsignedEvent: A4AUnsignedEvent, privkeyHex: string): A4AEvent;
export function verifyEvent(ev: A4AEvent): boolean;
export function validateDelegation(event: A4AEvent, mandate: A4AEvent, now?: number | null): boolean;

export function nip44ConversationKey(privkeyHex: string, pubkeyHex: string): Buffer;
export function nip44Encrypt(
  plaintext: string,
  senderPrivkeyHex: string,
  recipientPubkeyHex: string,
  nonce32?: Buffer | Uint8Array | null
): string;
export function nip44Decrypt(payloadB64: string, recipientPrivkeyHex: string, senderPubkeyHex: string): string;

export function wrapEvent(
  innerSignedEvent: A4AEvent,
  senderPrivkeyHex: string,
  recipientPubkeyHex: string,
  expiration: number
): A4AEvent;
export function unwrapGiftWrap(outerEvent: A4AEvent, recipientPrivkeyHex: string): A4AEvent;

export function encryptFileBlob(
  plaintextBytes: Buffer | Uint8Array,
  keyHex?: string | null,
  nonce12Bytes?: Buffer | Uint8Array | null
): { blob: Buffer; sha256: string; keyHex: string; enc: string };
export function openFileBlob(blobBytes: Buffer | Uint8Array, fileRef: A4AFileReference): Buffer;
