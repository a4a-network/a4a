// A4AClientMinimal.swift
// Minimal self-contained Swift reference implementation of the A4A v0.4 client protocol
// for iPhone / iPad (iOS 16+) and macOS (macOS 13+).
//
// Uses Apple's built-in Foundation + CryptoKit (SHA256, HMAC<SHA256>, URLSessionWebSocketTask)
// plus pure-Swift Bech32 (A4A Bech32 asec1/apub1), NIP-44 v2 (HKDF-SHA256 + ChaCha20 + HMAC-SHA256),
// A4A Sealed Envelope 3-layer Gift Wrap (kind 14 -> kind 13 -> kind 1059), and A4A kind 31000 / 31023 / 31034.
//
// For secp256k1 EC point arithmetic and BIP-340 Schnorr signatures on iOS/macOS, wire the
// `Secp256k1Provider` protocol below to SwiftPM `GigaBitcoin/secp256k1.swift` (libsecp256k1)
// or your app's existing secp256k1 module.

import CryptoKit
import Foundation

public enum A4AError: Error, LocalizedError {
    case invalidHex(String)
    case invalidBech32(String)
    case invalidPadding(String)
    case invalidMac
    case invalidSignature(String)
    case invalidEventId
    case relayRejected(String)
    case timeout

    public var errorDescription: String? {
        switch self {
        case .invalidHex(let msg),
             .invalidBech32(let msg),
             .invalidPadding(let msg),
             .invalidSignature(let msg),
             .relayRejected(let msg):
            return msg
        case .invalidMac:
            return "Invalid NIP-44 MAC"
        case .invalidEventId:
            return "Event id mismatch"
        case .timeout:
            return "Relay operation timed out"
        }
    }
}

// MARK: - Pluggable secp256k1 / BIP-340 Provider (e.g. GigaBitcoin/secp256k1.swift)

public protocol Secp256k1Provider: Sendable {
    /// Returns the 32-byte x-only public key for a 32-byte secret key.
    func xOnlyPublicKey(secretKey32: Data) throws -> Data
    /// Returns the 32-byte unhashed ECDH x-coordinate shared secret between secretKey32 and peerPubKeyX32 (even Y).
    func sharedSecretX(secretKey32: Data, peerPubKeyX32: Data) throws -> Data
    /// Returns the 64-byte BIP-340 Schnorr signature over msgHash32.
    func signSchnorr(msgHash32: Data, secretKey32: Data, auxRand32: Data) throws -> Data
    /// Verifies a 64-byte BIP-340 Schnorr signature over msgHash32 for pubKeyX32.
    func verifySchnorr(signature64: Data, msgHash32: Data, pubKeyX32: Data) -> Bool
}

// MARK: - 1. Hex & Bech32 (A4A Bech32 asec1 / apub1)

public enum A4ABech32 {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
    private static let generator: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ UInt32(v)
            for i in 0..<5 where ((b >> i) & 1) != 0 {
                chk ^= generator[i]
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        var out: [UInt8] = bytes.map { $0 >> 5 }
        out.append(0)
        out.append(contentsOf: bytes.map { $0 & 31 })
        return out
    }

    private static func convertBits(_ data: [UInt8], fromBits: Int, toBits: Int, pad: Bool) throws -> [UInt8] {
        var acc = 0
        var bits = 0
        var ret: [UInt8] = []
        let maxv = (1 << toBits) - 1
        for value in data {
            if (Int(value) >> fromBits) != 0 {
                throw A4AError.invalidBech32("Invalid bit value")
            }
            acc = (acc << fromBits) | Int(value)
            bits += fromBits
            while bits >= toBits {
                bits -= toBits
                ret.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 {
                ret.append(UInt8((acc << (toBits - bits)) & maxv))
            }
        } else if bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0 {
            throw A4AError.invalidBech32("Invalid Bech32 padding")
        }
        return ret
    }

    public static func encode(hrp: String, data32: Data) throws -> String {
        let words = try convertBits(Array(data32), fromBits: 8, toBits: 5, pad: true)
        let mod = polymod(hrpExpand(hrp) + words + [0, 0, 0, 0, 0, 0]) ^ 1
        var checksum: [UInt8] = []
        for i in 0..<6 {
            checksum.append(UInt8((mod >> (5 * (5 - i))) & 31))
        }
        let combined = (words + checksum).map { charset[Int($0)] }
        return hrp + "1" + String(combined)
    }

    public static func decode(_ str: String) throws -> (hrp: String, data: Data) {
        guard str == str.lowercased() || str == str.uppercased() else {
            throw A4AError.invalidBech32("Mixed-case Bech32 string")
        }
        let lower = str.lowercased()
        guard let pos = lower.lastIndex(of: "1") else {
            throw A4AError.invalidBech32("Invalid Bech32 separator")
        }
        let hrp = String(lower[..<pos])
        let dataPart = lower[lower.index(after: pos)...]
        guard !hrp.isEmpty, dataPart.count >= 6 else {
            throw A4AError.invalidBech32("Bech32 string too short")
        }
        var words: [UInt8] = []
        for ch in dataPart {
            guard let idx = charset.firstIndex(of: ch) else {
                throw A4AError.invalidBech32("Invalid Bech32 character: \(ch)")
            }
            words.append(UInt8(idx))
        }
        guard polymod(hrpExpand(hrp) + words) == 1 else {
            throw A4AError.invalidBech32("Invalid Bech32 checksum")
        }
        let payload = Array(words.dropLast(6))
        let bytes = try convertBits(payload, fromBits: 5, toBits: 8, pad: false)
        return (hrp, Data(bytes))
    }
}

public extension Data {
    init(a4aHex hex: String) throws {
        guard hex.count % 2 == 0 else { throw A4AError.invalidHex("Odd-length hex string") }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else {
                throw A4AError.invalidHex("Invalid hex byte")
            }
            bytes.append(b)
            idx = next
        }
        self.init(bytes)
    }

    var a4aHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - 2. NIP-44 v2 Encryption (HKDF-SHA256 + ChaCha20 + HMAC-SHA256)

public enum A4ANip44 {
    public static func calcPaddedLen(_ unpaddedLen: Int) throws -> Int {
        guard (1...65535).contains(unpaddedLen) else {
            throw A4AError.invalidPadding("Plaintext length must be 1..65535 bytes")
        }
        if unpaddedLen <= 32 { return 32 }
        let nextPower = 1 << (Int.bitWidth - (unpaddedLen - 1).leadingZeroBitCount)
        let chunk = nextPower <= 256 ? 32 : nextPower / 8
        return chunk * (((unpaddedLen - 1) / chunk) + 1)
    }

    public static func pad(_ plaintext: String) throws -> Data {
        let raw = Data(plaintext.utf8)
        let paddedLen = try calcPaddedLen(raw.count)
        var out = Data(count: 2 + paddedLen)
        out[0] = UInt8((raw.count >> 8) & 0xff)
        out[1] = UInt8(raw.count & 0xff)
        out.replaceSubrange(2..<(2 + raw.count), with: raw)
        return out
    }

    public static func unpad(_ padded: Data) throws -> String {
        guard padded.count >= 34 else {
            throw A4AError.invalidPadding("Padded buffer too short")
        }
        let unpaddedLen = (Int(padded[0]) << 8) | Int(padded[1])
        let expectedPaddedLen = try calcPaddedLen(unpaddedLen)
        guard padded.count == 2 + expectedPaddedLen else {
            throw A4AError.invalidPadding("Invalid padded frame length")
        }
        for i in (2 + unpaddedLen)..<padded.count where padded[i] != 0 {
            throw A4AError.invalidPadding("Non-zero padding byte")
        }
        guard let str = String(data: padded.subdata(in: 2..<(2 + unpaddedLen)), encoding: .utf8) else {
            throw A4AError.invalidPadding("Invalid UTF-8")
        }
        return str
    }

    /// HKDF-Extract(salt="nip44-v2", IKM=ECDH_x)
    public static func conversationKey(
        secretKey32: Data,
        peerPubKeyX32: Data,
        secp: Secp256k1Provider
    ) throws -> Data {
        let sharedX = try secp.sharedSecretX(secretKey32: secretKey32, peerPubKeyX32: peerPubKeyX32)
        let salt = SymmetricKey(data: Data("nip44-v2".utf8))
        let prk = HMAC<SHA256>.authenticationCode(for: sharedX, using: salt)
        return Data(prk)
    }

    public static func messageKeys(conversationKey32: Data, nonce32: Data) throws -> (chachaKey: Data, chachaNonce: Data, hmacKey: Data) {
        guard conversationKey32.count == 32, nonce32.count == 32 else {
            throw A4AError.invalidPadding("conversationKey and nonce must be 32 bytes")
        }
        let prk = SymmetricKey(data: conversationKey32)
        var t = Data()
        var okm = Data()
        for counter: UInt8 in 1...3 {
            var input = t + nonce32
            input.append(counter)
            t = Data(HMAC<SHA256>.authenticationCode(for: input, using: prk))
            okm.append(t)
        }
        return (
            chachaKey: okm.subdata(in: 0..<32),
            chachaNonce: okm.subdata(in: 32..<44),
            hmacKey: okm.subdata(in: 44..<76)
        )
    }

    /// RFC 8439 ChaCha20 stream cipher (counter = 0).
    private static func chacha20Xor(key32: Data, nonce12: Data, input: Data) -> Data {
        func rotl(_ v: UInt32, _ c: UInt32) -> UInt32 { (v << c) | (v >> (32 - c)) }
        func u32le(_ b: [UInt8], _ o: Int) -> UInt32 {
            UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
        }
        func qround(_ x: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[a] &+= x[b]; x[d] = rotl(x[d] ^ x[a], 16)
            x[c] &+= x[d]; x[b] = rotl(x[b] ^ x[c], 12)
            x[a] &+= x[b]; x[d] = rotl(x[d] ^ x[a], 8)
            x[c] &+= x[d]; x[b] = rotl(x[b] ^ x[c], 7)
        }
        let kb = Array(key32), nb = Array(nonce12), ib = Array(input)
        var out = [UInt8](repeating: 0, count: ib.count)
        let base: [UInt32] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            u32le(kb, 0), u32le(kb, 4), u32le(kb, 8), u32le(kb, 12),
            u32le(kb, 16), u32le(kb, 20), u32le(kb, 24), u32le(kb, 28),
            0, u32le(nb, 0), u32le(nb, 4), u32le(nb, 8)
        ]
        var counter: UInt32 = 0
        for offset in stride(from: 0, to: ib.count, by: 64) {
            var state = base
            state[12] = counter
            var working = state
            for _ in 0..<10 {
                qround(&working, 0, 4, 8, 12); qround(&working, 1, 5, 9, 13)
                qround(&working, 2, 6, 10, 14); qround(&working, 3, 7, 11, 15)
                qround(&working, 0, 5, 10, 15); qround(&working, 1, 6, 11, 12)
                qround(&working, 2, 7, 8, 13); qround(&working, 3, 4, 9, 14)
            }
            for i in 0..<16 { working[i] &+= state[i] }
            let take = min(64, ib.count - offset)
            for i in 0..<take {
                let word = working[i >> 2]
                let keystreamByte = UInt8((word >> ((i & 3) * 8)) & 0xff)
                out[offset + i] = ib[offset + i] ^ keystreamByte
            }
            counter &+= 1
        }
        return Data(out)
    }

    public static func encrypt(plaintext: String, conversationKey32: Data, nonce32: Data? = nil) throws -> String {
        let actualNonce: Data = nonce32 ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let keys = try messageKeys(conversationKey32: conversationKey32, nonce32: actualNonce)
        let padded = try pad(plaintext)
        let ciphertext = chacha20Xor(key32: keys.chachaKey, nonce12: keys.chachaNonce, input: padded)
        let mac = Data(HMAC<SHA256>.authenticationCode(
            for: actualNonce + ciphertext,
            using: SymmetricKey(data: keys.hmacKey)
        ))
        var frame = Data([0x02])
        frame.append(actualNonce)
        frame.append(ciphertext)
        frame.append(mac)
        return frame.base64EncodedString()
    }

    public static func decrypt(payloadBase64: String, conversationKey32: Data) throws -> String {
        guard let raw = Data(base64Encoded: payloadBase64), raw.count >= 99, raw[0] == 0x02 else {
            throw A4AError.invalidPadding("Unsupported NIP-44 envelope")
        }
        let nonce = raw.subdata(in: 1..<33)
        let ciphertext = raw.subdata(in: 33..<(raw.count - 32))
        let mac = raw.subdata(in: (raw.count - 32)..<raw.count)
        let keys = try messageKeys(conversationKey32: conversationKey32, nonce32: nonce)
        let validMac = HMAC<SHA256>.isValidAuthenticationCode(
            mac,
            authenticating: nonce + ciphertext,
            using: SymmetricKey(data: keys.hmacKey)
        )
        guard validMac else { throw A4AError.invalidMac }
        let padded = chacha20Xor(key32: keys.chachaKey, nonce12: keys.chachaNonce, input: ciphertext)
        return try unpad(padded)
    }
}

// MARK: - 3. Canonical A4A Event Event Serialization & BIP-340 Signing

public struct A4AEvent: Codable, Sendable {
    public let id: String
    public let pubkey: String
    public let created_at: Int64
    public let kind: Int
    public let tags: [[String]]
    public let content: String
    public let sig: String

    public static func escapeJsonString(_ s: String) -> String {
        var out = "\""
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x22: out += "\\\""
            case 0x5c: out += "\\\\"
            case 0x08: out += "\\b"
            case 0x0c: out += "\\f"
            case 0x0a: out += "\\n"
            case 0x0d: out += "\\r"
            case 0x09: out += "\\t"
            case 0x00...0x1f: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
        return out
    }

    public static func canonicalJson(pubkey: String, createdAt: Int64, kind: Int, tags: [[String]], content: String) -> String {
        let tagsStr = "[" + tags.map { row in
            "[" + row.map { escapeJsonString($0) }.joined(separator: ",") + "]"
        }.joined(separator: ",") + "]"
        return "[0,\(escapeJsonString(pubkey)),\(createdAt),\(kind),\(tagsStr),\(escapeJsonString(content))]"
    }

    public static func computeId(pubkey: String, createdAt: Int64, kind: Int, tags: [[String]], content: String) -> String {
        let json = canonicalJson(pubkey: pubkey, createdAt: createdAt, kind: kind, tags: tags, content: content)
        return Data(SHA256.hash(data: Data(json.utf8))).a4aHex
    }

    public static func sign(
        secretKeyHex: String,
        kind: Int,
        tags: [[String]],
        content: String,
        createdAt: Int64 = Int64(Date().timeIntervalSince1970),
        auxRand32: Data? = nil,
        secp: Secp256k1Provider
    ) throws -> A4AEvent {
        let sk = try Data(a4aHex: secretKeyHex)
        let pubkey = try secp.xOnlyPublicKey(secretKey32: sk).a4aHex
        let id = computeId(pubkey: pubkey, createdAt: createdAt, kind: kind, tags: tags, content: content)
        let aux = auxRand32 ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let sig = try secp.signSchnorr(msgHash32: Data(a4aHex: id), secretKey32: sk, auxRand32: aux).a4aHex
        return A4AEvent(id: id, pubkey: pubkey, created_at: createdAt, kind: kind, tags: tags, content: content, sig: sig)
    }

    public func verify(secp: Secp256k1Provider) -> Bool {
        let expected = Self.computeId(pubkey: pubkey, createdAt: created_at, kind: kind, tags: tags, content: content)
        guard expected == id,
              let sigData = try? Data(a4aHex: sig),
              let idData = try? Data(a4aHex: id),
              let pubData = try? Data(a4aHex: pubkey) else { return false }
        return secp.verifySchnorr(signature64: sigData, msgHash32: idData, pubKeyX32: pubData)
    }
}

// MARK: - 4. A4A Sealed Envelope 3-Layer Sealed Envelope (Gift Wrap: kind 14 -> kind 13 -> kind 1059)

public enum A4AGiftWrap {
    public static func wrap(
        innerEvent: A4AEvent,
        recipientPubKeyHex: String,
        senderSecretKeyHex: String,
        ephemeralSecretKeyHex: String? = nil,
        secp: Secp256k1Provider
    ) throws -> A4AEvent {
        let senderSk = try Data(a4aHex: senderSecretKeyHex)
        let senderPub = try secp.xOnlyPublicKey(secretKey32: senderSk).a4aHex
        guard innerEvent.pubkey == senderPub, innerEvent.verify(secp: secp) else {
            throw A4AError.invalidSignature("Inner event must be validly signed by sender")
        }
        let recipientPk = try Data(a4aHex: recipientPubKeyHex)
        let innerJson = String(data: try JSONEncoder().encode(innerEvent), encoding: .utf8)!

        let rumorObj: [String: Any] = [
            "id": innerEvent.id,
            "pubkey": senderPub,
            "created_at": innerEvent.created_at,
            "kind": 14,
            "tags": [["p", recipientPubKeyHex], ["a4a-inner-kind", String(innerEvent.kind)]],
            "content": innerJson
        ]
        let rumorJson = String(data: try JSONSerialization.data(withJSONObject: rumorObj), encoding: .utf8)!
        let sealConvKey = try A4ANip44.conversationKey(secretKey32: senderSk, peerPubKeyX32: recipientPk, secp: secp)
        let sealCiphertext = try A4ANip44.encrypt(plaintext: rumorJson, conversationKey32: sealConvKey)
        let now = Int64(Date().timeIntervalSince1970)
        let seal = try A4AEvent.sign(
            secretKeyHex: senderSecretKeyHex,
            kind: 13,
            tags: [],
            content: sealCiphertext,
            createdAt: now - Int64.random(in: 0..<172800),
            secp: secp
        )
        let sealJson = String(data: try JSONEncoder().encode(seal), encoding: .utf8)!
        let ephHex = ephemeralSecretKeyHex ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) }).a4aHex
        let ephSk = try Data(a4aHex: ephHex)
        let wrapConvKey = try A4ANip44.conversationKey(secretKey32: ephSk, peerPubKeyX32: recipientPk, secp: secp)
        let wrapCiphertext = try A4ANip44.encrypt(plaintext: sealJson, conversationKey32: wrapConvKey)
        return try A4AEvent.sign(
            secretKeyHex: ephHex,
            kind: 1059,
            tags: [["p", recipientPubKeyHex], ["expiration", String(now + 30 * 86400)]],
            content: wrapCiphertext,
            createdAt: now - Int64.random(in: 0..<172800),
            secp: secp
        )
    }

    public static func unwrap(
        outerWrap: A4AEvent,
        recipientSecretKeyHex: String,
        secp: Secp256k1Provider
    ) throws -> A4AEvent {
        guard outerWrap.kind == 1059, outerWrap.verify(secp: secp) else {
            throw A4AError.invalidSignature("Invalid outer kind 1059 gift wrap")
        }
        let recipientSk = try Data(a4aHex: recipientSecretKeyHex)
        let wrapConvKey = try A4ANip44.conversationKey(
            secretKey32: recipientSk,
            peerPubKeyX32: try Data(a4aHex: outerWrap.pubkey),
            secp: secp
        )
        let sealJson = try A4ANip44.decrypt(payloadBase64: outerWrap.content, conversationKey32: wrapConvKey)
        let seal = try JSONDecoder().decode(A4AEvent.self, from: Data(sealJson.utf8))
        guard seal.kind == 13, seal.tags.isEmpty, seal.verify(secp: secp) else {
            throw A4AError.invalidSignature("Invalid kind 13 seal")
        }
        let sealConvKey = try A4ANip44.conversationKey(
            secretKey32: recipientSk,
            peerPubKeyX32: try Data(a4aHex: seal.pubkey),
            secp: secp
        )
        let rumorJson = try A4ANip44.decrypt(payloadBase64: seal.content, conversationKey32: sealConvKey)
        guard let rumor = try JSONSerialization.jsonObject(with: Data(rumorJson.utf8)) as? [String: Any],
              (rumor["kind"] as? Int) == 14,
              (rumor["pubkey"] as? String) == seal.pubkey,
              let innerContent = rumor["content"] as? String else {
            throw A4AError.invalidSignature("Rumor pubkey/kind mismatch")
        }
        let inner = try JSONDecoder().decode(A4AEvent.self, from: Data(innerContent.utf8))
        guard inner.pubkey == seal.pubkey, inner.verify(secp: secp) else {
            throw A4AError.invalidSignature("Inner event signature/author mismatch")
        }
        return inner
    }
}

// MARK: - 5. High-Level iOS / macOS A4A Client (URLSessionWebSocketTask)

@available(iOS 16.0, macOS 13.0, *)
public final class A4AMinimalClient: Sendable {
    public let relayUrls: [URL]
    public let agentSecretKeyHex: String
    public let agentPubKeyHex: String
    public let secp: Secp256k1Provider

    public init(relayUrls: [URL], agentSecretKeyHex: String, secp: Secp256k1Provider) throws {
        self.relayUrls = relayUrls
        self.agentSecretKeyHex = agentSecretKeyHex
        self.secp = secp
        self.agentPubKeyHex = try secp.xOnlyPublicKey(secretKey32: Data(a4aHex: agentSecretKeyHex)).a4aHex
    }

    public func publish(_ event: A4AEvent, to relayUrl: URL) async throws {
        let task = URLSession.shared.webSocketTask(with: relayUrl)
        task.resume()
        defer { task.cancel(with: .normalClosure, reason: nil) }

        let eventData = try JSONEncoder().encode(event)
        let eventJson = String(data: eventData, encoding: .utf8)!
        try await task.send(.string("[\"EVENT\",\(eventJson)]"))

        while true {
            let msg = try await task.receive()
            guard case .string(let text) = msg,
                  let arr = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [Any],
                  let verb = arr.first as? String else { continue }
            if verb == "OK", (arr.dropFirst().first as? String) == event.id {
                let accepted = (arr.dropFirst(2).first as? Bool) ?? false
                if !accepted {
                    let reason = (arr.dropFirst(3).first as? String) ?? "rejected"
                    throw A4AError.relayRejected(reason)
                }
                return
            }
        }
    }
}
