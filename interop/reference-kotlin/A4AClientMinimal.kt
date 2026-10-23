package network.a4a.interop

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.floor
import kotlin.math.ln

/**
 * A4A v0.4 Minimal Reference Implementation for Kotlin (Android API 28+ / JVM 17+).
 *
 * Zero external cryptography libraries required:
 * - secp256k1 x-only keys, BIP-340 Schnorr sign/verify, and raw-X ECDH via BigInteger
 * - Bech32 (apub / asec) encoding/decoding and universal parseA4AContact()
 * - Canonical event serialization (SHA-256) and kind 31000 -> kind 31001 delegation check
 * - NIP-44 v2 encryption & decryption (HKDF-SHA256 + power-of-two padding + ChaCha20 + HMAC-SHA256)
 * - A4A Signed Gift Wrap (signed kind 14 PrivateRumor -> kind 13 Seal -> kind 1059 GiftWrap)
 * - Encrypted file attachments (a4a-chacha20poly1305-v1 AEAD + SHA-256 verification)
 */
object A4AClientMinimal {

    val DEFAULT_RELAYS = listOf(
        "wss://eu1.a4a.network",
        "wss://us1.a4a.network",
        "wss://sg1.a4a.network",
        "wss://kz1.a4a.network",
        "wss://ru1.a4a.network",
        "wss://ru2.a4a.network"
    )

    const val KIND_SEAL = 13
    const val KIND_PRIVATE_RUMOR = 14
    const val KIND_GIFT_WRAP = 1059
    const val KIND_RELAY_LIST = 10002
    const val KIND_HTTP_AUTH = 27235
    const val KIND_DELEGATION = 31000
    const val KIND_AGENT_PROFILE = 31001
    const val KIND_ACK_RECEIPT = 31034
    const val FILE_ENC_SCHEME = "a4a-chacha20poly1305-v1"

    private val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val GX = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    private val GY = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)
    private val SEVEN = BigInteger.valueOf(7)
    private val EXP_SQRT = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4))
    private val rng = SecureRandom()

    data class Point(val x: BigInteger, val y: BigInteger)
    private val G = Point(GX, GY)

    data class Keys(
        val privkeyHex: String,
        val pubkeyHex: String,
        val asec: String,
        val apub: String
    )

    data class ParsedContact(
        val apub: String,
        val pubkeyHex: String,
        val relays: List<String>
    )

    // --- 1. secp256k1 & BIP-340 Schnorr --------------------------------------

    private fun modP(a: BigInteger): BigInteger {
        val r = a.mod(P)
        return if (r.signum() < 0) r.add(P) else r
    }

    private fun pointAdd(p1: Point?, p2: Point?): Point? {
        if (p1 == null) return p2
        if (p2 == null) return p1
        if (p1.x == p2.x) {
            if (p1.y != p2.y || p1.y == BigInteger.ZERO) return null
            val lam = modP(THREE.multiply(p1.x).multiply(p1.x).multiply(TWO.multiply(p1.y).modInverse(P)))
            val x3 = modP(lam.multiply(lam).subtract(TWO.multiply(p1.x)))
            val y3 = modP(lam.multiply(p1.x.subtract(x3)).subtract(p1.y))
            return Point(x3, y3)
        }
        val lam = modP(p2.y.subtract(p1.y).multiply(modP(p2.x.subtract(p1.x)).modInverse(P)))
        val x3 = modP(lam.multiply(lam).subtract(p1.x).subtract(p2.x))
        val y3 = modP(lam.multiply(p1.x.subtract(x3)).subtract(p1.y))
        return Point(x3, y3)
    }

    private fun pointMul(pt: Point?, scalar: BigInteger): Point? {
        var k = scalar.mod(N)
        if (k == BigInteger.ZERO || pt == null) return null
        var res: Point? = null
        var addend = pt
        while (k > BigInteger.ZERO) {
            if (k.testBit(0)) res = pointAdd(res, addend)
            addend = pointAdd(addend, addend)
            k = k.shiftRight(1)
        }
        return res
    }

    private fun liftXEven(xHex: String): Point {
        val x = BigInteger(xHex, 16)
        require(x > BigInteger.ZERO && x < P) { "Invalid x coordinate" }
        val c = modP(x.modPow(THREE, P).add(SEVEN))
        val y = c.modPow(EXP_SQRT, P)
        require(modP(y.multiply(y)) == c) { "Point not on secp256k1 curve" }
        return Point(x, if (!y.testBit(0)) y else P.subtract(y))
    }

    private fun bigTo32Bytes(n: BigInteger): ByteArray {
        val raw = n.toByteArray()
        if (raw.size == 32) return raw
        val out = ByteArray(32)
        if (raw.size > 32) {
            System.arraycopy(raw, raw.size - 32, out, 0, 32)
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.size, raw.size)
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "Odd hex length" }
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    private fun taggedHash(tag: String, vararg parts: ByteArray): ByteArray {
        val tagHash = sha256(tag.toByteArray(StandardCharsets.UTF_8))
        val md = MessageDigest.getInstance("SHA-256")
        md.update(tagHash)
        md.update(tagHash)
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun getPublicKeyHex(privkeyHex: String): String {
        val d0 = BigInteger(privkeyHex, 16)
        require(d0 > BigInteger.ZERO && d0 < N) { "Invalid private key" }
        val pt = pointMul(G, d0) ?: error("Point at infinity")
        return bytesToHex(bigTo32Bytes(pt.x))
    }

    fun schnorrSign(msgHashHex: String, privkeyHex: String, auxRandHex: String? = null): String {
        val d0 = BigInteger(privkeyHex, 16)
        require(d0 > BigInteger.ZERO && d0 < N) { "Invalid private key" }
        val pt = pointMul(G, d0) ?: error("Invalid public point")
        val d = if (!pt.y.testBit(0)) d0 else N.subtract(d0)
        val pxBytes = bigTo32Bytes(pt.x)
        val dBytes = bigTo32Bytes(d)
        val mBytes = hexToBytes(msgHashHex)
        val aux = if (auxRandHex != null) hexToBytes(auxRandHex) else ByteArray(32).also { rng.nextBytes(it) }
        val tHash = taggedHash("BIP0340/aux", aux)
        val tBytes = ByteArray(32) { i -> (dBytes[i].toInt() xor tHash[i].toInt()).toByte() }
        val rand = taggedHash("BIP0340/nonce", tBytes, pxBytes, mBytes)
        val k0 = BigInteger(1, rand).mod(N)
        require(k0 != BigInteger.ZERO) { "Zero nonce" }
        val rPt = pointMul(G, k0) ?: error("Invalid R point")
        val k = if (!rPt.y.testBit(0)) k0 else N.subtract(k0)
        val rxBytes = bigTo32Bytes(rPt.x)
        val eHash = taggedHash("BIP0340/challenge", rxBytes, pxBytes, mBytes)
        val e = BigInteger(1, eHash).mod(N)
        val s = k.add(e.multiply(d)).mod(N)
        return bytesToHex(rxBytes) + bytesToHex(bigTo32Bytes(s))
    }

    fun schnorrVerify(msgHashHex: String, pubkeyHex: String, sigHex: String): Boolean {
        return try {
            if (pubkeyHex.length != 64 || sigHex.length != 128) return false
            val pt = liftXEven(pubkeyHex)
            val r = BigInteger(sigHex.substring(0, 64), 16)
            val s = BigInteger(sigHex.substring(64, 128), 16)
            if (r >= P || s >= N) return false
            val rxBytes = hexToBytes(sigHex.substring(0, 64))
            val pxBytes = hexToBytes(pubkeyHex)
            val mBytes = hexToBytes(msgHashHex)
            val eHash = taggedHash("BIP0340/challenge", rxBytes, pxBytes, mBytes)
            val e = BigInteger(1, eHash).mod(N)
            val sG = pointMul(G, s)
            val eP = pointMul(Point(pt.x, P.subtract(pt.y)), e)
            val rPt = pointAdd(sG, eP) ?: return false
            !rPt.y.testBit(0) && rPt.x == r
        } catch (_: Exception) {
            false
        }
    }

    // --- 2. Bech32 (apub / asec) & Universal Contact Parser ------------------

    private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val BECH32_GEN = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

    private fun bech32Polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) {
                if (((top ushr i) and 1) != 0) chk = chk xor BECH32_GEN[i]
            }
        }
        return chk
    }

    private fun bech32HrpExpand(hrp: String): IntArray {
        val ret = IntArray(hrp.length * 2 + 1)
        for (i in hrp.indices) ret[i] = hrp[i].code ushr 5
        ret[hrp.length] = 0
        for (i in hrp.indices) ret[hrp.length + 1 + i] = hrp[i].code and 31
        return ret
    }

    private fun convertBits(data: IntArray, fromBits: Int, toBits: Int, pad: Boolean): IntArray {
        var acc = 0
        var bits = 0
        val ret = ArrayList<Int>()
        val maxv = (1 shl toBits) - 1
        for (v in data) {
            require(v >= 0 && (v ushr fromBits) == 0) { "Invalid bit value" }
            acc = (acc shl fromBits) or v
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                ret.add((acc ushr bits) and maxv)
            }
        }
        if (pad) {
            if (bits > 0) ret.add((acc shl (toBits - bits)) and maxv)
        } else {
            require(bits < fromBits && ((acc shl (toBits - bits)) and maxv) == 0) { "Invalid Bech32 padding" }
        }
        return ret.toIntArray()
    }

    fun encodeBech32(hrp: String, hexData: String): String {
        val raw = hexToBytes(hexData)
        val in8 = IntArray(raw.size) { raw[it].toInt() and 0xff }
        val data5 = convertBits(in8, 8, 5, true)
        val expanded = bech32HrpExpand(hrp)
        val polymodInput = IntArray(expanded.size + data5.size + 6)
        System.arraycopy(expanded, 0, polymodInput, 0, expanded.size)
        System.arraycopy(data5, 0, polymodInput, expanded.size, data5.size)
        val mod = bech32Polymod(polymodInput) xor 1
        val sb = StringBuilder(hrp).append('1')
        for (d in data5) sb.append(BECH32_CHARSET[d])
        for (i in 0 until 6) sb.append(BECH32_CHARSET[(mod ushr (5 * (5 - i))) and 31])
        return sb.toString()
    }

    fun decodeBech32(bech: String): Pair<String, String> {
        val s = bech.lowercase()
        val pos = s.lastIndexOf('1')
        require(pos >= 1 && pos + 7 <= s.length) { "Invalid Bech32 string" }
        val hrp = s.substring(0, pos)
        val data = IntArray(s.length - pos - 1)
        for (i in data.indices) {
            val idx = BECH32_CHARSET.indexOf(s[pos + 1 + i])
            require(idx >= 0) { "Invalid Bech32 character" }
            data[i] = idx
        }
        val expanded = bech32HrpExpand(hrp)
        val check = IntArray(expanded.size + data.size)
        System.arraycopy(expanded, 0, check, 0, expanded.size)
        System.arraycopy(data, 0, check, expanded.size, data.size)
        require(bech32Polymod(check) == 1) { "Invalid Bech32 checksum" }
        val out8 = convertBits(data.copyOfRange(0, data.size - 6), 5, 8, false)
        val bytes = ByteArray(out8.size) { out8[it].toByte() }
        return Pair(hrp, bytesToHex(bytes))
    }

    fun generateKeys(privkeyHex: String? = null): Keys {
        val priv = (privkeyHex ?: bytesToHex(ByteArray(32).also { rng.nextBytes(it) })).lowercase()
        val pub = getPublicKeyHex(priv)
        return Keys(
            privkeyHex = priv,
            pubkeyHex = pub,
            asec = encodeBech32("asec", priv),
            apub = encodeBech32("apub", pub)
        )
    }

    fun parseA4AContact(input: String?, defaultRelays: List<String> = DEFAULT_RELAYS): ParsedContact? {
        val text = (input ?: "").trim()
        val npubRegex = Regex("\\b(apub1[023456789acdefghjklmnpqrstuvwxyz]{58})\\b", RegexOption.IGNORE_CASE)
        val match = npubRegex.find(text) ?: return null
        val apub = match.groupValues[1].lowercase()
        val (prefix, pubHex) = decodeBech32(apub)
        if (prefix != "apub" || pubHex.length != 64) return null
        val relayRegex = Regex("wss?://[^\\s,;\"'>)]+", RegexOption.IGNORE_CASE)
        val relays = relayRegex.findAll(text).map { it.value }.distinct().toList()
        return ParsedContact(
            apub = apub,
            pubkeyHex = pubHex,
            relays = if (relays.isNotEmpty()) relays else defaultRelays
        )
    }

    // --- 3. NIP-44 v2 Encryption & Decryption --------------------------------

    private fun hmacSha256(key: ByteArray, vararg data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (d in data) mac.update(d)
        return mac.doFinal()
    }

    fun nip44ConversationKey(privkeyHex: String, pubkeyHex: String): ByteArray {
        val priv = BigInteger(privkeyHex, 16)
        val pubPt = liftXEven(pubkeyHex)
        val sharedPt = pointMul(pubPt, priv) ?: error("ECDH point at infinity")
        val sharedX = bigTo32Bytes(sharedPt.x)
        return hmacSha256("nip44-v2".toByteArray(StandardCharsets.UTF_8), sharedX)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            t = hmacSha256(prk, t, info, byteArrayOf(counter.toByte()))
            val copyLen = minOf(t.size, length - offset)
            System.arraycopy(t, 0, out, offset, copyLen)
            offset += copyLen
            counter++
        }
        return out
    }

    private fun calcPaddedLen(unpaddedLen: Int): Int {
        if (unpaddedLen <= 32) return 32
        val nextPower = 1 shl (floor(ln((unpaddedLen - 1).toDouble()) / ln(2.0)).toInt() + 1)
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * ((unpaddedLen - 1) / chunk + 1)
    }

    private fun chacha20Counter0(key32: ByteArray, nonce12: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "ChaCha20"), ChaCha20ParameterSpec(nonce12, 0))
        return cipher.doFinal(input)
    }

    fun nip44Encrypt(
        plaintext: String,
        senderPrivkeyHex: String,
        recipientPubkeyHex: String,
        nonce32: ByteArray? = null
    ): String {
        val convKey = nip44ConversationKey(senderPrivkeyHex, recipientPubkeyHex)
        val nonce = nonce32 ?: ByteArray(32).also { rng.nextBytes(it) }
        val okm = hkdfExpand(convKey, nonce, 76)
        val chachaKey = okm.copyOfRange(0, 32)
        val chachaNonce = okm.copyOfRange(32, 44)
        val hmacKey = okm.copyOfRange(44, 76)

        val raw = plaintext.toByteArray(StandardCharsets.UTF_8)
        require(raw.size in 1..65535) { "Invalid plaintext length" }
        val padded = ByteArray(2 + calcPaddedLen(raw.size))
        padded[0] = ((raw.size ushr 8) and 0xff).toByte()
        padded[1] = (raw.size and 0xff).toByte()
        System.arraycopy(raw, 0, padded, 2, raw.size)

        val ciphertext = chacha20Counter0(chachaKey, chachaNonce, padded)
        val mac = hmacSha256(hmacKey, nonce, ciphertext)
        val payload = ByteArray(1 + 32 + ciphertext.size + 32)
        payload[0] = 0x02
        System.arraycopy(nonce, 0, payload, 1, 32)
        System.arraycopy(ciphertext, 0, payload, 33, ciphertext.size)
        System.arraycopy(mac, 0, payload, 33 + ciphertext.size, 32)
        return Base64.getEncoder().encodeToString(payload)
    }

    fun nip44Decrypt(payloadB64: String, recipientPrivkeyHex: String, senderPubkeyHex: String): String {
        require(payloadB64.length >= 132 && !payloadB64.startsWith("#")) { "Invalid NIP-44 payload" }
        val data = Base64.getDecoder().decode(payloadB64)
        require(data.size >= 99 && data[0].toInt() == 0x02) { "Unsupported NIP-44 version" }
        val nonce = data.copyOfRange(1, 33)
        val ciphertext = data.copyOfRange(33, data.size - 32)
        val mac = data.copyOfRange(data.size - 32, data.size)

        val convKey = nip44ConversationKey(recipientPrivkeyHex, senderPubkeyHex)
        val okm = hkdfExpand(convKey, nonce, 76)
        val chachaKey = okm.copyOfRange(0, 32)
        val chachaNonce = okm.copyOfRange(32, 44)
        val hmacKey = okm.copyOfRange(44, 76)

        val expectedMac = hmacSha256(hmacKey, nonce, ciphertext)
        require(MessageDigest.isEqual(expectedMac, mac)) { "NIP-44 MAC mismatch" }
        val padded = chacha20Counter0(chachaKey, chachaNonce, ciphertext)
        val unpaddedLen = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        require(unpaddedLen > 0 && padded.size == 2 + calcPaddedLen(unpaddedLen)) { "Invalid NIP-44 padding" }
        return String(padded, 2, unpaddedLen, StandardCharsets.UTF_8)
    }

    // --- 4. Encrypted File Blobs (a4a-chacha20poly1305-v1) -------------------

    fun openFileBlob(blob: ByteArray, keyHex: String, expectedSha256Hex: String): ByteArray {
        val actualSha = bytesToHex(sha256(blob))
        require(actualSha == expectedSha256Hex.lowercase()) { "Encrypted blob SHA-256 mismatch" }
        require(blob.size >= 28) { "Encrypted blob too short" }
        val nonce = blob.copyOfRange(0, 12)
        val ctAndTag = blob.copyOfRange(12, blob.size)
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(hexToBytes(keyHex), "ChaCha20-Poly1305"),
            IvParameterSpec(nonce)
        )
        cipher.updateAAD(FILE_ENC_SCHEME.toByteArray(StandardCharsets.UTF_8))
        return cipher.doFinal(ctAndTag)
    }
}
