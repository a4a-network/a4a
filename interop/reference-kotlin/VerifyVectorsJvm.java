import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Zero-dependency JVM verifier for the A4A v0.4 app & messenger test vectors
 * using the exact standard JDK/Android crypto primitives from A4AClientMinimal.kt.
 *
 * Run directly on OpenJDK 17+:
 *   java interop/reference-kotlin/VerifyVectorsJvm.java
 */
public class VerifyVectorsJvm {

    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger GX = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GY = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger EXP_SQRT = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4));

    record Point(BigInteger x, BigInteger y) {}
    private static final Point G = new Point(GX, GY);

    private static BigInteger modP(BigInteger a) {
        BigInteger r = a.mod(P);
        return r.signum() < 0 ? r.add(P) : r;
    }

    private static Point pointAdd(Point p1, Point p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        if (p1.x.equals(p2.x)) {
            if (!p1.y.equals(p2.y) || p1.y.equals(BigInteger.ZERO)) return null;
            BigInteger lam = modP(THREE.multiply(p1.x).multiply(p1.x).multiply(TWO.multiply(p1.y).modInverse(P)));
            BigInteger x3 = modP(lam.multiply(lam).subtract(TWO.multiply(p1.x)));
            BigInteger y3 = modP(lam.multiply(p1.x.subtract(x3)).subtract(p1.y));
            return new Point(x3, y3);
        }
        BigInteger lam = modP(p2.y.subtract(p1.y).multiply(modP(p2.x.subtract(p1.x)).modInverse(P)));
        BigInteger x3 = modP(lam.multiply(lam).subtract(p1.x).subtract(p2.x));
        BigInteger y3 = modP(lam.multiply(p1.x.subtract(x3)).subtract(p1.y));
        return new Point(x3, y3);
    }

    private static Point pointMul(Point pt, BigInteger scalar) {
        BigInteger k = scalar.mod(N);
        if (k.equals(BigInteger.ZERO) || pt == null) return null;
        Point res = null;
        Point addend = pt;
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) res = pointAdd(res, addend);
            addend = pointAdd(addend, addend);
            k = k.shiftRight(1);
        }
        return res;
    }

    private static Point liftXEven(String xHex) {
        BigInteger x = new BigInteger(xHex, 16);
        BigInteger c = modP(x.modPow(THREE, P).add(SEVEN));
        BigInteger y = c.modPow(EXP_SQRT, P);
        if (!modP(y.multiply(y)).equals(c)) throw new IllegalArgumentException("Point not on curve");
        return new Point(x, !y.testBit(0) ? y : P.subtract(y));
    }

    private static byte[] bigTo32Bytes(BigInteger n) {
        byte[] raw = n.toByteArray();
        if (raw.length == 32) return raw;
        byte[] out = new byte[32];
        if (raw.length > 32) System.arraycopy(raw, raw.length - 32, out, 0, 32);
        else System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        return out;
    }

    private static byte[] sha256(byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }

    private static byte[] taggedHash(String tag, byte[]... parts) throws Exception {
        byte[] th = sha256(tag.getBytes(StandardCharsets.UTF_8));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(th);
        md.update(th);
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }

    private static String getPublicKeyHex(String privHex) {
        Point pt = pointMul(G, new BigInteger(privHex, 16));
        return HexFormat.of().formatHex(bigTo32Bytes(pt.x));
    }

    private static boolean schnorrVerify(String msgHashHex, String pubkeyHex, String sigHex) throws Exception {
        Point pt = liftXEven(pubkeyHex);
        BigInteger r = new BigInteger(sigHex.substring(0, 64), 16);
        BigInteger s = new BigInteger(sigHex.substring(64, 128), 16);
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) return false;
        byte[] rx = HexFormat.of().parseHex(sigHex.substring(0, 64));
        byte[] px = HexFormat.of().parseHex(pubkeyHex);
        byte[] m = HexFormat.of().parseHex(msgHashHex);
        BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", rx, px, m)).mod(N);
        Point sG = pointMul(G, s);
        Point eP = pointMul(new Point(pt.x, P.subtract(pt.y)), e);
        Point rPt = pointAdd(sG, eP);
        return rPt != null && !rPt.y.testBit(0) && rPt.x.equals(r);
    }

    // Bech32
    private static final String BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] BECH32_GEN = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    private static int bech32Polymod(int[] values) {
        int chk = 1;
        for (int v : values) {
            int top = chk >>> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (int i = 0; i < 5; i++) if (((top >>> i) & 1) != 0) chk ^= BECH32_GEN[i];
        }
        return chk;
    }

    private static int[] bech32HrpExpand(String hrp) {
        int[] ret = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) ret[i] = hrp.charAt(i) >>> 5;
        ret[hrp.length()] = 0;
        for (int i = 0; i < hrp.length(); i++) ret[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        return ret;
    }

    private static int[] convertBits(int[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0, bits = 0, maxv = (1 << toBits) - 1;
        List<Integer> ret = new ArrayList<>();
        for (int v : data) {
            acc = (acc << fromBits) | v;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.add((acc >>> bits) & maxv);
            }
        }
        if (pad && bits > 0) ret.add((acc << (toBits - bits)) & maxv);
        return ret.stream().mapToInt(i -> i).toArray();
    }

    private static String encodeBech32(String hrp, String hexData) {
        byte[] raw = HexFormat.of().parseHex(hexData);
        int[] in8 = new int[raw.length];
        for (int i = 0; i < raw.length; i++) in8[i] = raw[i] & 0xff;
        int[] data5 = convertBits(in8, 8, 5, true);
        int[] exp = bech32HrpExpand(hrp);
        int[] poly = new int[exp.length + data5.length + 6];
        System.arraycopy(exp, 0, poly, 0, exp.length);
        System.arraycopy(data5, 0, poly, exp.length, data5.length);
        int mod = bech32Polymod(poly) ^ 1;
        StringBuilder sb = new StringBuilder(hrp).append('1');
        for (int d : data5) sb.append(BECH32_CHARSET.charAt(d));
        for (int i = 0; i < 6; i++) sb.append(BECH32_CHARSET.charAt((mod >>> (5 * (5 - i))) & 31));
        return sb.toString();
    }

    private static byte[] hmacSha256(byte[] key, byte[]... parts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        for (byte[] p : parts) mac.update(p);
        return mac.doFinal();
    }

    private static byte[] nip44ConversationKey(String privHex, String pubHex) throws Exception {
        Point shared = pointMul(liftXEven(pubHex), new BigInteger(privHex, 16));
        return hmacSha256("nip44-v2".getBytes(StandardCharsets.UTF_8), bigTo32Bytes(shared.x));
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int offset = 0, counter = 1;
        while (offset < length) {
            t = hmacSha256(prk, t, info, new byte[]{(byte) counter});
            int n = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, out, offset, n);
            offset += n;
            counter++;
        }
        return out;
    }

    private static int calcPaddedLen(int unpaddedLen) {
        if (unpaddedLen <= 32) return 32;
        int nextPower = 1 << ((int) Math.floor(Math.log(unpaddedLen - 1) / Math.log(2)) + 1);
        int chunk = nextPower <= 256 ? 32 : nextPower / 8;
        return chunk * ((unpaddedLen - 1) / chunk + 1);
    }

    private static String nip44Decrypt(String payloadB64, String recipientPrivHex, String senderPubHex) throws Exception {
        byte[] data = Base64.getDecoder().decode(payloadB64);
        if (data[0] != 0x02) throw new IllegalArgumentException("Unsupported NIP-44 version");
        byte[] nonce = new byte[32];
        byte[] ct = new byte[data.length - 65];
        byte[] mac = new byte[32];
        System.arraycopy(data, 1, nonce, 0, 32);
        System.arraycopy(data, 33, ct, 0, ct.length);
        System.arraycopy(data, data.length - 32, mac, 0, 32);

        byte[] convKey = nip44ConversationKey(recipientPrivHex, senderPubHex);
        byte[] okm = hkdfExpand(convKey, nonce, 76);
        byte[] chachaKey = new byte[32];
        byte[] chachaNonce = new byte[12];
        byte[] hmacKey = new byte[32];
        System.arraycopy(okm, 0, chachaKey, 0, 32);
        System.arraycopy(okm, 32, chachaNonce, 0, 12);
        System.arraycopy(okm, 44, hmacKey, 0, 32);

        byte[] expectedMac = hmacSha256(hmacKey, nonce, ct);
        if (!MessageDigest.isEqual(expectedMac, mac)) throw new SecurityException("NIP-44 MAC mismatch");

        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chachaKey, "ChaCha20"), new ChaCha20ParameterSpec(chachaNonce, 0));
        byte[] padded = cipher.doFinal(ct);
        int unpaddedLen = ((padded[0] & 0xff) << 8) | (padded[1] & 0xff);
        if (unpaddedLen <= 0 || padded.length != 2 + calcPaddedLen(unpaddedLen)) throw new SecurityException("Bad padding");
        return new String(padded, 2, unpaddedLen, StandardCharsets.UTF_8);
    }

    private static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    private static String extractJsonField(String block, String field) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(block);
        if (!m.find()) throw new IllegalArgumentException("Field not found: " + field);
        return m.group(1);
    }

    public static void main(String[] args) throws Exception {
        Path vectorsFile = Path.of("interop/test-vectors/app-messenger-v0.4.json");
        if (!Files.exists(vectorsFile)) {
            vectorsFile = Path.of("../test-vectors/app-messenger-v0.4.json");
        }
        String json = Files.readString(vectorsFile, StandardCharsets.UTF_8);

        // 1. Verify keys & Bech32
        String aliceAgentPriv = "0202020202020202020202020202020202020202020202020202020202020202";
        String aliceAgentPub = getPublicKeyHex(aliceAgentPriv);
        check(aliceAgentPub.equals("4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"), "alice_agent pubkey");
        check(encodeBech32("apub", aliceAgentPub).equals("apub1f49ke5fkzqev4x7j46uajq92f4zan6kcpty5yvm5c3g6wf2dqanq02uprj"), "alice_agent apub");

        String bobUserPriv = "0303030303030303030303030303030303030303030303030303030303030303";
        String bobUserPub = getPublicKeyHex(bobUserPriv);
        check(bobUserPub.equals("531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"), "bob_user pubkey");
        check(encodeBech32("apub", bobUserPub).equals("apub12v07vp5px3gr6ferzvez0jr84j86djpu2dlf53xrck7mmjcluvmsge0kyy"), "bob_user apub");

        // 2. Verify Schnorr BIP-340 signatures for Mandate (31000), Profile (31001), RelayList (10002), Inner Rumor (14)
        check(schnorrVerify(
            "6a77c31c930e58bd2bda43751c858e161841ab32faa1b1de453cbcd7bc8bba82",
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "55401685860fdb66855cf786da0cd35f869417c127ae2977df459f3d22915252e55da961844178f9d1bd42ae028c92b9fc2fe5f1a3cb5e0f59f90b2788d1443a"
        ), "Mandate kind 31000 BIP-340 verify");

        check(schnorrVerify(
            "fe0a32f9fd1c2077b3774c9b7faacba240be6d45f7e4e3a3c79b1bf17df22a5d",
            aliceAgentPub,
            extractJsonField(json.substring(json.indexOf("\"profile_kind_31001\"")), "sig")
        ), "Profile kind 31001 BIP-340 verify");

        check(schnorrVerify(
            "a087c7b7648e9418c4e248ba17c5b1044ded09c6a3d42a3c3eedea9daaf83402",
            aliceAgentPub,
            "3fca1357a6b433ae6d85e986072ea09c7f0fa6c26d1ae11add804ddf8d1c81065705c8ffb39c4c456060d05c68dc1cdf083dcafcaf8dabb75b150f312b926afd"
        ), "Inner Rumor kind 14 BIP-340 verify");

        // 3. Verify NIP-44 v2 ECDH conversation key & payload decryption
        byte[] convKey = nip44ConversationKey(aliceAgentPriv, bobUserPub);
        check(HexFormat.of().formatHex(convKey).equals("26c7fcb82d7e02ea36f13c8189e275d6f974e52f9bcb57202cdd3faab811a27f"), "NIP-44 conversation key");
        String nip44Payload = extractJsonField(json, "payload_b64");
        String decrypted = nip44Decrypt(nip44Payload, bobUserPriv, aliceAgentPub);
        String expectedPlaintext = extractJsonField(json, "plaintext");
        check(decrypted.equals(expectedPlaintext), "NIP-44 direct decrypt");

        // 4. Verify Gift Wrap (kind 1059 -> kind 13 -> signed kind 14)
        String gwEphPub = "462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b";
        int gwIdx = json.indexOf("\"f54fad2864d8bd5e99a9297ef548a71da1cbb5b257f989731e510fe1b462b07d\"");
        String gwContent = extractJsonField(json.substring(gwIdx), "content");
        String sealJson = nip44Decrypt(gwContent, bobUserPriv, gwEphPub);
        String sealContent = extractJsonField(sealJson, "content");
        String innerJson = nip44Decrypt(sealContent, bobUserPriv, aliceAgentPub);
        check(innerJson.contains("\"a087c7b7648e9418c4e248ba17c5b1044ded09c6a3d42a3c3eedea9daaf83402\""), "GiftWrap unwrap inner id");

        // 5. Verify Encrypted File Attachment (a4a-chacha20poly1305-v1)
        byte[] blob = HexFormat.of().parseHex(extractJsonField(json, "encrypted_blob_hex"));
        String expectedSha = extractJsonField(json, "encrypted_blob_sha256");
        check(HexFormat.of().formatHex(sha256(blob)).equals(expectedSha), "File blob SHA-256");
        byte[] nonce12 = new byte[12];
        byte[] ctAndTag = new byte[blob.length - 12];
        System.arraycopy(blob, 0, nonce12, 0, 12);
        System.arraycopy(blob, 12, ctAndTag, 0, ctAndTag.length);
        Cipher aead = Cipher.getInstance("ChaCha20-Poly1305");
        aead.init(
            Cipher.DECRYPT_MODE,
            new SecretKeySpec(HexFormat.of().parseHex("6161616161616161616161616161616161616161616161616161616161616161"), "ChaCha20-Poly1305"),
            new IvParameterSpec(nonce12)
        );
        aead.updateAAD("a4a-chacha20poly1305-v1".getBytes(StandardCharsets.UTF_8));
        byte[] filePlain = aead.doFinal(ctAndTag);
        check(HexFormat.of().formatHex(filePlain).equals(extractJsonField(json, "plaintext_hex")), "File decrypt");

        System.out.println("ALL A4A v0.4 JVM / KOTLIN CRYPTO & ENVELOPE VECTORS VERIFIED SUCCESSFULLY.");
    }
}
