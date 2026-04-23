package com.truecaller.backend.service.crypto;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.key.KeyGen;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * BLS12-381 G2 keygen and did:key encoding (multicodec {@code 0xeb01},
 * W3C-DID-KEY §2). Keys are real BBS+ keypairs (IRTF-BBS draft v5,
 * BLS12-381 SHA-256 ciphersuite) backed by the BFH BLS12-381 reference
 * library shipped with https://github.com/roblesjoel/P2_BBS_Signature.
 *
 * <p>The 96-byte compressed G2 element returned by {@code KeyGen.SkToPk}
 * is what we wrap in the multicodec — and what the verifier resolves
 * back from a {@code did:key} URL.
 */
@Service
public class BlsKeyService {

    /** Multicodec prefix for BLS12-381 G2 public keys (W3C-DID-KEY §2). */
    private static final byte[] MULTICODEC_BLS12_381_G2_PUB = { (byte) 0xeb, (byte) 0x01 };

    private static final SecureRandom RNG = new SecureRandom();

    /** Real BBS+ keypair. */
    public record BlsKeyPair(Scalar secret, OctetString publicKey) {}

    private final Map<String, BlsKeyPair> keyStore = new ConcurrentHashMap<>();

    public record KeyInfo(String did, String publicKeyBase64) {}

    /** Generates a BBS+ keypair and registers a corresponding {@code did:key}. */
    public KeyInfo generateKeyPair() {
        byte[] material = new byte[32]; // IRTF-BBS minimum; KeyGen aborts otherwise.
        RNG.nextBytes(material);
        Scalar sk = KeyGen.KeyGen(
                new OctetString(material),
                new OctetString(new byte[0]),
                new OctetString(new byte[0]));
        OctetString pk = KeyGen.SkToPk(sk);
        byte[] pkBytes = pk.toBytes();
        String did = "did:key:" + multibasePublicKey(pkBytes);
        keyStore.put(did, new BlsKeyPair(sk, pk));
        return new KeyInfo(did,
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(pkBytes));
    }

    public BlsKeyPair getKeyPair(String did) {
        BlsKeyPair kp = keyStore.get(did);
        if (kp == null) throw new IllegalArgumentException("Unknown BLS DID: " + did);
        return kp;
    }

    public boolean knows(String did) { return keyStore.containsKey(did); }

    /** Returns the raw 96-byte compressed G2 public key for a did:key. */
    public byte[] resolveDidKey(String didKey) {
        if (didKey == null) throw new IllegalArgumentException("null DID");
        int hash = didKey.indexOf('#');
        String did = hash >= 0 ? didKey.substring(0, hash) : didKey;
        if (!did.startsWith("did:key:z"))
            throw new IllegalArgumentException("Unsupported DID method: " + did);
        String mb = did.substring("did:key:".length());
        byte[] decoded = Base58Btc.decode(mb.substring(1));
        if (decoded.length < 2 || (decoded[0] & 0xff) != 0xeb || (decoded[1] & 0xff) != 0x01)
            throw new IllegalArgumentException("did:key is not BLS12-381 G2 (missing 0xeb01 multicodec): " + did);
        return Arrays.copyOfRange(decoded, 2, decoded.length);
    }

    /** Resolves a did:key (BLS12-381 G2) to the BBS+ public OctetString. */
    public OctetString resolveToPublicOctetString(String didKey) {
        return new OctetString(resolveDidKey(didKey));
    }

    /** Canonical did:key verification method id ({@code did + "#" + multibase}, W3C-CID §3.1.1). */
    public String verificationMethodFor(String didKey) {
        if (didKey == null || !didKey.startsWith("did:key:"))
            throw new IllegalArgumentException("Not a did:key DID: " + didKey);
        return didKey + "#" + didKey.substring("did:key:".length());
    }

    private static String multibasePublicKey(byte[] rawPubKey) {
        byte[] payload = new byte[MULTICODEC_BLS12_381_G2_PUB.length + rawPubKey.length];
        System.arraycopy(MULTICODEC_BLS12_381_G2_PUB, 0, payload, 0, MULTICODEC_BLS12_381_G2_PUB.length);
        System.arraycopy(rawPubKey, 0, payload, MULTICODEC_BLS12_381_G2_PUB.length, rawPubKey.length);
        return "z" + Base58Btc.encode(payload);
    }
}

