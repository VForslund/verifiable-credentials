package com.truecaller.backend.service.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ed25519 keygen, did:key (multicodec {@code 0xed01}) encode/resolve, raw sign/verify.
 *
 * <p>References: W3C-DID-KEY (the did:key Method) and W3C-DI-EDDSA (eddsa-jcs-2022).
 */
@Service
public class Ed25519KeyService {

    /** Multicodec prefix for Ed25519 public keys (W3C-DID-KEY §2). */
    private static final byte[] MULTICODEC_ED25519_PUB = { (byte) 0xed, (byte) 0x01 };

    private final Map<String, OctetKeyPair> keyStore = new ConcurrentHashMap<>();

    public record KeyInfo(String did, String publicKeyBase64) {}

    public KeyInfo generateKeyPair() {
        try {
            OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            byte[] pub = jwk.getDecodedX();
            String did = "did:key:" + multibasePublicKey(pub);
            keyStore.put(did, jwk);
            return new KeyInfo(did, Base64.getUrlEncoder().withoutPadding().encodeToString(pub));
        } catch (JOSEException e) {
            throw new RuntimeException("Ed25519 key generation failed", e);
        }
    }

    /** Returns the JWK we generated for {@code did} (private + public). */
    public OctetKeyPair getKeyPair(String did) {
        OctetKeyPair jwk = keyStore.get(did);
        if (jwk == null) throw new IllegalArgumentException("Unknown DID (no key pair): " + did);
        return jwk;
    }

    public boolean knows(String did) { return keyStore.containsKey(did); }

    /** Resolves a did:key (Ed25519) to a public-only Nimbus JWK. */
    public OctetKeyPair resolveToPublicJwk(String didKey) {
        byte[] rawPub = resolveDidKey(didKey);
        return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(rawPub)).build();
    }

    /** Canonical did:key verification method id ({@code did + "#" + multibase}, W3C-CID §3.1.1). */
    public String verificationMethodFor(String didKey) {
        if (didKey == null || !didKey.startsWith("did:key:"))
            throw new IllegalArgumentException("Not a did:key DID: " + didKey);
        return didKey + "#" + didKey.substring("did:key:".length());
    }

    /** Returns the raw 32-byte Ed25519 public key for a did:key, validating the 0xed01 prefix. */
    public byte[] resolveDidKey(String didKey) {
        if (didKey == null) throw new IllegalArgumentException("null DID");
        int hash = didKey.indexOf('#');
        String did = hash >= 0 ? didKey.substring(0, hash) : didKey;
        if (!did.startsWith("did:key:z"))
            throw new IllegalArgumentException("Unsupported DID method (only did:key is supported): " + did);
        String mb = did.substring("did:key:".length());
        byte[] decoded = Base58Btc.decode(mb.substring(1));
        if (decoded.length < 2 || (decoded[0] & 0xff) != 0xed || (decoded[1] & 0xff) != 0x01)
            throw new IllegalArgumentException("did:key is not Ed25519 (missing 0xed01 multicodec): " + did);
        return Arrays.copyOfRange(decoded, 2, decoded.length);
    }

    /** Raw Ed25519 signature → multibase base58btc (Data Integrity {@code proofValue} form). */
    public String signRaw(String did, byte[] message) {
        OctetKeyPair jwk = getKeyPair(did);
        Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(jwk.getDecodedD(), 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, params);
        signer.update(message, 0, message.length);
        return "z" + Base58Btc.encode(signer.generateSignature());
    }

    /** Verifies a multibase base58btc Ed25519 signature using the public key resolved from {@code didKey}. */
    public boolean verifyRaw(String didKey, byte[] message, String multibaseSig) {
        try {
            byte[] pub = resolveDidKey(didKey);
            if (multibaseSig == null || multibaseSig.isEmpty() || multibaseSig.charAt(0) != 'z') return false;
            byte[] sig = Base58Btc.decode(multibaseSig.substring(1));
            Ed25519PublicKeyParameters params = new Ed25519PublicKeyParameters(pub, 0);
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, params);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(sig);
        } catch (Exception e) {
            return false;
        }
    }

    private static String multibasePublicKey(byte[] rawPubKey) {
        byte[] payload = new byte[MULTICODEC_ED25519_PUB.length + rawPubKey.length];
        System.arraycopy(MULTICODEC_ED25519_PUB, 0, payload, 0, MULTICODEC_ED25519_PUB.length);
        System.arraycopy(rawPubKey, 0, payload, MULTICODEC_ED25519_PUB.length, rawPubKey.length);
        return "z" + Base58Btc.encode(payload);
    }
}

