package com.truecaller.backend.service.crypto;

import org.springframework.stereotype.Service;

/**
 * did:key resolver — multicodec-prefix dispatch (W3C-DID-KEY §2).
 *
 * <p>This is the only DID method we support per AGENT.md §11. Resolution
 * is purely local — we decode the multibase, validate the multicodec,
 * and hand the raw public key bytes back to whichever cryptosuite
 * needs them.
 */
@Service
public class DidResolver {

    public enum KeyType { ED25519, BLS12_381_G2 }

    private final Ed25519KeyService ed25519;
    private final BlsKeyService bls;

    public DidResolver(Ed25519KeyService ed25519, BlsKeyService bls) {
        this.ed25519 = ed25519;
        this.bls = bls;
    }

    /** Identifies which key type a did:key encodes by its multicodec prefix. */
    public KeyType keyType(String didKey) {
        if (didKey == null) throw new IllegalArgumentException("null DID");
        int hash = didKey.indexOf('#');
        String did = hash >= 0 ? didKey.substring(0, hash) : didKey;
        if (!did.startsWith("did:key:z"))
            throw new IllegalArgumentException("Unsupported DID method: " + did);
        byte[] decoded = Base58Btc.decode(did.substring("did:key:".length() + 1));
        if (decoded.length < 2)
            throw new IllegalArgumentException("Truncated did:key: " + did);
        int b0 = decoded[0] & 0xff, b1 = decoded[1] & 0xff;
        if (b0 == 0xed && b1 == 0x01) return KeyType.ED25519;
        if (b0 == 0xeb && b1 == 0x01) return KeyType.BLS12_381_G2;
        throw new IllegalArgumentException(
                "Unsupported did:key multicodec: 0x" + Integer.toHexString(b0)
                        + Integer.toHexString(b1));
    }

    /**
     * Returns true iff the given verification method URL is authoritative for
     * {@code assertionMethod} on the resolved DID document — for did:key, every
     * key is authoritative for every purpose by definition (W3C-DID-KEY §3.2).
     */
    public boolean isAssertionMethod(String verificationMethodUrl) {
        if (verificationMethodUrl == null) return false;
        int hash = verificationMethodUrl.indexOf('#');
        if (hash <= 0) return false;
        String did = verificationMethodUrl.substring(0, hash);
        String fragment = verificationMethodUrl.substring(hash + 1);
        // Per did:key spec, the fragment MUST equal the multibase identifier of the DID.
        return did.startsWith("did:key:z")
                && fragment.equals(did.substring("did:key:".length()));
    }
}

