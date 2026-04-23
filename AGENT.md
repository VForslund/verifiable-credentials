# AGENT.md — Verifiable Credentials Reference Implementation

> **Mandate:** the implementation MUST be 100% conformant with the W3C
> Verifiable Credentials Data Model v2.0 and the supporting W3C / IETF specs
> listed below. No proprietary fields leaking into the credential, no
> "convenience" mirror objects pretending to be VC properties, no shortcuts
> on canonicalization, key binding, or proof verification.
>
> The wallet MUST be able to:
> 1. **Selectively disclose** any subset of the issuer-signed claims.
> 2. **Derive** new proofs from a signed credential — including arbitrary
>    range / threshold predicates such as "age ≥ N for any N the issuer
>    never explicitly enumerated" — without revealing the underlying claim.
>
> When a feature cannot be done in a fully spec-conformant way, it MUST NOT
> be implemented at all. Add a comment pointing at the spec section and
> stop. We do not ship demo-grade hand-waves.

---

## 1. Normative References (read these, link to them in code comments)

| # | Spec | URL |
|---|------|-----|
| W3C-VCDM-2.0    | Verifiable Credentials Data Model v2.0                 | https://www.w3.org/TR/vc-data-model-2.0/ |
| W3C-VC-DI       | Verifiable Credential Data Integrity 1.0               | https://www.w3.org/TR/vc-data-integrity/ |
| W3C-DI-EDDSA    | Data Integrity EdDSA Cryptosuites v1.0 (`eddsa-jcs-2022`) | https://www.w3.org/TR/vc-di-eddsa/ |
| W3C-DI-BBS      | Data Integrity BBS Cryptosuites v1.0 (`bbs-2023`)      | https://www.w3.org/TR/vc-di-bbs/ |
| W3C-VC-JOSE-COSE| Securing VCs using JOSE and COSE                       | https://www.w3.org/TR/vc-jose-cose/ |
| W3C-CID         | Controlled Identifier Document 1.0                      | https://www.w3.org/TR/cid/ |
| W3C-DID         | Decentralized Identifiers (DIDs) v1.0                  | https://www.w3.org/TR/did-1.0/ |
| W3C-DID-KEY     | The did:key Method                                     | https://w3c-ccg.github.io/did-method-key/ |
| W3C-STATUS-LIST | Bitstring Status List v1.0                              | https://www.w3.org/TR/vc-bitstring-status-list/ |
| IETF-SD-JWT     | Selective Disclosure for JWTs (SD-JWT)                  | https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/ |
| IETF-SD-JWT-VC  | SD-JWT-based Verifiable Credentials                     | https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/ |
| IETF-JCS        | JSON Canonicalization Scheme (RFC 8785)                 | https://www.rfc-editor.org/rfc/rfc8785 |
| IRTF-BBS        | The BBS Signature Scheme                                | https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/ |

Anything not anchored in one of these specs is, by definition, not in scope.

---

## 2. Two Securing Mechanisms, Both Fully Conformant

VCDM 2.0 (§4.12) deliberately does not pick one securing mechanism. We
implement two, side-by-side, because they serve different needs:

### 2.1 `bbs-2023` (W3C Data Integrity, BBS Cryptosuite) — DEFAULT

Use BBS+ for any credential where the holder must derive proofs the issuer
did not pre-enumerate (range proofs, set-membership, arbitrary predicates).

* **Issuer** signs the canonicalised credential once with a BBS+ signature
  over BLS12-381 G1, producing a `DataIntegrityProof` of type
  `DataIntegrityProof` with `cryptosuite: "bbs-2023"` and
  `proofPurpose: "assertionMethod"`. This is the **base proof**.
* **Holder** runs the `deriveProof` algorithm from W3C-DI-BBS §3.4.6 to
  produce a **derived proof** that:
  * reveals only the chosen statements (selective disclosure),
  * proves arbitrary predicates over hidden statements (range, equality,
    set-membership) using the BBS+ proof-of-knowledge protocol,
  * is unlinkable to the base proof and to other derived proofs.
* **Verifier** verifies the derived proof per W3C-DI-BBS §3.4.7.

This is the only path that supports true derivable proofs (e.g. "age ≥ 27"
when the issuer only signed `dateOfBirth`).

### 2.2 SD-JWT VC (IETF-SD-JWT-VC + VCDM 2.0 EnvelopedVerifiableCredential)

Use SD-JWT VC for interop with ecosystems standardised on it (EUDI ARF,
ISO 18013-5 mDL profile, OpenID4VC). It supports:

* **Selective disclosure** of any subset of the issuer-signed claims.
* **Predicate disclosure** ONLY for thresholds the issuer pre-computed and
  signed as boolean claims (`age_equal_or_over_18`, `_21`, etc.). This is
  the ISO mDL convention; it is NOT a derived proof — the wallet cannot
  prove "age ≥ 27" without revealing `dateOfBirth`.

The SD-JWT itself is wrapped in a VCDM 2.0 `EnvelopedVerifiableCredential`
per §4.3.2 with `id: "data:application/vc+sd-jwt,<sd-jwt>"`.

### 2.3 Mechanism Selection

The issuer endpoint accepts a `securingMechanism` parameter:

```
"securingMechanism": "bbs-2023"        // default; supports derived proofs
"securingMechanism": "sd-jwt-vc"       // selective disclosure only
"securingMechanism": "eddsa-jcs-2022"  // no selective disclosure; for non-private VCs
```

The wallet inspects `proof.cryptosuite` (or the envelope media type) at
present-time and picks the correct presentation algorithm. Mixing
mechanisms inside one `VerifiablePresentation.verifiableCredential` array
is permitted by VCDM 2.0 and MUST be supported.

---

## 3. Roles

### 3.1 Issuer
* Generates and persists its own keys (one per `securingMechanism`):
  * Ed25519 for `eddsa-jcs-2022` and SD-JWT VC.
  * BLS12-381 G2 for `bbs-2023` (signatures live in G1, public keys in G2).
* Identifier is a `did:key` (W3C-DID-KEY) for both curves; the multicodec
  prefix MUST be `0xed01` for Ed25519 and `0xeb01` for BLS12-381 G2.
* Returns ONLY a W3C-conformant credential. UI helper data is returned in
  a clearly non-VC sibling object (see §5.2).

### 3.2 Holder / Wallet
* Generates its own `did:key` per session.
* Stores credentials verbatim — never mutates the issuer's signed bytes.
* When responding to a presentation request:
  * For `bbs-2023`: runs `deriveProof` with the verifier's challenge as
    nonce; embeds the derived proof in the VC.
  * For SD-JWT VC: runs the SD-JWT presentation algorithm (§4.2 of
    IETF-SD-JWT) with verifier-supplied `aud` and `nonce` bound into the
    Key Binding JWT.
* Wraps the secured credential(s) in a `VerifiablePresentation` (VCDM 2.0
  §5) and signs the VP with its own Data Integrity proof
  (`proofPurpose: "authentication"`, `domain` = verifier DID,
  `challenge` = verifier nonce — VCDM 2.0 §6.2.1 / W3C-VC-DI §2.2).

### 3.3 Verifier
* Exposes a `/challenge` endpoint that returns `{verifierDid, nonce}` for
  each request (replay protection).
* On verification, performs the full check matrix in §6.

---

## 4. Identifiers and Keys

* DIDs: `did:key` only, per W3C-DID-KEY. Resolution is local: decode the
  multibase, validate the multicodec prefix, return the public key.
* Verification method IDs: `<did>#<multibase-fragment>` (W3C-CID §3.1.1).
* No raw public keys in the VC body — always reference via DID URL.
* Key generation MUST use a CSPRNG (`SecureRandom` / OS entropy).

---

## 5. Credential Shape (VCDM 2.0)

### 5.1 Required properties on every issued VC

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://truecaller.demo/contexts/identity/v1"
  ],
  "id": "urn:uuid:…",
  "type": ["VerifiableCredential", "GovernmentIdentityCredential"],
  "issuer": "did:key:…",
  "validFrom": "2026-04-22T09:20:52Z",
  "validUntil": "2036-04-19T09:20:52Z",
  "credentialSubject": { "id": "did:key:…", "…": "…" },
  "credentialSchema": {
    "id": "https://truecaller.demo/schemas/GovernmentIdentityCredential.json",
    "type": "JsonSchema"
  },
  "credentialStatus": {
    "id": "https://truecaller.demo/status/3#94567",
    "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://truecaller.demo/status/3"
  },
  "proof": { "…": "…" }
}
```

* `@context[0]` MUST be `"https://www.w3.org/ns/credentials/v2"` (VCDM
  2.0 §4.1). Any additional terms used in the document MUST be defined in
  a JSON-LD context referenced after it. No undefined terms in the body.
* `type[0]` MUST be `"VerifiableCredential"`.
* `issuer` MAY be a string DID or an object `{id: <DID>}`. It MUST NOT
  carry display fields; display metadata belongs in a separate
  type-metadata document.
* `validFrom` / `validUntil` are `xsd:dateTime` (VCDM 2.0 §4.6).
* `credentialSchema` MUST point to a real JSON Schema document; the
  verifier validates `credentialSubject` against it.
* `credentialStatus` MUST use `BitstringStatusListEntry` per
  W3C-STATUS-LIST. The issuer hosts the status list at
  `/status/{listId}` and updates it on revocation.

### 5.2 Issuer response transport

The HTTP response from `/api/issuer/issue` MUST be:

```json
{
  "verifiableCredential": { …the VC exactly as defined in §5.1… }
}
```

For SD-JWT VC the value of `verifiableCredential` is the
`EnvelopedVerifiableCredential` object (VCDM 2.0 §4.3.2).

A wallet UI helper MAY be returned as a sibling key, but it MUST be
clearly named and MUST NOT mirror VC properties at the top level:

```json
{
  "verifiableCredential": { … },
  "_walletHints": { "issuerDisplayName": "…", "icon": "…", "sdFieldNames": […] }
}
```

The leading underscore signals "non-normative; never forwarded to a
verifier". The holder MUST strip `_walletHints` before any further use.

The previous hybrid blob (top-level mirrors of `id` / `type` / `issuer` /
`credentialSubject` / `sdJwt` / `sdFields` alongside `envelopedCredential`)
is **REMOVED**. Any code reading those top-level mirrors is non-conformant
and must be migrated.

### 5.3 Verifiable Presentation shape

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:…",
  "type": ["VerifiablePresentation"],
  "holder": "did:key:…",
  "verifiableCredential": [ …VCs or EnvelopedVerifiableCredentials… ],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "…",
    "verificationMethod": "did:key:…#…",
    "proofPurpose": "authentication",
    "domain": "<verifier DID>",
    "challenge": "<verifier nonce>",
    "proofValue": "z…"
  }
}
```

`domain` and `challenge` MUST be present and MUST equal the verifier's
challenge (VCDM 2.0 §6.2.1). The VP body MUST NOT contain any
non-normative fields such as `privacySummary` — those are returned to the
wallet UI as a separate object alongside the VP, never inside it.

---

## 6. Verification Algorithm (verifier side)

For each presentation, in order; first failure is fatal:

1. **Structural** — `@context[0]`, `type` includes `VerifiablePresentation`,
   `id` is a URI, `verifiableCredential` is a non-empty array.
2. **VP proof** — Verify the `DataIntegrityProof` on the VP per W3C-VC-DI
   §4.2.
3. **VP challenge binding** — `proof.domain == verifierDid` and
   `proof.challenge == issuedNonce`. Reject otherwise.
4. **Per credential**, pick the algorithm from `proof.cryptosuite` or the
   envelope media type:
   * **`bbs-2023`** — W3C-DI-BBS §3.4.7 verification. The derived proof
     MUST cover the verifier's nonce.
   * **`eddsa-jcs-2022`** — W3C-DI-EDDSA §3.3.
   * **SD-JWT VC** — IETF-SD-JWT §6 + IETF-SD-JWT-VC §3.5. KB-JWT MUST
     be present; `aud == verifierDid`, `nonce == issuedNonce`,
     `sd_hash` MUST match the presented SD-JWT. Reject any disclosure
     whose digest is not in `_sd`.
5. **Issuer trust** — Resolve the issuer DID, confirm the verification
   method is authoritative for `assertionMethod`.
6. **Temporal validity** — `validFrom <= now < validUntil`.
7. **Schema** — Fetch `credentialSchema.id`, validate
   `credentialSubject` against it.
8. **Status** — Fetch `credentialStatus.statusListCredential`, verify ITS
   proof, look up `statusListIndex`. Reject if revoked.
9. **Holder binding** — For SD-JWT VC: KB-JWT signature with `cnf` key.
   For Data Integrity: `credentialSubject.id == VP.holder` (or an explicit
   holder-binding proof).
10. **Business assertions** — Evaluate against revealed / proven claims.
    For `bbs-2023` derived proofs, the predicate result is part of the
    proof itself (no further computation). For SD-JWT VC predicates, read
    the disclosed `age_equal_or_over_NN` boolean.

A check that cannot be performed (e.g. status list unreachable) is a
verification failure, not a warning.

---

## 7. Selective vs. Derived Disclosure — How the Wallet Decides

Given a verifier proof request item `{field, operator, value}`:

```
function chooseDisclosure(item, vc):
  if vc uses bbs-2023:
      # True derived proof of any predicate, no pre-computed claim needed.
      return DerivedProofRequest(reveal=[…], predicates=[(item.field, op, value)])

  if vc uses sd-jwt-vc:
      if item.operator in {age_gte, age_lte} and "age_equal_or_over_<value>" ∈ sdFields:
          return DiscloseSdJwtClaim("age_equal_or_over_<value>")
      if item.field ∈ sdFields:
          return DiscloseSdJwtClaim(item.field)   # discloses the raw value
      # No way to satisfy the predicate without revealing the field; refuse.
      return Refuse("not derivable on SD-JWT without raw disclosure")

  # eddsa-jcs-2022: VC is all-or-nothing, no selective disclosure possible.
  return DiscloseFullCredential()
```

The wallet MUST surface this decision to the user before sending. The user
sees exactly which atoms (or which derived predicates) will be revealed.

---

## 8. Backend Implementation (Spring Boot, Java 25)

```
com.truecaller.backend
├── BackendApplication.java
├── CorsConfig.java / WebConfig.java
├── controller/
│   └── VcController.java                     # POST /issuer/issue, /holder/present, /verifier/verify; GET /verifier/challenge, /status/{id}, /schemas/{name}, /contexts/{name}
├── dto/
│   ├── IssueRequest.java                     # issuerType, holderDid, claims, securingMechanism
│   ├── PresentRequest.java                   # holderDid, vcs, proofRequest, verifierDid, nonce
│   └── VerifyRequest.java                    # presentation, assertions, expectedAud, expectedNonce
├── service/
│   ├── crypto/
│   │   ├── Ed25519KeyService.java            # keygen, sign, verify, did:key
│   │   ├── BlsKeyService.java                # BLS12-381 G2 keygen; backed by mattrglobal/pairing-crypto via JNI or pure-Java pairing impl
│   │   └── DidResolver.java                  # did:key only; multicodec validation
│   ├── canon/
│   │   ├── JcsCanonicalizer.java             # RFC 8785 (existing)
│   │   └── JsonLdCanonicalizer.java          # URDNA2015 (titanium-json-ld + rdf-canon-java)
│   ├── proof/
│   │   ├── DataIntegrityEddsaJcs2022.java    # existing, extracted
│   │   ├── DataIntegrityBbs2023.java         # NEW — issue base proof, derive, verify
│   │   ├── SdJwtVcService.java               # existing SdJwtService renamed
│   │   └── ProofRouter.java                  # picks impl by cryptosuite / envelope media type
│   ├── status/
│   │   └── BitstringStatusListService.java   # NEW — produces and verifies status list VCs
│   ├── schema/
│   │   └── CredentialSchemaService.java      # NEW — JSON Schema fetch + validate
│   ├── IssuerService.java                    # builds VC, attaches schema/status, delegates to ProofRouter
│   ├── HolderService.java                    # builds VP, derives proofs / runs SD-JWT presentation
│   └── VerifierService.java                  # full §6 algorithm
└── resources/
    ├── contexts/identity-v1.jsonld           # served at /contexts/identity/v1
    ├── schemas/GovernmentIdentityCredential.json
    └── schemas/…
```

### 8.1 Dependencies (add to `pom.xml`)

| Artifact | Purpose |
|---|---|
| `com.nimbusds:nimbus-jose-jwt`           | JOSE primitives (existing) |
| `org.bouncycastle:bcprov-jdk18on`        | Ed25519 + BLS12-381 base arithmetic (existing) |
| `io.github.erdtman:java-json-canonicalization` | JCS (existing) |
| `com.apicatalog:titanium-json-ld`        | JSON-LD 1.1 expansion / compaction |
| `com.apicatalog:rdf-canon`               | URDNA2015 canonical RDF (required by `bbs-2023`) |
| `com.apicatalog:iron-verifiable-credentials` | Reference VCDM impl + `bbs-2023` & `eddsa-jcs-2022` cryptosuites — use as the spine; we only specialise where the demo needs to. |
| `com.networknt:json-schema-validator`    | JSON Schema 2020-12 |

`iron-verifiable-credentials` is the most actively maintained Java
implementation of Data Integrity + cryptosuites, including BBS+. Prefer
its primitives over hand-rolling pairing crypto. Hand-rolled BBS+ is out
of scope.

### 8.2 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/keys/generate` | Generate a holder keypair; returns `{did}` |
| `GET`  | `/api/issuers` | Catalogue of demo issuers and their fields |
| `POST` | `/api/issuer/issue` | Issue a VC; returns `{verifiableCredential, _walletHints}` |
| `POST` | `/api/holder/present` | Build a VP for a proof request; returns `{verifiableCredential: VP}` plus a sibling `_walletHints` |
| `GET`  | `/api/verifier/challenge` | Returns `{verifierDid, nonce}` |
| `POST` | `/api/verifier/verify` | Verifies a VP; returns the §6 check report |
| `GET`  | `/api/status/{listId}` | Bitstring status list VC (signed) |
| `GET`  | `/api/schemas/{name}.json` | JSON Schema for a credential type |
| `GET`  | `/api/contexts/{name}` | JSON-LD context |
| `GET`  | `/.well-known/did.json` (optional) | If hosting any `did:web` issuers |

---

## 9. Frontend Implementation (Angular 21, standalone components)

* `services/vc-api.service.ts` — typed wrappers around the endpoints in §8.2.
* `services/vc-state.service.ts` — Signals: `holderDid`, `storedCredentials`,
  `pendingProofRequest`, `currentChallenge`, `lastPresentation`, `lastReport`.
* `services/credential-decoder.service.ts` — pure client-side decoder:
  given a stored VC (BBS-secured JSON-LD or `EnvelopedVerifiableCredential`),
  returns the wallet-side display model (issuer name, type, `validFrom`,
  decoded subject, list of disclosable fields). The wallet display MUST be
  derived locally from the credential, NOT from a server-supplied mirror.
* `issuer/`, `wallet/`, `verifier/` components — UI only; no business
  logic. Wallet shows the disclosure preview from §7 and the resulting
  derived/SD-JWT artifact before sending.

The wallet state never stores anything outside the W3C credential plus the
ephemeral `_walletHints`. No mirrored VC fields at the top level.

---

## 10. Test Plan (`backend/src/test/...`)

A suite per cryptosuite, each running issue → present → verify and
covering the failure modes. The tests are the conformance gate.

| Test | Asserts |
|---|---|
| `Eddsa_Issue_Verify_HappyPath`              | Document hash, JCS, signature round-trip |
| `Eddsa_TamperedClaim_Rejected`              | Single byte flip in `credentialSubject` breaks proof |
| `SdJwt_SelectiveDisclosure_HidesNonRevealed`| Verifier sees only requested claims, no DOB leakage |
| `SdJwt_AgeOver21_PredicateBoolean`          | Verifier sees `age_equal_or_over_21=true` only |
| `SdJwt_KbJwt_Aud_Mismatch_Rejected`         | Wrong `aud` in KB-JWT fails verification |
| `SdJwt_KbJwt_Nonce_Mismatch_Rejected`       | Wrong `nonce` fails |
| `SdJwt_TamperedDisclosure_Rejected`         | Modified disclosure → digest mismatch |
| `Bbs_DerivedProof_AgeOver27_NoDobLeak`      | Wallet proves `age >= 27` from a DOB it never reveals |
| `Bbs_DerivedProof_Unlinkable`               | Two derived proofs from the same VC are unlinkable |
| `Bbs_TamperedRevealedClaim_Rejected`        | Modifying a revealed statement fails verify |
| `Status_RevokedCredential_Rejected`         | Bitstring status list flips bit → verify fails |
| `Schema_InvalidSubject_Rejected`            | Subject violating JSON Schema fails verify |
| `Vp_MissingChallenge_Rejected`              | VP without `challenge`/`domain` fails |
| `Vp_WrongHolderKey_Rejected`                | VP signed by a different DID fails |

CI MUST run the full suite. A failing test blocks merge.

---

## 11. Out of Scope

* DID methods other than `did:key` (no `did:web`, no `did:ion`).
* Real revocation distribution (the status list is hosted by the same
  backend; that's fine for the demo, but document it).
* OpenID4VCI / OpenID4VP transport. Endpoints are bespoke; the
  on-the-wire format above is what matters.
* Linked Data Proofs older than `eddsa-jcs-2022` / `bbs-2023`.
* AnonCreds, JWT VC (pre-SD), CL signatures.

---

## 12. Definition of Done

A PR is mergeable iff, on a clean build:

1. Every endpoint returns documents that pass an external W3C VCDM 2.0
   conformance check (the canonical reference is the
   [`vc-test-suite`](https://github.com/w3c/vc-test-suite) corpus —
   spot-check at least the issuer and verifier suites).
2. The full §10 test suite is green.
3. `grep -R "TODO\|FIXME\|HACK\|XXX" src/` returns nothing in the
   security-relevant packages (`service/proof`, `service/crypto`,
   `service/canon`).
4. The HTTP responses contain no field that is not either (a) defined by a
   referenced spec, or (b) under a `_walletHints`-style namespace prefixed
   with `_`.
5. The wallet UI never renders an issuer-supplied display string without
   surfacing the underlying DID alongside it.

If any of those are red, the implementation is not done — even if the demo
"works".

