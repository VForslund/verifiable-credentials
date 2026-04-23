package com.truecaller.backend.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.truecaller.backend.dto.IssueRequest;
import com.truecaller.backend.dto.PresentRequest;
import com.truecaller.backend.dto.VerifyRequest;
import com.truecaller.backend.service.HolderService;
import com.truecaller.backend.service.IssuerService;
import com.truecaller.backend.service.VerifierService;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import com.truecaller.backend.service.schema.CredentialSchemaService;
import com.truecaller.backend.service.status.BitstringStatusListService;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/** VCDM 2.0 demo endpoints — see AGENT.md §8.2. */
@RestController
@RequestMapping("/api")
public class VcController {

    private static final SecureRandom RNG = new SecureRandom();

    private final Ed25519KeyService ed25519;
    private final IssuerService issuerService;
    private final HolderService holderService;
    private final VerifierService verifierService;
    private final BitstringStatusListService statusLists;
    private final CredentialSchemaService schemas;

    /** A persistent verifier DID for the demo, lazily generated once at startup. */
    private volatile String verifierDid;

    public VcController(Ed25519KeyService ed25519, IssuerService issuerService,
                        HolderService holderService, VerifierService verifierService,
                        BitstringStatusListService statusLists, CredentialSchemaService schemas) {
        this.ed25519 = ed25519;
        this.issuerService = issuerService;
        this.holderService = holderService;
        this.verifierService = verifierService;
        this.statusLists = statusLists;
        this.schemas = schemas;
    }

    @PostMapping("/keys/generate")
    public Map<String, String> generateKeys() {
        var k = ed25519.generateKeyPair();
        return Map.of("did", k.did(), "publicKey", k.publicKeyBase64());
    }

    @GetMapping("/issuers")
    public Map<String, Object> getAvailableIssuers() {
        return issuerService.getAvailableIssuers();
    }

    @PostMapping("/issuer/issue")
    public Map<String, Object> issueCredential(@RequestBody IssueRequest request) {
        return issuerService.issueCredential(
                request.issuerType(), request.holderDid(),
                request.claims(), request.securingMechanismOrDefault());
    }

    @PostMapping("/holder/present")
    public Map<String, Object> createPresentation(@RequestBody PresentRequest request) {
        return holderService.createPresentation(
                request.holderDid(), request.verifiableCredentials(), request.proofRequest(),
                request.verifierDid(), request.nonce());
    }

    /** Per AGENT.md §3.3 — fresh nonce + verifier DID for replay protection. */
    @GetMapping("/verifier/challenge")
    public synchronized Map<String, String> challenge() {
        if (verifierDid == null) verifierDid = ed25519.generateKeyPair().did();
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Map.of("verifierDid", verifierDid,
                "nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(b));
    }

    @PostMapping("/verifier/verify")
    public Map<String, Object> verify(@RequestBody VerifyRequest request) {
        return verifierService.verify(
                request.presentation(), request.assertions(),
                request.expectedAud(), request.expectedNonce());
    }

    /** Bitstring status list VC (W3C-STATUS-LIST), signed eddsa-jcs-2022. */
    @GetMapping("/status/{listId}")
    public Map<String, Object> statusList(@PathVariable String listId) {
        return statusLists.buildStatusListCredential(listId, "https://truecaller.demo");
    }

    /** JSON Schema 2020-12 documents — referenced by {@code credentialSchema.id}. */
    @GetMapping(value = "/schemas/{name}.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode schema(@PathVariable String name) {
        return schemas.loadSchemaJson(name);
    }

    /** JSON-LD context documents — referenced from a credential's {@code @context}. */
    @GetMapping(value = "/contexts/{name}", produces = "application/ld+json")
    public ResponseEntity<byte[]> context(@PathVariable String name) throws Exception {
        try (InputStream in = new ClassPathResource("contexts/" + name + ".jsonld").getInputStream()) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/ld+json")
                    .body(in.readAllBytes());
        }
    }
}

