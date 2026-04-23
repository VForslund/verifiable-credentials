import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { VerifierChallenge } from './vc-state.service';

/**
 * Typed wrappers for the AGENT.md §8.2 endpoints.
 *
 * <p>The `securingMechanism` parameter on issuance defaults to
 * {@code "sd-jwt-vc"} here even though AGENT.md §2.3 names {@code "bbs-2023"}
 * as the abstract default — the backend honours that default with HTTP 501
 * because no conformant Java BBS+ suite is available (see
 * {@code DataIntegrityBbs2023}). The wallet picks `sd-jwt-vc` so the demo
 * actually issues something; this is documented in AGENT.md §2.1 / §11.
 */
@Injectable({ providedIn: 'root' })
export class VcApiService {
  private http = inject(HttpClient);
  private base = '/api';

  generateKeys(): Observable<{ did: string; publicKey: string }> {
    return this.http.post<{ did: string; publicKey: string }>(`${this.base}/keys/generate`, {});
  }

  getIssuers(): Observable<Record<string, any>> {
    return this.http.get<Record<string, any>>(`${this.base}/issuers`);
  }

  issueCredential(
    issuerType: string,
    holderDid: string,
    claims: Record<string, string>,
    securingMechanism: 'sd-jwt-vc' | 'eddsa-jcs-2022' | 'bbs-2023' = 'sd-jwt-vc'
  ): Observable<{ verifiableCredential: any; _walletHints: any }> {
    return this.http.post<{ verifiableCredential: any; _walletHints: any }>(
      `${this.base}/issuer/issue`,
      { issuerType, holderDid, claims, securingMechanism });
  }

  /** Returns {verifiableCredential: <VP>, _walletHints: <preview>} per AGENT.md §5.2. */
  createPresentation(
    holderDid: string,
    verifiableCredentials: any[],
    proofRequest: { field: string; operator: string; value: string; disclose: boolean }[],
    verifierDid: string,
    nonce: string
  ): Observable<{ verifiableCredential: any; _walletHints: any }> {
    return this.http.post<{ verifiableCredential: any; _walletHints: any }>(
      `${this.base}/holder/present`,
      { holderDid, verifiableCredentials, proofRequest, verifierDid, nonce });
  }

  /** AGENT.md §3.3 — the verifier emits a fresh challenge per request. */
  getChallenge(): Observable<VerifierChallenge> {
    return this.http.get<VerifierChallenge>(`${this.base}/verifier/challenge`);
  }

  verifyPresentation(
    presentation: any,
    assertions: { field: string; operator: string; value: string }[] = [],
    expectedAud: string,
    expectedNonce: string
  ): Observable<any> {
    return this.http.post<any>(
      `${this.base}/verifier/verify`,
      { presentation, assertions, expectedAud, expectedNonce });
  }
}

