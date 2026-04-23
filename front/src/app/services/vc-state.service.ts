import { Injectable, signal } from '@angular/core';

export type Persona = 'ISSUER' | 'HOLDER' | 'VERIFIER';

export interface ProofRequestItem {
  field: string;
  operator: string;
  value: string;
  disclose: boolean;
}

export interface PendingVerificationRequest {
  scenarioName: string;
  scenarioIcon: string;
  assertions: { field: string; operator: string; value: string }[];
  proofRequest: ProofRequestItem[];
}

/**
 * Wallet-side credential wrapper, exactly as returned by /api/issuer/issue.
 * AGENT.md §5.2 / §9: store {verifiableCredential, _walletHints} verbatim,
 * never mirror VC fields at the top level.
 */
export interface StoredCredential {
  verifiableCredential: any;
  _walletHints: any;
}

/** What the verifier's /challenge endpoint returns. */
export interface VerifierChallenge {
  verifierDid: string;
  nonce: string;
}

@Injectable({ providedIn: 'root' })
export class VcStateService {
  readonly activePersona = signal<Persona>('HOLDER');
  readonly holderDid = signal<string | null>(null);
  readonly storedCredentials = signal<StoredCredential[]>([]);

  /** The VP last produced by the holder for the current scenario. */
  readonly generatedPresentation = signal<any | null>(null);

  /** Verifier challenge currently being satisfied by the wallet. */
  readonly currentChallenge = signal<VerifierChallenge | null>(null);

  /** Last verifier report shown in the UI. */
  readonly lastReport = signal<any | null>(null);

  /** Verification request from verifier → wallet. */
  readonly pendingVerificationRequest = signal<PendingVerificationRequest | null>(null);

  /** Selected scenario persists across verifier/wallet navigation. */
  readonly selectedScenarioKey = signal<string | null>(null);

  addCredential(stored: StoredCredential) {
    this.storedCredentials.update(creds => [...creds, stored]);
  }
}

