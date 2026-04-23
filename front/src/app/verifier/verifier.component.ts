import { Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { JsonPipe } from '@angular/common';
import { VcApiService } from '../services/vc-api.service';
import { VcStateService } from '../services/vc-state.service';

interface Assertion {
  field: string;
  operator: string;
  value: string;
}

interface VerificationScenario {
  key: string;
  name: string;
  icon: string;
  description: string;
  color: string;
  bgColor: string;
  requiredCredentials: string[];
  assertions: Assertion[];
}

const SCENARIOS: VerificationScenario[] = [
  {
    key: 'age-check',
    name: 'Age Verification (Bar / Club)',
    icon: '🍺',
    description: 'Prove you are 21 or older to enter. The bar sees only the age_equal_or_over_21 boolean — your date of birth, name, personal number, and nationality stay hidden.',
    color: 'text-amber-800', bgColor: 'bg-amber-50',
    requiredCredentials: ['GovernmentIdentityCredential'],
    assertions: [
      { field: 'dateOfBirth', operator: 'age_gte', value: '21' }
    ]
  },
  {
    key: 'senior-check',
    name: 'Senior Discount (85+)',
    icon: '👴',
    description: 'A transport company offers free rides for people 85 or older. Wallet discloses only the age_equal_or_over_85 boolean.',
    color: 'text-amber-800', bgColor: 'bg-amber-50',
    requiredCredentials: ['GovernmentIdentityCredential'],
    assertions: [
      { field: 'dateOfBirth', operator: 'age_gte', value: '85' }
    ]
  },
  {
    key: 'blood-donation',
    name: 'Blood Donation Eligibility',
    icon: '🩸',
    description: 'A blood bank needs to confirm your blood type is NOT B+ (they have excess B+ stock). Uses your medical record credential.',
    color: 'text-red-800', bgColor: 'bg-red-50',
    requiredCredentials: ['MedicalRecordCredential'],
    assertions: [
      { field: 'bloodType', operator: 'neq', value: 'B+' }
    ]
  },
  {
    key: 'job-application',
    name: 'Job Application (Employer)',
    icon: '💼',
    description: 'An employer wants to verify you hold a university degree and are a Swedish national. Combines credentials from two different issuers.',
    color: 'text-blue-800', bgColor: 'bg-blue-50',
    requiredCredentials: ['UniversityDegreeCredential', 'GovernmentIdentityCredential'],
    assertions: [
      { field: 'degree', operator: 'exists', value: '' },
      { field: 'nationality', operator: 'eq', value: 'Swedish' }
    ]
  },
  {
    key: 'caller-verification',
    name: 'Caller Identity (Truecaller)',
    icon: '📞',
    description: 'Truecaller verifies the incoming caller has a telecom-issued phone credential and a government-verified name. This is the future of spam-proof caller ID.',
    color: 'text-purple-800', bgColor: 'bg-purple-50',
    requiredCredentials: ['VerifiedPhoneCredential'],
    assertions: [
      { field: 'phoneNumber', operator: 'exists', value: '' },
      { field: 'subscriberName', operator: 'exists', value: '' }
    ]
  },
  {
    key: 'health-insurance',
    name: 'Health Insurance Check',
    icon: '🏥',
    description: 'An insurance provider checks your height is at least 150cm and weight is under 120kg based on your medical record.',
    color: 'text-teal-800', bgColor: 'bg-teal-50',
    requiredCredentials: ['MedicalRecordCredential'],
    assertions: [
      { field: 'height', operator: 'gte', value: '150' },
      { field: 'weight', operator: 'lt', value: '120' }
    ]
  },
];

@Component({
  selector: 'app-verifier',
  standalone: true,
  imports: [FormsModule, JsonPipe],
  templateUrl: './verifier.component.html'
})
export class VerifierComponent implements OnInit {
  state = inject(VcStateService);
  private api = inject(VcApiService);

  scenarios = SCENARIOS;
  selectedScenario = signal<VerificationScenario | null>(null);
  loading = signal(false);
  report = signal<any>(null);

  ngOnInit() {
    const savedKey = this.state.selectedScenarioKey();
    if (savedKey) {
      const scenario = SCENARIOS.find(s => s.key === savedKey) || null;
      this.selectedScenario.set(scenario);
    }

    const vp = this.state.generatedPresentation();
    const scenario = this.selectedScenario();
    if (vp && scenario) {
      this.verify();
    }
  }

  selectScenario(scenario: VerificationScenario) {
    this.selectedScenario.set(scenario);
    this.state.selectedScenarioKey.set(scenario.key);
    this.report.set(null);
    this.state.lastReport.set(null);
    this.state.generatedPresentation.set(null);
    this.state.currentChallenge.set(null);
  }

  sendProofRequest() {
    const scenario = this.selectedScenario();
    if (!scenario) return;

    this.report.set(null);
    this.state.selectedScenarioKey.set(scenario.key);

    // Mint a fresh verifier challenge per request — AGENT.md §3.3 / §6 step 3.
    this.api.getChallenge().subscribe(ch => {
      this.state.currentChallenge.set(ch);

      const proofRequest = scenario.assertions.map(a => ({
        field: a.field,
        operator: a.operator,
        value: a.value,
        disclose: true,
      }));

      this.state.pendingVerificationRequest.set({
        scenarioName: scenario.name,
        scenarioIcon: scenario.icon,
        assertions: scenario.assertions,
        proofRequest,
      });

      this.state.activePersona.set('HOLDER');
    });
  }

  operatorLabel(op: string): string {
    const labels: Record<string, string> = {
      eq: '=', neq: '≠', gte: '≥', lte: '≤', gt: '>', lt: '<',
      age_gte: '(age) ≥', age_lte: '(age) ≤', exists: 'exists'
    };
    return labels[op] || op;
  }

  verify() {
    const vp = this.state.generatedPresentation();
    const scenario = this.selectedScenario();
    const challenge = this.state.currentChallenge();
    if (!vp || !scenario || !challenge) return;

    this.loading.set(true);
    this.api.verifyPresentation(vp, scenario.assertions, challenge.verifierDid, challenge.nonce).subscribe({
      next: result => {
        this.report.set(result);
        this.state.lastReport.set(result);
        this.loading.set(false);
      },
      error: () => {
        const err = { valid: false, checks: [], errors: ['Server error during verification'], assertionResults: [] };
        this.report.set(err);
        this.state.lastReport.set(err);
        this.loading.set(false);
      }
    });
  }
}

