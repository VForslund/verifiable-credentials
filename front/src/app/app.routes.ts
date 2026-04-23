import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'wallet', pathMatch: 'full' },
  { path: 'issuer', loadComponent: () => import('./issuer/issuer.component').then(m => m.IssuerComponent) },
  { path: 'wallet', loadComponent: () => import('./wallet/wallet.component').then(m => m.WalletComponent) },
  { path: 'verifier', loadComponent: () => import('./verifier/verifier.component').then(m => m.VerifierComponent) },
];
