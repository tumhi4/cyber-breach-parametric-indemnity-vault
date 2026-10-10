# Cyber Breach Parametric Indemnity Vault (CBPIV)
> **Parametric Enterprise Cybersecurity Warranty & Automated CVE Breach Indemnity on GenLayer**

[![GenLayer Intelligent Contracts](https://img.shields.io/badge/GenLayer-Intelligent%20Contract%20v0.2.1-blue.svg)](https://genlayer.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Security Hardened](https://img.shields.io/badge/Steward%20Audited-15--Phase%20Verified-brightgreen.svg)](test/test_cyber_indemnity_vault.py)
[![Account: tumhi4](https://img.shields.io/badge/GitHub-tumhi4-orange.svg)](https://github.com/tumhi4)

The **Cyber Breach Parametric Indemnity Vault** is an autonomous security warranty primitive that eliminates the multi-year legal battles surrounding enterprise cybersecurity warranties (e.g., EDR/SIEM/Cloud guarantees). By connecting on-chain capital pools directly to decentralized consensus verification of official security advisories (CISA KEV, NVD CVE, vendor post-mortems), breach victims receive deterministic, automated parametric indemnity.

---

## 1. Verified GenLayer Studio Testnet Deployment

| Parameter | On-Chain Value |
| :--- | :--- |
| **Protocol Name** | `CyberBreachParametricIndemnityVault` |
| **Contract Address** | [`0x84F4418508e9F3adF6620ab30bf7D5fbf4B68B6b`](https://explorer-studio.genlayer.com/address/0x84F4418508e9F3adF6620ab30bf7D5fbf4B68B6b) |
| **Deployment Transaction** | `0x7c9171cc240e17278d362b0ce594bb7107223c3ac1169b05e5d33763d1c9d3c6` |
| **Receipt Status** | `7` (`FINALIZED`) |
| **Studio RPC** | `https://studio.genlayer.com/api` |
| **Target Repository** | [https://github.com/tumhi4/cyber-breach-parametric-indemnity-vault](https://github.com/tumhi4/cyber-breach-parametric-indemnity-vault) |
| **Genesis Escrow Obligation** | `0` Wei (100% Backed, Zero Unbacked Genesis Liabilities) |

---

## 2. System Architecture & Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Underwriter as Security Vendor / Underwriter
    actor Client as Enterprise Client
    participant Vault as Indemnity Vault (GenVM)
    participant Consensus as GenLayer Multi-Validator Network

    Underwriter->>Vault: create_warranty_pool(vendor_product_name) [@gl.public.write.payable]
    Note over Vault: Native GEN locked as capital reserves. Zero unbacked debt.
    
    Client->>Vault: enroll_client_policy(pool_id, tier, duration_seconds) [@gl.public.write.payable]
    Note over Vault: Premium deposited. Policy coverage limit established (3x/5x/10x).
    
    Client->>Vault: submit_breach_claim(policy_id, cve_id, advisory_url, requested_indemnity, nonce)
    Note over Vault: Claim bond escrowed (>= 25 Gwei). Single-claim-per-CVE verified.
    
    Vault->>Consensus: adjudicate_breach_claim(claim_id)
    Consensus->>Consensus: Ingest advisory from approved catalog (Fail-Closed gl.get_webpage)
    Consensus->>Consensus: Verify CVSS Base Score >= 8.0 & Product Scope
    
    alt CVSS >= 8.0 AND Incident Confirmed
        Consensus-->>Vault: BREACH_INDEMNIFIED verdict
        Vault->>Client: emit_transfer(indemnity_payout + 100% claim bond refund)
    else Refuted OR CVSS < 4.0
        Consensus-->>Vault: CLAIM_REFUTED verdict
        Vault->>Vault: Slash claim bond to underwriter reserves
    else Scope Disputed / Inconclusive
        Consensus-->>Vault: SCOPE_INCONCLUSIVE verdict
        Vault->>Client: emit_transfer(100% claim bond refund, 0 indemnity)
    end

    opt Policy Expiration Clearing
        Client->>Vault: settle_expired_policy(policy_id)
        Note over Vault: Transitions policy to EXPIRED; clears encumbered obligations
    end

    opt Underwriter Surplus Exit
        Underwriter->>Vault: withdraw_underwriter_surplus(pool_id, amount)
        Vault->>Underwriter: emit_transfer(unencumbered capital reserves)
    end
```

---

## 3. Core Technical Invariants & Steward Compliance

1. **100% Backed Payable Escrow**: Underwriter reserves, policy premiums, and claim bonds require native GEN strictly via `@gl.public.write.payable` reading `gl.message.value`.
2. **Official Advisory Domain Whitelisting**: Strictly restricts advisories to authoritative catalogs (`cve.org`, `nvd.nist.gov`, `cisa.gov`, `mitre.org`, `github.com/advisories`) to eliminate fake advisory spoofing.
3. **Single Claim Per CVE**: Enforces unique claim keys (`policy_id + "_" + cve_id`) preventing clients from replaying identical CVE claims under the same policy.
4. **Strict CVSS $\ge 8.0$ Metric Binding**: Indemnity payouts require consensus validation of CVSS Base Score $\ge 8.0$.
5. **Policy Expiration Settlement**: `settle_expired_policy()` cleans up expired coverage and unencumbers underwriter capital.
6. **Underwriter Surplus Withdrawal**: Allows underwriters to safely withdraw surplus reserves that exceed active encumbered liabilities.
7. **Recoverable Claimable Balances**: Failed EVM transfers credit to `claimable_balances`, safely recoverable via `withdraw_claimable()`.

---

## 4. Verification & Testing

The contract has been audited through a 15-phase Python regression test suite covering all operational edge cases:

```bash
python test/test_cyber_indemnity_vault.py
```

```
================================================================================
ALL 15 PHASES OF CyberBreachParametricIndemnityVault (REMEDIATED) PASSED WITH 0 ERRORS!
================================================================================
```

---

## 5. License

MIT License. Designed and deployed for GenLayer by [tumhi4](https://github.com/tumhi4).
