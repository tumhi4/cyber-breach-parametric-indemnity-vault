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
| **Contract Address** | [`0xB6eB6BD14d9519071A642dd7E615947F0D71fa9B`](https://explorer-studio.genlayer.com/address/0xB6eB6BD14d9519071A642dd7E615947F0D71fa9B) |
| **Deployment Transaction** | `0xc79aae590aa7e0cdbc73126029e6b6be24bf9f7ed68e594e96df131531ae47d9` |
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
    Note over Vault: Anti-spam claim bond escrowed (>= 25 Gwei). Fingerprint burned.
    
    Vault->>Consensus: adjudicate_breach_claim(claim_id)
    Consensus->>Consensus: Fetch advisory (Fail-Closed gl.get_webpage)
    Consensus->>Consensus: Multi-Validator CVE Severity & Impact Verification (CVSS >= 8.0)
    
    alt Incident Confirmed (BREACH_INDEMNIFIED)
        Consensus-->>Vault: BREACH_INDEMNIFIED verdict
        Vault->>Client: emit_transfer(indemnity_payout + 100% claim bond refund)
    else Incident Refuted (CLAIM_REFUTED)
        Consensus-->>Vault: CLAIM_REFUTED verdict
        Vault->>Vault: Slash claim bond to underwriter reserves
    else Scope Disputed (SCOPE_INCONCLUSIVE)
        Consensus-->>Vault: SCOPE_INCONCLUSIVE verdict
        Vault->>Client: emit_transfer(100% claim bond refund, 0 indemnity)
    end

    opt Native Transfer Failure Recovery
        Client->>Vault: withdraw_claimable()
        Note over Vault: Optimistically zeroes balance; restores if transfer fails
    end
```

---

## 3. Core Technical Invariants & Steward Compliance

1. **100% Backed Payable Escrow**: Underwriter reserves, policy premiums, and claim bonds require native GEN strictly via `@gl.public.write.payable` reading `gl.message.value`.
2. **Zero Genesis Debt**: Initialized without synthetic seed claims or unbacked liabilities in `__init__`.
3. **Delimiter-Resistant Hashing**: Claim fingerprints encode canonical length prefixes (`L<len>:<val>|...`) preventing preimage collision attacks.
4. **Strict Address & SSRF Defense**: Comprehensive URL verification rejecting loopback, numeric IPs, RFC1918 subnets, and userinfo delimiters.
5. **Fail-Closed Evidence Ingestion**: If consensus web ingestion fails or returns empty payloads, reverts with `[ERR_EVIDENCE_FETCH_FAILED]` without state mutation.
6. **Recoverable Claimable Balances**: Failed EVM transfers credit to `claimable_balances`, safely recoverable via `withdraw_claimable()`.

---

## 4. Verification & Testing

The contract has been audited through a 15-phase Python regression test suite covering all operational edge cases:

```bash
python test/test_cyber_indemnity_vault.py
```

```
================================================================================
ALL 15 PHASES OF CyberBreachParametricIndemnityVault PASSED WITH 0 ERRORS!
================================================================================
```

---

## 5. License

MIT License. Designed and deployed for GenLayer by [tumhi4](https://github.com/tumhi4).
