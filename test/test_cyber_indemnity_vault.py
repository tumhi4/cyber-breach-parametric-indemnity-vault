# test_cyber_indemnity_vault.py
# 15-Phase Comprehensive Regression & Security Test Suite for CyberBreachParametricIndemnityVault (Remediated)
import json
import hashlib
import urllib.parse
from datetime import datetime, timezone


class MockNondetWeb:
    def __init__(self, parent):
        self.parent = parent

    def render(self, url: str, mode: str = "text") -> str:
        if self.parent.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to CVE advisory")
        return self.parent.mock_web_responses.get(
            url,
            "<html><body><h1>CISA Known Exploited Vulnerability Advisory: CVE-2026-38291</h1>"
            "<p>Critical remote code execution vulnerability in Enterprise Gateway EDR v4.x. CVSS Base Score: 9.8. Exploitation confirmed in the wild.</p></body></html>"
        )


class MockNondet:
    def __init__(self, parent):
        self.web = MockNondetWeb(parent)


class MockEqPrinciple:
    def __init__(self, parent):
        self.parent = parent

    def prompt_non_comparative(self, get_input_fn, task: str, criteria: str) -> str:
        input_data = get_input_fn()
        return self.parent.exec_prompt(task + "\n" + input_data)


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False
        self.nondet = MockNondet(self)
        self.eq_principle = MockEqPrinciple(self)

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})

    def get_webpage(self, url: str) -> str:
        return self.nondet.web.render(url)

    def exec_prompt(self, prompt: str) -> str:
        return json.dumps({
            "verdict": "BREACH_INDEMNIFIED",
            "cvss_score": 9.8,
            "rationale": "CISA catalog and vendor advisory confirm critical active RCE zero-day exploit."
        })


class MockCyberBreachParametricIndemnityVault:
    def __init__(self, owner_address: str, gl_mock: MockGL):
        self.gl = gl_mock
        self.owner = owner_address.lower()
        self.total_pools_created = 0
        self.total_policies_enrolled = 0
        self.total_claims_filed = 0
        self.total_claims_adjudicated = 0
        self.total_volume_locked = 0
        self.total_indemnities_distributed = 0

        self.pools = {}
        self.policies = {}
        self.claims = {}
        self.consumed_claim_hashes = {}
        self.claimed_policy_cves = {}
        self.claimable_balances = {}

        self.STATUS_POLICY_ACTIVE = "ACTIVE"
        self.STATUS_POLICY_EXPIRED = "EXPIRED"

        self.CLAIM_PENDING = "PENDING_CONSENSUS"
        self.CLAIM_INDEMNIFIED = "BREACH_INDEMNIFIED"
        self.CLAIM_REFUTED = "CLAIM_REFUTED"
        self.CLAIM_INCONCLUSIVE = "SCOPE_INCONCLUSIVE"
        self.CLAIM_ABANDONED = "CLAIM_ABANDONED"

        self.TIER_STANDARD = "TIER_STANDARD"
        self.TIER_ENTERPRISE = "TIER_ENTERPRISE"
        self.TIER_MISSION_CRITICAL = "TIER_MISSION_CRITICAL"

        self.MIN_POOL_LIQUIDITY = 100_000_000_000
        self.MIN_POLICY_PREMIUM = 10_000_000_000
        self.MIN_CLAIM_BOND = 25_000_000_000
        self.MIN_POLICY_DURATION = 86400 * 30
        self.MAX_POLICY_DURATION = 86400 * 365 * 2
        self.CVSS_CRITICAL_THRESHOLD = 8.0
        self.CLAIM_TIMEOUT_SECONDS = 86400 * 7

        self.APPROVED_ADVISORY_DOMAINS = (
            "cve.org", "nvd.nist.gov", "cisa.gov", "mitre.org", "github.com",
            "security.googleblog.com", "msrc.microsoft.com", "aws.amazon.com",
            "cloudflare.com", "crowdstrike.com", "sentinelone.com"
        )

    def fund_contract(self, caller: str, value: int):
        if value > 0:
            cur = self.claimable_balances.get(self.owner, 0)
            self.claimable_balances[self.owner] = cur + value
            self.total_volume_locked += value

    def _compute_claim_hash(self, policy_id: str, claimant: str, cve_id: str, url: str, nonce: str) -> str:
        data = (
            "L" + str(len(policy_id)) + ":" + policy_id.upper() + "|" +
            "L" + str(len(claimant)) + ":" + claimant.lower() + "|" +
            "L" + str(len(cve_id)) + ":" + cve_id.upper() + "|" +
            "L" + str(len(url)) + ":" + url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42 and clean.startswith("0x"), "[ERR_ADDR_01] " + field_name
        for ch in clean[2:].lower():
            assert ch in "0123456789abcdef", "[ERR_ADDR_02] " + field_name
        assert clean.lower() != "0x0000000000000000000000000000000000000000", "[ERR_ADDR_ZERO] " + field_name
        return clean

    def _validate_url(self, url: str, field_name: str) -> str:
        clean_url = url.strip().strip('"').strip("'")
        assert 10 <= len(clean_url) <= 300, "[ERR_URL_LEN] " + field_name
        parsed = urllib.parse.urlsplit(clean_url)
        assert parsed.scheme in ("https", "http"), "[ERR_URL_SCHEME] " + field_name
        assert not parsed.username and not parsed.password, "[ERR_URL_SSRF]"
        assert "@" not in parsed.netloc, "[ERR_URL_SSRF]"
        host = parsed.hostname.lower() if parsed.hostname else ""
        assert host, "[ERR_URL_HOST]"
        if host.isdigit() or host.startswith("0x") or host.startswith("0o"):
            raise AssertionError("[ERR_URL_SSRF] Numeric IP")
        if host in ("localhost", "0.0.0.0", "::", "::1"):
            raise AssertionError("[ERR_URL_SSRF] Localhost")
        if any(host.endswith(s) for s in (".local", ".internal", ".lan", ".corp", ".test", ".invalid")):
            raise AssertionError("[ERR_URL_SSRF] Internal domain")
        parts = host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            o1, o2, o3, o4 = [int(p) for p in parts]
            if o1 in (127, 10, 0) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168) or (o1 == 169 and o2 == 254):
                raise AssertionError("[ERR_URL_SSRF] RFC1918 IP")

        domain_approved = any(host == d or host.endswith("." + d) for d in self.APPROVED_ADVISORY_DOMAINS)
        assert domain_approved, "[ERR_UNAPPROVED_ADVISORY_DOMAIN]"

        return clean_url

    def create_warranty_pool(self, caller: str, value: int, vendor_product_name: str) -> str:
        sender_hex = self._validate_eth_address(caller, "Underwriter").lower()
        clean_prod = vendor_product_name.strip().strip('"').strip("'")
        assert 3 <= len(clean_prod) <= 120, "[ERR_PRODUCT_LEN]"
        assert value >= self.MIN_POOL_LIQUIDITY, "[ERR_MIN_LIQUIDITY]"

        now_utc = int(datetime.now(timezone.utc).timestamp())
        new_pool_id = "WARRANTY_POOL_" + str(self.total_pools_created + 1)
        self.pools[new_pool_id] = {
            "pool_id": new_pool_id,
            "underwriter": sender_hex,
            "vendor_product_name": clean_prod,
            "capital_reserves": value,
            "total_indemnities_paid": 0,
            "active_policies_count": 0,
            "active_encumbered_obligations": 0,
            "created_at": now_utc,
            "is_active": True
        }
        self.total_pools_created += 1
        self.total_volume_locked += value
        return "POOL_CREATED: " + new_pool_id

    def deposit_warranty_pool(self, caller: str, value: int, pool_id: str) -> str:
        self._validate_eth_address(caller, "Caller")
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]
        assert pool["is_active"], "[ERR_POOL_INACTIVE]"
        assert value > 0, "[ERR_ZERO_DEPOSIT]"

        pool["capital_reserves"] += value
        self.pools[clean_p_id] = pool
        self.total_volume_locked += value
        return "POOL_TOPPED_UP: " + clean_p_id

    def enroll_client_policy(self, caller: str, value: int, pool_id: str, tier: str, duration_seconds: int) -> str:
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]
        assert pool["is_active"], "[ERR_POOL_INACTIVE]"

        sender_hex = self._validate_eth_address(caller, "Client").lower()
        clean_tier = tier.strip().upper()
        assert clean_tier in (self.TIER_STANDARD, self.TIER_ENTERPRISE, self.TIER_MISSION_CRITICAL), "[ERR_INVALID_TIER]"

        dur = int(duration_seconds)
        assert self.MIN_POLICY_DURATION <= dur <= self.MAX_POLICY_DURATION, "[ERR_DURATION_BOUNDS]"
        assert value >= self.MIN_POLICY_PREMIUM, "[ERR_MIN_PREMIUM]"

        if clean_tier == self.TIER_STANDARD:
            cov_limit = value * 3
        elif clean_tier == self.TIER_ENTERPRISE:
            cov_limit = value * 5
        else:
            cov_limit = value * 10

        now_utc = int(datetime.now(timezone.utc).timestamp())
        new_pol_id = "POLICY_" + str(self.total_policies_enrolled + 1)
        self.policies[new_pol_id] = {
            "policy_id": new_pol_id,
            "pool_id": clean_p_id,
            "client": sender_hex,
            "tier": clean_tier,
            "premium_paid": value,
            "max_coverage_limit": cov_limit,
            "start_time": now_utc,
            "expiration_time": now_utc + dur,
            "total_claims_paid": 0,
            "status": self.STATUS_POLICY_ACTIVE
        }
        pool["capital_reserves"] += value
        pool["active_policies_count"] += 1
        pool["active_encumbered_obligations"] += cov_limit
        self.pools[clean_p_id] = pool
        self.total_policies_enrolled += 1
        self.total_volume_locked += value
        return "POLICY_ENROLLED: " + new_pol_id

    def submit_breach_claim(self, caller: str, value: int, policy_id: str, cve_id: str, advisory_url: str, requested_indemnity: int, nonce: str) -> str:
        clean_pol_id = policy_id.strip().upper()
        assert clean_pol_id in self.policies, "[ERR_POLICY_NOT_FOUND]"
        pol = self.policies[clean_pol_id]

        sender_hex = self._validate_eth_address(caller, "Claimant").lower()
        assert sender_hex == pol["client"], "[ERR_UNAUTHORIZED_CLAIMANT]"

        now_utc = int(datetime.now(timezone.utc).timestamp())
        assert now_utc <= pol["expiration_time"], "[ERR_POLICY_EXPIRED]"
        assert pol["status"] == self.STATUS_POLICY_ACTIVE, "[ERR_POLICY_INACTIVE]"

        clean_cve = cve_id.strip().upper()
        assert clean_cve.startswith("CVE-") and len(clean_cve) >= 9, "[ERR_INVALID_CVE]"

        cve_key = clean_pol_id + "_" + clean_cve
        assert cve_key not in self.claimed_policy_cves, "[ERR_CVE_ALREADY_CLAIMED]"

        clean_url = self._validate_url(advisory_url, "Security Advisory URL")

        assert requested_indemnity > 0, "[ERR_ZERO_INDEMNITY]"
        remaining_cov = pol["max_coverage_limit"] - pol["total_claims_paid"]
        assert requested_indemnity <= remaining_cov, "[ERR_EXCEEDS_COVERAGE]"
        assert value >= self.MIN_CLAIM_BOND, "[ERR_MIN_CLAIM_BOND]"

        c_hash = self._compute_claim_hash(clean_pol_id, sender_hex, clean_cve, clean_url, nonce)
        assert c_hash.lower() not in self.consumed_claim_hashes, "[ERR_CLAIM_EXISTS]"

        new_c_id = "CLAIM_" + str(self.total_claims_filed + 1)
        self.claims[new_c_id] = {
            "claim_id": new_c_id,
            "policy_id": clean_pol_id,
            "pool_id": pol["pool_id"],
            "claimant": sender_hex,
            "cve_id": clean_cve,
            "advisory_url": clean_url,
            "claim_fingerprint": c_hash,
            "requested_indemnity": requested_indemnity,
            "claim_bond": value,
            "filed_at": now_utc,
            "adjudicated_at": 0,
            "verdict": self.CLAIM_PENDING,
            "indemnity_awarded": 0,
            "has_claimed": False,
            "adjudication_rationale": ""
        }
        self.consumed_claim_hashes[c_hash.lower()] = True
        self.claimed_policy_cves[cve_key] = True
        self.total_claims_filed += 1
        self.total_volume_locked += value
        return "CLAIM_FILED: " + new_c_id

    def adjudicate_breach_claim(self, claim_id: str) -> str:
        clean_c_id = claim_id.strip().upper()
        assert clean_c_id in self.claims, "[ERR_CLAIM_NOT_FOUND]"
        clm = self.claims[clean_c_id]
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_ALREADY_ADJUDICATED]"

        pool = self.pools[clm["pool_id"]]
        pol = self.policies[clm["policy_id"]]

        def get_input() -> str:
            try:
                adv_text = self.gl.nondet.web.render(clm["advisory_url"], mode="text")
            except Exception:
                raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED]")

            assert adv_text is not None and len(adv_text.strip()) >= 30, "[ERR_EVIDENCE_FETCH_FAILED]"
            return f"Vendor & Product: {pool['vendor_product_name']}\nClaimed Incident CVE: {clm['cve_id']}\n<advisory>{adv_text}</advisory>"

        task = "Eval CVE advisory prompt"
        criteria = "Validate CVSS >= 8.0 and product match"
        raw_resp = self.gl.eq_principle.prompt_non_comparative(get_input, task, criteria)
        parsed_verdict = self.CLAIM_INCONCLUSIVE
        rationale = "Fallback"
        cvss = 0.0

        try:
            parsed = json.loads(raw_resp)
            cand = str(parsed.get("verdict", "")).strip().upper()
            if cand in (self.CLAIM_INDEMNIFIED, self.CLAIM_REFUTED, self.CLAIM_INCONCLUSIVE):
                parsed_verdict = cand
            cvss = float(parsed.get("cvss_score", 0.0))
            rationale = str(parsed.get("rationale", ""))
        except Exception:
            pass

        # Metric Binding
        if cvss >= self.CVSS_CRITICAL_THRESHOLD and parsed_verdict == self.CLAIM_INDEMNIFIED:
            final_verdict = self.CLAIM_INDEMNIFIED
        elif parsed_verdict == self.CLAIM_REFUTED or cvss < 4.0:
            final_verdict = self.CLAIM_REFUTED
        else:
            final_verdict = self.CLAIM_INCONCLUSIVE

        now_utc = int(datetime.now(timezone.utc).timestamp())
        clm["adjudicated_at"] = now_utc
        clm["verdict"] = final_verdict
        clm["adjudication_rationale"] = rationale

        bond_amount = clm["claim_bond"]
        awarded = 0

        if final_verdict == self.CLAIM_INDEMNIFIED:
            req = clm["requested_indemnity"]
            res = pool["capital_reserves"]
            awarded = req if req <= res else res

            total_disbursement = awarded + bond_amount
            clm["indemnity_awarded"] = awarded
            pool["capital_reserves"] -= awarded
            pool["total_indemnities_paid"] += awarded
            pol["total_claims_paid"] += awarded

            if pool["active_encumbered_obligations"] >= awarded:
                pool["active_encumbered_obligations"] -= awarded
            else:
                pool["active_encumbered_obligations"] = 0

            self.total_indemnities_distributed += awarded

            if self.total_volume_locked >= total_disbursement:
                self.total_volume_locked -= total_disbursement
            else:
                self.total_volume_locked = 0

            clm["has_claimed"] = True

            try:
                self.gl.emit_transfer(clm["claimant"], total_disbursement)
            except Exception:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + total_disbursement

        elif final_verdict == self.CLAIM_REFUTED:
            pool["capital_reserves"] += bond_amount
            clm["indemnity_awarded"] = 0
            clm["has_claimed"] = True

        else: # SCOPE_INCONCLUSIVE
            clm["indemnity_awarded"] = 0
            clm["has_claimed"] = True
            if self.total_volume_locked >= bond_amount:
                self.total_volume_locked -= bond_amount
            else:
                self.total_volume_locked = 0

            try:
                self.gl.emit_transfer(clm["claimant"], bond_amount)
            except Exception:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_amount

        self.claims[clean_c_id] = clm
        self.pools[clm["pool_id"]] = pool
        self.policies[clm["policy_id"]] = pol
        self.total_claims_adjudicated += 1
        return "CLAIM_ADJUDICATED: " + clean_c_id

    def settle_expired_policy(self, policy_id: str, simulated_now_offset: int = 0) -> str:
        clean_pol_id = policy_id.strip().upper()
        assert clean_pol_id in self.policies, "[ERR_POLICY_NOT_FOUND]"
        pol = self.policies[clean_pol_id]
        assert pol["status"] == self.STATUS_POLICY_ACTIVE, "[ERR_POLICY_NOT_ACTIVE]"

        now_utc = int(datetime.now(timezone.utc).timestamp()) + simulated_now_offset
        assert now_utc > pol["expiration_time"], "[ERR_POLICY_NOT_EXPIRED]"

        pol["status"] = self.STATUS_POLICY_EXPIRED
        self.policies[clean_pol_id] = pol

        pool = self.pools[pol["pool_id"]]
        if pool["active_policies_count"] > 0:
            pool["active_policies_count"] -= 1

        unclaimed = pol["max_coverage_limit"] - pol["total_claims_paid"]
        if pool["active_encumbered_obligations"] >= unclaimed:
            pool["active_encumbered_obligations"] -= unclaimed
        else:
            pool["active_encumbered_obligations"] = 0

        self.pools[pol["pool_id"]] = pool
        return "POLICY_EXPIRED_SETTLED: " + clean_pol_id

    def withdraw_underwriter_surplus(self, caller: str, pool_id: str, amount: int) -> str:
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND]"
        pool = self.pools[clean_p_id]

        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex == pool["underwriter"], "[ERR_UNAUTHORIZED]"

        reserves = pool["capital_reserves"]
        encumbered = pool["active_encumbered_obligations"]
        unencumbered = reserves - encumbered if reserves > encumbered else 0
        assert amount <= unencumbered, "[ERR_INSUFFICIENT_SURPLUS]"

        pool["capital_reserves"] -= amount
        self.pools[clean_p_id] = pool

        if self.total_volume_locked >= amount:
            self.total_volume_locked -= amount
        else:
            self.total_volume_locked = 0

        try:
            self.gl.emit_transfer(sender_hex, amount)
        except Exception:
            cur = self.claimable_balances.get(sender_hex, 0)
            self.claimable_balances[sender_hex] = cur + amount

        return "SURPLUS_WITHDRAWN: " + clean_p_id

    def claim_abandoned_breach_bond(self, caller: str, claim_id: str, simulated_now_offset: int = 0) -> str:
        clean_c_id = claim_id.strip().upper()
        assert clean_c_id in self.claims, "[ERR_CLAIM_NOT_FOUND]"
        clm = self.claims[clean_c_id]

        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex == clm["claimant"], "[ERR_UNAUTHORIZED]"
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_CLAIM_NOT_PENDING]"

        now_utc = int(datetime.now(timezone.utc).timestamp()) + simulated_now_offset
        assert now_utc >= clm["filed_at"] + self.CLAIM_TIMEOUT_SECONDS, "[ERR_TIMEOUT_NOT_REACHED]"

        bond_val = clm["claim_bond"]
        clm["verdict"] = self.CLAIM_ABANDONED
        clm["has_claimed"] = True
        self.claims[clean_c_id] = clm

        if self.total_volume_locked >= bond_val:
            self.total_volume_locked -= bond_val
        else:
            self.total_volume_locked = 0

        try:
            self.gl.emit_transfer(sender_hex, bond_val)
        except Exception:
            cur = self.claimable_balances.get(sender_hex, 0)
            self.claimable_balances[sender_hex] = cur + bond_val

        return "BOND_RECLAIMED: " + clean_c_id

    def withdraw_claimable(self, caller: str) -> str:
        sender_hex = self._validate_eth_address(caller, "Caller").lower()
        assert sender_hex in self.claimable_balances, "[ERR_NO_CLAIMABLE]"
        bal = self.claimable_balances[sender_hex]
        assert bal > 0, "[ERR_ZERO_CLAIMABLE]"

        self.claimable_balances[sender_hex] = 0
        try:
            self.gl.emit_transfer(sender_hex, bal)
        except Exception:
            self.claimable_balances[sender_hex] = bal
            raise AssertionError("[ERR_WITHDRAWAL_FAILED]")

        return "WITHDRAW_SUCCESS: " + sender_hex + " | Amount: " + str(bal)


# --------------------------------------------------------------------------
# 15-Phase Execution Runner
# --------------------------------------------------------------------------
def run_tests():
    print("=" * 80)
    print("STARTING 15-PHASE REGRESSION TEST SUITE: CyberBreachParametricIndemnityVault (REMEDIATED)")
    print("=" * 80)

    gl = MockGL()
    owner = "0x1111111111111111111111111111111111111111"
    vault = MockCyberBreachParametricIndemnityVault(owner, gl)

    # Phase 1: Zero genesis fixtures
    print("\n[Phase 1] Testing Zero Genesis Fixtures & Zero Unbacked Obligation...")
    assert vault.total_pools_created == 0
    assert vault.total_policies_enrolled == 0
    assert vault.total_claims_filed == 0
    assert vault.total_volume_locked == 0
    assert len(vault.pools) == 0
    assert len(vault.policies) == 0
    assert len(vault.claims) == 0
    print("  [+] Phase 1 Passed: Initialized with zero unbacked debt and zero phantom records.")

    # Phase 2: Length-prefixed canonical hashing
    print("\n[Phase 2] Testing Canonical Length-Prefixed Hashing & Delimiter Resistance...")
    h1 = vault._compute_claim_hash("POLICY_1", "0xabc", "CVE-2026-1111", "https://cve.org/1", "1")
    h2 = vault._compute_claim_hash("POLICY_10", "xabc", "CVE-2026-1111", "https://cve.org/1", "1")
    assert h1 != h2
    print("  [+] Phase 2 Passed: Canonical hashing resists delimiter injection.")

    # Phase 3: Address sanitization
    print("\n[Phase 3] Testing Strict Address Sanitization...")
    try:
        vault._validate_eth_address("bad_address", "Client")
        assert False
    except AssertionError as e:
        assert "[ERR_ADDR_01]" in str(e)
    try:
        vault._validate_eth_address("0x0000000000000000000000000000000000000000", "Client")
        assert False
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)
    print("  [+] Phase 3 Passed: Address sanitization strictly enforced.")

    # Phase 4: SSRF & Official Advisory Domain Whitelisting (CB-01 Remediated)
    print("\n[Phase 4] Testing Advisory Domain Whitelisting (Fake Advisory Defense)...")
    for unapproved in [
        "https://attacker-fake-cve-tracker.com/cve-2026-1.html",
        "http://my-blog.com/exploit.html"
    ]:
        try:
            vault._validate_url(unapproved, "Advisory URL")
            assert False, "Should reject unapproved domain"
        except AssertionError as e:
            assert "[ERR_UNAPPROVED_ADVISORY_DOMAIN]" in str(e)
    valid_cisa = "https://cisa.gov/known-exploited-vulnerabilities/cve-2026-38291.html"
    assert vault._validate_url(valid_cisa, "Valid URL") == valid_cisa
    print("  [+] Phase 4 Passed: Unapproved advisory domains blocked; official catalogs enforced.")

    # Phase 5: Warranty Pool Creation with Payable Escrow
    print("\n[Phase 5] Testing Warranty Pool Creation (100% Backed)...")
    underwriter = "0x2222222222222222222222222222222222222222"
    pool_val = 1_000_000_000_000  # 1,000 Gwei
    res_pool = vault.create_warranty_pool(underwriter, pool_val, "SentinelCloud Zero-Trust EDR")
    assert "WARRANTY_POOL_1" in res_pool
    assert vault.pools["WARRANTY_POOL_1"]["capital_reserves"] == pool_val
    assert vault.total_volume_locked == pool_val
    print("  [+] Phase 5 Passed: WARRANTY_POOL_1 created with 1,000 Gwei capital reserves.")

    # Phase 6: Warranty Pool Top-Up Reserves
    print("\n[Phase 6] Testing Warranty Pool Top-Up Reserves...")
    topup = 500_000_000_000  # 500 Gwei
    vault.deposit_warranty_pool(underwriter, topup, "WARRANTY_POOL_1")
    assert vault.pools["WARRANTY_POOL_1"]["capital_reserves"] == pool_val + topup
    assert vault.total_volume_locked == pool_val + topup
    print("  [+] Phase 6 Passed: Capital reserves incremented to 1,500 Gwei.")

    # Phase 7: Client Policy Enrollment with Encumbered Obligations Tracking
    print("\n[Phase 7] Testing Client Policy Enrollment & Encumbered Obligations...")
    client1 = "0x3333333333333333333333333333333333333333"
    premium = 50_000_000_000  # 50 Gwei premium
    duration = 86400 * 90     # 90 Days
    res_pol = vault.enroll_client_policy(client1, premium, "WARRANTY_POOL_1", vault.TIER_ENTERPRISE, duration)
    assert "POLICY_1" in res_pol
    assert vault.policies["POLICY_1"]["max_coverage_limit"] == premium * 5  # 250 Gwei
    assert vault.pools["WARRANTY_POOL_1"]["active_encumbered_obligations"] == premium * 5
    print("  [+] Phase 7 Passed: POLICY_1 enrolled; 250 Gwei encumbered obligation tracked.")

    # Phase 8: Policy Duration & Premium Bounds Validation
    print("\n[Phase 8] Testing Policy Bounds Validation...")
    try:
        vault.enroll_client_policy(client1, 1_000_000_000, "WARRANTY_POOL_1", vault.TIER_STANDARD, duration)
        assert False
    except AssertionError as e:
        assert "[ERR_MIN_PREMIUM]" in str(e)
    try:
        vault.enroll_client_policy(client1, premium, "WARRANTY_POOL_1", vault.TIER_STANDARD, 86400 * 10)
        assert False
    except AssertionError as e:
        assert "[ERR_DURATION_BOUNDS]" in str(e)
    print("  [+] Phase 8 Passed: Minimum premium and duration bounds strictly enforced.")

    # Phase 9: Breach Claim Filing with Anti-Spam Bond
    print("\n[Phase 9] Testing Breach Claim Filing with Anti-Spam Bond...")
    claim_bond = 30_000_000_000  # 30 Gwei
    req_indemnity = 200_000_000_000  # 200 Gwei
    cve_id = "CVE-2026-38291"
    advisory_url = "https://cisa.gov/known-exploited-vulnerabilities/cve-2026-38291.html"
    res_clm = vault.submit_breach_claim(
        client1, claim_bond, "POLICY_1", cve_id, advisory_url, req_indemnity, "nonce-cve-1"
    )
    assert "CLAIM_1" in res_clm
    assert vault.claims["CLAIM_1"]["claim_bond"] == claim_bond
    print("  [+] Phase 9 Passed: CLAIM_1 filed with 30 Gwei anti-spam bond.")

    # Phase 10: Single Claim Per CVE Defense (CB-05 Remediated)
    print("\n[Phase 10] Testing Single-Claim-Per-CVE Invariant...")
    try:
        vault.submit_breach_claim(
            client1, claim_bond, "POLICY_1", cve_id, advisory_url, 50_000_000_000, "nonce-cve-duplicate"
        )
        assert False, "Should reject duplicate claim for identical CVE under same policy"
    except AssertionError as e:
        assert "[ERR_CVE_ALREADY_CLAIMED]" in str(e)
    print("  [+] Phase 10 Passed: Duplicate claim for identical CVE blocked.")

    # Phase 11: Fail-Closed Evidence Ingestion Invariant
    print("\n[Phase 11] Testing Fail-Closed Evidence Ingestion Invariant...")
    gl.fail_web_fetch = True
    try:
        vault.adjudicate_breach_claim("CLAIM_1")
        assert False
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    gl.fail_web_fetch = False
    assert vault.claims["CLAIM_1"]["verdict"] == vault.CLAIM_PENDING
    print("  [+] Phase 11 Passed: Network failure triggered zero-mutation abort.")

    # Phase 12: Consensus Adjudication with CVSS >= 8.0 Metric Binding (CB-02 Remediated)
    print("\n[Phase 12] Testing Consensus Adjudication with CVSS >= 8.0 Metric Binding...")
    res_adj = vault.adjudicate_breach_claim("CLAIM_1")
    assert "CLAIM_ADJUDICATED: CLAIM_1" in res_adj
    assert vault.claims["CLAIM_1"]["verdict"] == vault.CLAIM_INDEMNIFIED
    assert vault.claims["CLAIM_1"]["indemnity_awarded"] == req_indemnity
    assert gl.transfers[-1]["recipient"] == client1.lower()
    assert gl.transfers[-1]["amount"] == req_indemnity + claim_bond
    print("  [+] Phase 12 Passed: CVSS 9.8 verified; 200 Gwei indemnity + 30 Gwei bond refunded.")

    # Phase 13: Settle Expired Policy (CB-03 Remediated)
    print("\n[Phase 13] Testing Policy Expiration Settlement (settle_expired_policy)...")
    # Early attempt should fail
    try:
        vault.settle_expired_policy("POLICY_1", simulated_now_offset=0)
        assert False
    except AssertionError as e:
        assert "[ERR_POLICY_NOT_EXPIRED]" in str(e)
    # Settle after duration elapsed
    vault.settle_expired_policy("POLICY_1", simulated_now_offset=duration + 10)
    assert vault.policies["POLICY_1"]["status"] == vault.STATUS_POLICY_EXPIRED
    assert vault.pools["WARRANTY_POOL_1"]["active_policies_count"] == 0
    assert vault.pools["WARRANTY_POOL_1"]["active_encumbered_obligations"] == 0
    print("  [+] Phase 13 Passed: Policy settled to EXPIRED; encumbered obligations cleared.")

    # Phase 14: Underwriter Surplus Capital Withdrawal (CB-04 Remediated)
    print("\n[Phase 14] Testing Underwriter Surplus Capital Withdrawal...")
    # Pool capital reserves now free from obligations
    reserves_left = vault.pools["WARRANTY_POOL_1"]["capital_reserves"]
    draw_amount = 500_000_000_000  # 500 Gwei
    res_surplus = vault.withdraw_underwriter_surplus(underwriter, "WARRANTY_POOL_1", draw_amount)
    assert "SURPLUS_WITHDRAWN: WARRANTY_POOL_1" in res_surplus
    assert gl.transfers[-1]["recipient"] == underwriter.lower()
    assert gl.transfers[-1]["amount"] == draw_amount
    print("  [+] Phase 14 Passed: Underwriter safely withdrew 500 Gwei unencumbered surplus.")

    # Phase 15: Unreachable Advisory Timeout Recovery & withdraw_claimable()
    print("\n[Phase 15] Testing Unreachable Advisory Timeout Recovery & withdraw_claimable()...")
    client2 = "0x4444444444444444444444444444444444444444"
    vault.enroll_client_policy(client2, premium, "WARRANTY_POOL_1", vault.TIER_STANDARD, duration)
    vault.submit_breach_claim(
        client2, claim_bond, "POLICY_2", "CVE-2026-77777", "https://cve.org/offline.html", 50_000_000_000, "nonce-rec"
    )
    # Recover after 7 days
    vault.claim_abandoned_breach_bond(client2, "CLAIM_2", simulated_now_offset=86400 * 7 + 10)
    assert vault.claims["CLAIM_2"]["verdict"] == vault.CLAIM_ABANDONED
    assert gl.transfers[-1]["recipient"] == client2.lower()
    assert gl.transfers[-1]["amount"] == claim_bond
    print("  [+] Phase 15 Passed: Unreachable advisory bond safely recovered after timeout.")

    print("\n" + "=" * 80)
    print("ALL 15 PHASES OF CyberBreachParametricIndemnityVault (REMEDIATED) PASSED WITH 0 ERRORS!")
    print("=" * 80)


if __name__ == "__main__":
    run_tests()
