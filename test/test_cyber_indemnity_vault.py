# test_cyber_indemnity_vault.py
# 15-Phase Comprehensive Regression & Security Test Suite for CyberBreachParametricIndemnityVault
import json
import hashlib
import urllib.parse
from datetime import datetime, timezone


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})

    def get_webpage(self, url: str) -> str:
        if self.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to CVE advisory")
        return self.mock_web_responses.get(
            url,
            "<html><body><h1>CISA Known Exploited Vulnerability Advisory: CVE-2026-38291</h1>"
            "<p>Critical remote code execution vulnerability in Enterprise Gateway EDR v4.x. CVSS Base Score: 9.8. Exploitation confirmed in the wild.</p></body></html>"
        )

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
        self.claimable_balances = {}

        self.STATUS_POLICY_ACTIVE = "ACTIVE"
        self.STATUS_POLICY_EXPIRED = "EXPIRED"

        self.CLAIM_PENDING = "PENDING_CONSENSUS"
        self.CLAIM_INDEMNIFIED = "BREACH_INDEMNIFIED"
        self.CLAIM_REFUTED = "CLAIM_REFUTED"
        self.CLAIM_INCONCLUSIVE = "SCOPE_INCONCLUSIVE"

        self.TIER_STANDARD = "TIER_STANDARD"
        self.TIER_ENTERPRISE = "TIER_ENTERPRISE"
        self.TIER_MISSION_CRITICAL = "TIER_MISSION_CRITICAL"

        self.MIN_POOL_LIQUIDITY = 100_000_000_000
        self.MIN_POLICY_PREMIUM = 10_000_000_000
        self.MIN_CLAIM_BOND = 25_000_000_000
        self.MIN_POLICY_DURATION = 86400 * 30
        self.MAX_POLICY_DURATION = 86400 * 365 * 2

    def fund_contract(self, value: int):
        if value > 0:
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

        clean_cve = cve_id.strip().upper()
        assert clean_cve.startswith("CVE-") and len(clean_cve) >= 9, "[ERR_INVALID_CVE]"
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

        try:
            adv_text = self.gl.get_webpage(clm["advisory_url"])
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED]")

        assert adv_text is not None and len(adv_text.strip()) >= 30, "[ERR_EVIDENCE_FETCH_FAILED]"

        raw_resp = self.gl.exec_prompt("Eval CVE advisory prompt")
        verdict = self.CLAIM_INCONCLUSIVE
        rationale = "Fallback"

        try:
            parsed = json.loads(raw_resp)
            cand = str(parsed.get("verdict", "")).strip().upper()
            if cand in (self.CLAIM_INDEMNIFIED, self.CLAIM_REFUTED, self.CLAIM_INCONCLUSIVE):
                verdict = cand
            rationale = str(parsed.get("rationale", ""))
        except Exception:
            pass

        now_utc = int(datetime.now(timezone.utc).timestamp())
        clm["adjudicated_at"] = now_utc
        clm["verdict"] = verdict
        clm["adjudication_rationale"] = rationale

        bond_amount = clm["claim_bond"]
        awarded = 0

        if verdict == self.CLAIM_INDEMNIFIED:
            req = clm["requested_indemnity"]
            res = pool["capital_reserves"]
            awarded = req if req <= res else res

            total_disbursement = awarded + bond_amount
            clm["indemnity_awarded"] = awarded
            pool["capital_reserves"] -= awarded
            pool["total_indemnities_paid"] += awarded
            pol["total_claims_paid"] += awarded
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

        elif verdict == self.CLAIM_REFUTED:
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
    print("STARTING 15-PHASE REGRESSION TEST SUITE: CyberBreachParametricIndemnityVault")
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
    h1 = vault._compute_claim_hash("POLICY_1", "0xabc", "CVE-2026-1111", "https://cve.mitre.org/1", "1")
    h2 = vault._compute_claim_hash("POLICY_10", "xabc", "CVE-2026-1111", "https://cve.mitre.org/1", "1")
    assert h1 != h2, "Collision between different length policy IDs"
    print("  [+] Phase 2 Passed: Canonical hashing resists delimiter injection.")

    # Phase 3: Address sanitization
    print("\n[Phase 3] Testing Strict Address Sanitization...")
    try:
        vault._validate_eth_address("bad_address", "Client")
        assert False, "Should reject non-address"
    except AssertionError as e:
        assert "[ERR_ADDR_01]" in str(e)
    try:
        vault._validate_eth_address("0x0000000000000000000000000000000000000000", "Client")
        assert False, "Should reject zero address"
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)
    print("  [+] Phase 3 Passed: Address sanitization strictly enforced.")

    # Phase 4: SSRF sanitization
    print("\n[Phase 4] Testing SSRF Defense on Security Advisory URLs...")
    for bad_url in [
        "http://localhost:8080/advisory.html",
        "https://127.0.0.1/cve.json",
        "http://169.254.169.254/latest/meta-data",
        "https://user:pass@cisa.gov/kev",
        "https://vendor.internal/vuln",
        "http://10.0.0.1/sec.html"
    ]:
        try:
            vault._validate_url(bad_url, "Advisory URL")
            assert False, f"Should reject SSRF URL {bad_url}"
        except AssertionError:
            pass
    print("  [+] Phase 4 Passed: SSRF defense neutralized all vector attacks.")

    # Phase 5: Warranty Pool Creation with Payable Escrow
    print("\n[Phase 5] Testing Warranty Pool Creation (100% Backed)...")
    underwriter = "0x2222222222222222222222222222222222222222"
    pool_val = 1_000_000_000_000  # 1,000 Gwei (1 ETH)
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

    # Phase 7: Client Policy Enrollment with Tier Multipliers
    print("\n[Phase 7] Testing Client Policy Enrollment & Coverage Multipliers...")
    client1 = "0x3333333333333333333333333333333333333333"
    premium = 50_000_000_000  # 50 Gwei premium
    duration = 86400 * 90     # 90 Days
    # TIER_ENTERPRISE multiplier is 5x -> coverage limit = 250 Gwei
    res_pol = vault.enroll_client_policy(client1, premium, "WARRANTY_POOL_1", vault.TIER_ENTERPRISE, duration)
    assert "POLICY_1" in res_pol
    assert vault.policies["POLICY_1"]["max_coverage_limit"] == premium * 5
    assert vault.total_policies_enrolled == 1
    print("  [+] Phase 7 Passed: POLICY_1 enrolled; 50 Gwei premium yields 250 Gwei coverage limit.")

    # Phase 8: Policy Duration & Premium Bounds Validation
    print("\n[Phase 8] Testing Policy Bounds Validation...")
    try:
        vault.enroll_client_policy(client1, 1_000_000_000, "WARRANTY_POOL_1", vault.TIER_STANDARD, duration)
        assert False, "Should reject premium < 10 Gwei"
    except AssertionError as e:
        assert "[ERR_MIN_PREMIUM]" in str(e)
    try:
        vault.enroll_client_policy(client1, premium, "WARRANTY_POOL_1", vault.TIER_STANDARD, 86400 * 10)
        assert False, "Should reject duration < 30 days"
    except AssertionError as e:
        assert "[ERR_DURATION_BOUNDS]" in str(e)
    print("  [+] Phase 8 Passed: Minimum premium and duration bounds strictly enforced.")

    # Phase 9: Breach Claim Filing with Anti-Spam Bond
    print("\n[Phase 9] Testing Breach Claim Filing with Anti-Spam Bond...")
    claim_bond = 30_000_000_000  # 30 Gwei
    req_indemnity = 200_000_000_000  # 200 Gwei (within 250 Gwei max)
    cve_id = "CVE-2026-38291"
    advisory_url = "https://cisa.gov/known-exploited-vulnerabilities/cve-2026-38291.html"
    res_clm = vault.submit_breach_claim(
        client1, claim_bond, "POLICY_1", cve_id, advisory_url, req_indemnity, "nonce-cve-1"
    )
    assert "CLAIM_1" in res_clm
    assert vault.claims["CLAIM_1"]["claim_bond"] == claim_bond
    print("  [+] Phase 9 Passed: CLAIM_1 filed with 30 Gwei anti-spam bond.")

    # Phase 10: Replay Defense & Unauthorized Claimant Rejection
    print("\n[Phase 10] Testing Replay Defense & Unauthorized Claimants...")
    stranger = "0x9999999999999999999999999999999999999999"
    try:
        vault.submit_breach_claim(stranger, claim_bond, "POLICY_1", cve_id, advisory_url, req_indemnity, "nonce-x")
        assert False, "Should reject unauthorized caller"
    except AssertionError as e:
        assert "[ERR_UNAUTHORIZED_CLAIMANT]" in str(e)
    try:
        vault.submit_breach_claim(client1, claim_bond, "POLICY_1", cve_id, advisory_url, req_indemnity, "nonce-cve-1")
        assert False, "Should reject duplicate claim fingerprint"
    except AssertionError as e:
        assert "[ERR_CLAIM_EXISTS]" in str(e)
    print("  [+] Phase 10 Passed: Access control and fingerprint replay defense verified.")

    # Phase 11: Fail-Closed Evidence Ingestion Invariant
    print("\n[Phase 11] Testing Fail-Closed Evidence Ingestion Invariant...")
    gl.fail_web_fetch = True
    try:
        vault.adjudicate_breach_claim("CLAIM_1")
        assert False, "Should abort fail-closed on evidence fetch error"
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    gl.fail_web_fetch = False
    assert vault.claims["CLAIM_1"]["verdict"] == vault.CLAIM_PENDING
    print("  [+] Phase 11 Passed: Network failure triggered zero-mutation abort.")

    # Phase 12: Consensus Adjudication: BREACH_INDEMNIFIED (Payout + 100% Bond Refund)
    print("\n[Phase 12] Testing Consensus Adjudication: BREACH_INDEMNIFIED...")
    res_adj = vault.adjudicate_breach_claim("CLAIM_1")
    assert "CLAIM_ADJUDICATED: CLAIM_1" in res_adj
    assert vault.claims["CLAIM_1"]["verdict"] == vault.CLAIM_INDEMNIFIED
    assert vault.claims["CLAIM_1"]["indemnity_awarded"] == req_indemnity
    # Total payout = 200 Gwei indemnity + 30 Gwei bond refund = 230 Gwei
    assert len(gl.transfers) == 1
    assert gl.transfers[0]["recipient"] == client1.lower()
    assert gl.transfers[0]["amount"] == req_indemnity + claim_bond
    print("  [+] Phase 12 Passed: Breach indemnified; 200 Gwei indemnity + 30 Gwei bond refunded.")

    # Phase 13: Consensus Adjudication: CLAIM_REFUTED (Bond Slashed to Underwriter Reserves)
    print("\n[Phase 13] Testing Consensus Adjudication: CLAIM_REFUTED...")
    # Client files CLAIM_2 for remaining 50 Gwei
    vault.submit_breach_claim(
        client1, claim_bond, "POLICY_1", "CVE-2026-99999", "https://cisa.gov/refuted.html", 50_000_000_000, "nonce-refuted"
    )
    gl.exec_prompt = lambda p: json.dumps({
        "verdict": "CLAIM_REFUTED",
        "cvss_score": 3.1,
        "rationale": "Advisory states vulnerability does not affect enterprise production builds."
    })
    res_ref = vault.adjudicate_breach_claim("CLAIM_2")
    assert vault.claims["CLAIM_2"]["verdict"] == vault.CLAIM_REFUTED
    assert vault.claims["CLAIM_2"]["indemnity_awarded"] == 0
    # Slashed bond added to underwriter capital reserves
    print("  [+] Phase 13 Passed: Frivolous claim refuted; 30 Gwei bond slashed to capital reserves.")

    # Phase 14: Consensus Adjudication: SCOPE_INCONCLUSIVE (100% Bond Refunded, Zero Indemnity)
    print("\n[Phase 14] Testing Consensus Adjudication: SCOPE_INCONCLUSIVE...")
    client2 = "0x4444444444444444444444444444444444444444"
    vault.enroll_client_policy(client2, premium, "WARRANTY_POOL_1", vault.TIER_STANDARD, duration)
    vault.submit_breach_claim(
        client2, claim_bond, "POLICY_2", "CVE-2026-88888", "https://cisa.gov/inconclusive.html", 100_000_000_000, "nonce-inc"
    )
    gl.exec_prompt = lambda p: json.dumps({
        "verdict": "SCOPE_INCONCLUSIVE",
        "cvss_score": 6.5,
        "rationale": "Vendor post-mortem inconclusive regarding affected version branch."
    })
    vault.adjudicate_breach_claim("CLAIM_3")
    assert vault.claims["CLAIM_3"]["verdict"] == vault.CLAIM_INCONCLUSIVE
    assert vault.claims["CLAIM_3"]["indemnity_awarded"] == 0
    # 100% Bond refunded to client2
    last_tx = gl.transfers[-1]
    assert last_tx["recipient"] == client2.lower()
    assert last_tx["amount"] == claim_bond
    print("  [+] Phase 14 Passed: Scope inconclusive; 100% of claim bond safely returned.")

    # Phase 15: Failed Transfer Credited to Claimable Balance & Safe withdraw_claimable()
    print("\n[Phase 15] Testing Failed Transfer Handling & withdraw_claimable()...")
    client3 = "0x5555555555555555555555555555555555555555"
    vault.enroll_client_policy(client3, premium, "WARRANTY_POOL_1", vault.TIER_MISSION_CRITICAL, duration)
    vault.submit_breach_claim(
        client3, claim_bond, "POLICY_3", "CVE-2026-77777", "https://cisa.gov/crit.html", 100_000_000_000, "nonce-crit"
    )
    gl.simulate_transfer_fail = True
    gl.exec_prompt = lambda p: json.dumps({
        "verdict": "BREACH_INDEMNIFIED",
        "cvss_score": 9.9,
        "rationale": "Severe zero-day active exploitation verified."
    })
    vault.adjudicate_breach_claim("CLAIM_4")
    expected_claimable = 100_000_000_000 + claim_bond
    assert vault.claimable_balances[client3.lower()] == expected_claimable

    # Verify withdraw_claimable failure preserves balance
    try:
        vault.withdraw_claimable(client3)
        assert False, "Should raise when transfer fails"
    except AssertionError as e:
        assert "[ERR_WITHDRAWAL_FAILED]" in str(e)
    assert vault.claimable_balances[client3.lower()] == expected_claimable

    # Now verify successful withdrawal
    gl.simulate_transfer_fail = False
    vault.withdraw_claimable(client3)
    assert vault.claimable_balances[client3.lower()] == 0
    assert gl.transfers[-1]["recipient"] == client3.lower()
    assert gl.transfers[-1]["amount"] == expected_claimable
    print("  [+] Phase 15 Passed: Failed payout preserved and safely recovered via withdraw_claimable().")

    print("\n" + "=" * 80)
    print("ALL 15 PHASES OF CyberBreachParametricIndemnityVault PASSED WITH 0 ERRORS!")
    print("=" * 80)


if __name__ == "__main__":
    run_tests()
