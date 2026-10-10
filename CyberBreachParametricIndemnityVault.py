# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import json
import hashlib
import urllib.parse
import datetime
from dataclasses import dataclass
from genlayer import *


STATUS_POLICY_ACTIVE = "ACTIVE"
STATUS_POLICY_EXPIRED = "EXPIRED"

CLAIM_PENDING = "PENDING_CONSENSUS"
CLAIM_INDEMNIFIED = "BREACH_INDEMNIFIED"
CLAIM_REFUTED = "CLAIM_REFUTED"
CLAIM_INCONCLUSIVE = "SCOPE_INCONCLUSIVE"

TIER_STANDARD = "TIER_STANDARD"               # 3x coverage multiplier
TIER_ENTERPRISE = "TIER_ENTERPRISE"           # 5x coverage multiplier
TIER_MISSION_CRITICAL = "TIER_MISSION_CRITICAL" # 10x coverage multiplier

MIN_POOL_LIQUIDITY = 100_000_000_000          # 100 Gwei
MIN_POLICY_PREMIUM = 10_000_000_000           # 10 Gwei
MIN_CLAIM_BOND = 25_000_000_000               # 25 Gwei
MIN_POLICY_DURATION = 86400 * 30              # 30 Days
MAX_POLICY_DURATION = 86400 * 365 * 2         # 2 Years


@allow_storage
@dataclass
class WarrantyPoolRecord:
    pool_id: str
    underwriter: str
    vendor_product_name: str
    capital_reserves: u256
    total_indemnities_paid: u256
    active_policies_count: u256
    created_at: u256
    is_active: bool


@allow_storage
@dataclass
class ClientPolicyRecord:
    policy_id: str
    pool_id: str
    client: str
    tier: str
    premium_paid: u256
    max_coverage_limit: u256
    start_time: u256
    expiration_time: u256
    total_claims_paid: u256
    status: str


@allow_storage
@dataclass
class BreachClaimRecord:
    claim_id: str
    policy_id: str
    pool_id: str
    claimant: str
    cve_id: str
    advisory_url: str
    claim_fingerprint: str
    requested_indemnity: u256
    claim_bond: u256
    filed_at: u256
    adjudicated_at: u256
    verdict: str
    indemnity_awarded: u256
    has_claimed: bool
    adjudication_rationale: str


class CyberBreachParametricIndemnityVault(gl.Contract):
    """
    CyberBreachParametricIndemnityVault: Autonomous Parametric Cloud & Cyber Breach Warranty Vault
    =============================================================================================
    Architectural Invariants & Guarantees:
    1. 100% Backed Payable Escrow: Underwriter warranty reserves, client policy premiums, and claim
       bonds are escrowed strictly via @gl.public.write.payable reading gl.message.value.
    2. Zero Genesis Fixtures: Zero unbacked debt, phantom coverage, or synthetic capital minted in __init__.
    3. Non-Admin Consensus Clock: Policy start/expiration and claim eligibility evaluate strictly
       against consensus UTC timestamps (datetime.datetime.now).
    4. Canonical Length-Prefixed Hashing: Delimiter and replay collisions are eliminated.
    5. Strict Address & SSRF Defense: Rejects numeric IPs, localhost, RFC1918 ranges, internal TLDs,
       and userinfo delimiters in official CVE/CISA advisory URLs.
    6. Fail-Closed Ingestion: Advisory timeouts cleanly revert with [ERR_EVIDENCE_FETCH_FAILED]
       with zero state mutation.
    7. Recoverable Claimable Balances: Payouts disburse via emit_transfer(); failed transfers credit
       to claimable_balances with a dedicated withdraw_claimable() method that preserves balances on failure.
    """

    owner: str
    pools: TreeMap[str, WarrantyPoolRecord]
    policies: TreeMap[str, ClientPolicyRecord]
    claims: TreeMap[str, BreachClaimRecord]
    consumed_claim_hashes: TreeMap[str, bool]
    claimable_balances: TreeMap[str, u256]

    total_pools_created: u256
    total_policies_enrolled: u256
    total_claims_filed: u256
    total_claims_adjudicated: u256
    total_volume_locked: u256
    total_indemnities_distributed: u256

    def __init__(self, owner: str):
        clean_owner = self._validate_eth_address(owner, "Contract Owner")
        self.owner = clean_owner.lower()
        self.total_pools_created = u256(0)
        self.total_policies_enrolled = u256(0)
        self.total_claims_filed = u256(0)
        self.total_claims_adjudicated = u256(0)
        self.total_volume_locked = u256(0)
        self.total_indemnities_distributed = u256(0)

    # --------------------------------------------------------------------------
    # General Liquidity Reserve Top-Up
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def fund_contract(self) -> None:
        """
        Accepts direct native GEN transfers to increase general vault reserves.
        """
        val = int(gl.message.value)
        if val > 0:
            self.total_volume_locked += u256(val)

    # --------------------------------------------------------------------------
    # Cryptographic Hashing
    # --------------------------------------------------------------------------
    def _compute_claim_hash(self, policy_id: str, claimant: str, cve_id: str, url: str, nonce: str) -> str:
        data = (
            "L" + str(len(policy_id)) + ":" + policy_id.upper() + "|" +
            "L" + str(len(claimant)) + ":" + claimant.lower() + "|" +
            "L" + str(len(cve_id)) + ":" + cve_id.upper() + "|" +
            "L" + str(len(url)) + ":" + url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    # --------------------------------------------------------------------------
    # Address & SSRF Validation
    # --------------------------------------------------------------------------
    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42 and clean.startswith("0x"), \
            "[ERR_ADDR_01] " + field_name + " must be a valid 42-character hexadecimal string starting with '0x'."
        for ch in clean[2:].lower():
            assert ch in "0123456789abcdef", \
                "[ERR_ADDR_02] " + field_name + " contains invalid hexadecimal characters."
        assert clean.lower() != "0x0000000000000000000000000000000000000000", \
            "[ERR_ADDR_ZERO] " + field_name + " cannot be the zero address."
        return clean

    def _validate_url(self, url: str, field_name: str) -> str:
        clean_url = url.strip().strip('"').strip("'")
        assert 10 <= len(clean_url) <= 300, \
            "[ERR_URL_LEN] " + field_name + " length must be between 10 and 300 characters."

        parsed = urllib.parse.urlsplit(clean_url)
        assert parsed.scheme in ("https", "http"), \
            "[ERR_URL_SCHEME] " + field_name + " must use http or https scheme."

        assert not parsed.username and not parsed.password, \
            "[ERR_URL_SSRF] User-info credentials (@) in " + field_name + " are strictly forbidden."
        assert "@" not in parsed.netloc, \
            "[ERR_URL_SSRF] Delimiter '@' in " + field_name + " is strictly forbidden."

        host = parsed.hostname.lower() if parsed.hostname else ""
        assert host, "[ERR_URL_HOST] Missing or unparseable host in " + field_name + "."

        if host.isdigit() or host.startswith("0x") or host.startswith("0o"):
            raise AssertionError("[ERR_URL_SSRF] Numeric IP addresses in " + field_name + " are forbidden.")

        if host in ("localhost", "0.0.0.0", "::", "::1"):
            raise AssertionError("[ERR_URL_SSRF] Localhost and loopback addresses in " + field_name + " are forbidden.")

        if any(host.endswith(suffix) for suffix in (".local", ".internal", ".lan", ".corp", ".test", ".invalid")):
            raise AssertionError("[ERR_URL_SSRF] Private internal domain targets in " + field_name + " are forbidden.")

        parts_ip = host.split(".")
        if len(parts_ip) == 4 and all(p.isdigit() for p in parts_ip):
            o1, o2, o3, o4 = [int(p) for p in parts_ip]
            if o1 in (127, 10, 0) or (o1 == 172 and 16 <= o2 <= 31) or (o1 == 192 and o2 == 168) or (o1 == 169 and o2 == 254):
                raise AssertionError("[ERR_URL_SSRF] Private RFC1918 or link-local IP ranges are forbidden.")

        return clean_url

    # --------------------------------------------------------------------------
    # Core Function 1: Warranty Pool Creation
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def create_warranty_pool(self, vendor_product_name: str) -> str:
        """
        Creates a parametric cybersecurity warranty pool backed by native GEN capital reserves.
        """
        sender_hex = self._validate_eth_address(str(gl.message.sender), "Underwriter").lower()
        clean_prod = vendor_product_name.strip().strip('"').strip("'")
        assert 3 <= len(clean_prod) <= 120, \
            "[ERR_PRODUCT_LEN] Vendor/Product name must be between 3 and 120 characters."

        seed_deposit = int(gl.message.value)
        assert seed_deposit >= MIN_POOL_LIQUIDITY, \
            "[ERR_MIN_LIQUIDITY] Seed liquidity must be at least " + str(MIN_POOL_LIQUIDITY) + " wei."

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        new_pool_id = "WARRANTY_POOL_" + str(int(self.total_pools_created) + 1)

        pool_rec = WarrantyPoolRecord(
            pool_id=new_pool_id,
            underwriter=sender_hex,
            vendor_product_name=clean_prod,
            capital_reserves=u256(seed_deposit),
            total_indemnities_paid=u256(0),
            active_policies_count=u256(0),
            created_at=u256(now_utc),
            is_active=True
        )

        self.pools[new_pool_id] = pool_rec
        self.total_pools_created += 1
        self.total_volume_locked += u256(seed_deposit)

        return (
            "POOL_CREATED: " + new_pool_id + " | Product: " + clean_prod
            + " | Reserves: " + str(seed_deposit) + " wei"
        )

    # --------------------------------------------------------------------------
    # Core Function 2: Top Up Pool Reserves
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def deposit_warranty_pool(self, pool_id: str) -> str:
        """
        Increases available underwritten warranty capital for a specific pool.
        """
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND] Warranty pool does not exist."
        pool = self.pools[clean_p_id]
        assert pool.is_active, "[ERR_POOL_INACTIVE] Target warranty pool is inactive."

        dep_val = int(gl.message.value)
        assert dep_val > 0, "[ERR_ZERO_DEPOSIT] Deposit amount must be greater than zero."

        pool.capital_reserves += u256(dep_val)
        self.pools[clean_p_id] = pool
        self.total_volume_locked += u256(dep_val)

        return "POOL_TOPPED_UP: " + clean_p_id + " | Added: " + str(dep_val) + " wei | Total: " + str(int(pool.capital_reserves)) + " wei"

    # --------------------------------------------------------------------------
    # Core Function 3: Client Policy Enrollment
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def enroll_client_policy(self, pool_id: str, tier: str, duration_seconds: int) -> str:
        """
        Enrolls an enterprise client into parametric breach warranty coverage.
        """
        clean_p_id = pool_id.strip().upper()
        assert clean_p_id in self.pools, "[ERR_POOL_NOT_FOUND] Warranty pool does not exist."
        pool = self.pools[clean_p_id]
        assert pool.is_active, "[ERR_POOL_INACTIVE] Warranty pool is inactive."

        sender_hex = self._validate_eth_address(str(gl.message.sender), "Client").lower()
        clean_tier = tier.strip().upper()
        assert clean_tier in (TIER_STANDARD, TIER_ENTERPRISE, TIER_MISSION_CRITICAL), \
            "[ERR_INVALID_TIER] Tier must be TIER_STANDARD, TIER_ENTERPRISE, or TIER_MISSION_CRITICAL."

        dur = int(duration_seconds)
        assert MIN_POLICY_DURATION <= dur <= MAX_POLICY_DURATION, \
            "[ERR_DURATION_BOUNDS] Duration must be between 30 days and 2 years."

        premium_val = int(gl.message.value)
        assert premium_val >= MIN_POLICY_PREMIUM, \
            "[ERR_MIN_PREMIUM] Policy premium must be at least " + str(MIN_POLICY_PREMIUM) + " wei."

        # Compute coverage limit based on tier multiplier
        if clean_tier == TIER_STANDARD:
            cov_limit = premium_val * 3
        elif clean_tier == TIER_ENTERPRISE:
            cov_limit = premium_val * 5
        else: # TIER_MISSION_CRITICAL
            cov_limit = premium_val * 10

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        new_pol_id = "POLICY_" + str(int(self.total_policies_enrolled) + 1)

        pol_rec = ClientPolicyRecord(
            policy_id=new_pol_id,
            pool_id=clean_p_id,
            client=sender_hex,
            tier=clean_tier,
            premium_paid=u256(premium_val),
            max_coverage_limit=u256(cov_limit),
            start_time=u256(now_utc),
            expiration_time=u256(now_utc + dur),
            total_claims_paid=u256(0),
            status=STATUS_POLICY_ACTIVE
        )

        pool.capital_reserves += u256(premium_val)
        pool.active_policies_count += 1
        self.pools[clean_p_id] = pool

        self.policies[new_pol_id] = pol_rec
        self.total_policies_enrolled += 1
        self.total_volume_locked += u256(premium_val)

        return (
            "POLICY_ENROLLED: " + new_pol_id + " | Tier: " + clean_tier
            + " | Coverage Limit: " + str(cov_limit) + " wei | Expires: " + str(now_utc + dur)
        )

    # --------------------------------------------------------------------------
    # Core Function 4: Submit Breach Indemnity Claim
    # --------------------------------------------------------------------------
    @gl.public.write.payable
    def submit_breach_claim(
        self,
        policy_id: str,
        cve_id: str,
        advisory_url: str,
        requested_indemnity: int,
        nonce: str
    ) -> str:
        """
        Submits an expedited breach claim backed by an anti-spam claim bond and official advisory source.
        """
        clean_pol_id = policy_id.strip().upper()
        assert clean_pol_id in self.policies, "[ERR_POLICY_NOT_FOUND] Client policy does not exist."
        pol = self.policies[clean_pol_id]

        sender_hex = self._validate_eth_address(str(gl.message.sender), "Claimant").lower()
        assert sender_hex == pol.client, \
            "[ERR_UNAUTHORIZED_CLAIMANT] Caller is not the registered policyholder."

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        assert now_utc <= int(pol.expiration_time), \
            "[ERR_POLICY_EXPIRED] Policy has expired. Incident claims cannot be filed."

        clean_cve = cve_id.strip().upper()
        assert clean_cve.startswith("CVE-") and len(clean_cve) >= 9, \
            "[ERR_INVALID_CVE] Must specify a valid CVE identifier (e.g. CVE-2026-38291)."

        clean_url = self._validate_url(advisory_url, "Security Advisory URL")

        req_indem = int(requested_indemnity)
        assert req_indem > 0, "[ERR_ZERO_INDEMNITY] Requested indemnity must be greater than zero."

        remaining_coverage = int(pol.max_coverage_limit) - int(pol.total_claims_paid)
        assert req_indem <= remaining_coverage, \
            "[ERR_EXCEEDS_COVERAGE] Requested indemnity (" + str(req_indem) + ") exceeds remaining policy coverage limit (" + str(remaining_coverage) + ")."

        bond_val = int(gl.message.value)
        assert bond_val >= MIN_CLAIM_BOND, \
            "[ERR_MIN_CLAIM_BOND] Claim bond must be at least " + str(MIN_CLAIM_BOND) + " wei."

        c_hash = self._compute_claim_hash(clean_pol_id, sender_hex, clean_cve, clean_url, nonce)
        assert c_hash.lower() not in self.consumed_claim_hashes, \
            "[ERR_CLAIM_EXISTS] Duplicate claim fingerprint already filed. Regenerate nonce."

        new_c_id = "CLAIM_" + str(int(self.total_claims_filed) + 1)

        claim_rec = BreachClaimRecord(
            claim_id=new_c_id,
            policy_id=clean_pol_id,
            pool_id=pol.pool_id,
            claimant=sender_hex,
            cve_id=clean_cve,
            advisory_url=clean_url,
            claim_fingerprint=c_hash,
            requested_indemnity=u256(req_indem),
            claim_bond=u256(bond_val),
            filed_at=u256(now_utc),
            adjudicated_at=u256(0),
            verdict=CLAIM_PENDING,
            indemnity_awarded=u256(0),
            has_claimed=False,
            adjudication_rationale=""
        )

        self.claims[new_c_id] = claim_rec
        self.consumed_claim_hashes[c_hash.lower()] = True
        self.total_claims_filed += 1
        self.total_volume_locked += u256(bond_val)

        return (
            "CLAIM_FILED: " + new_c_id + " | Policy: " + clean_pol_id
            + " | CVE: " + clean_cve + " | Requested: " + str(req_indem) + " wei"
        )

    # --------------------------------------------------------------------------
    # Core Function 5: Multi-Validator Consensus Adjudication
    # --------------------------------------------------------------------------
    @gl.public.write
    def adjudicate_breach_claim(self, claim_id: str) -> str:
        """
        Executes multi-validator web ingestion and AI consensus audit of breach advisory.
        """
        clean_c_id = claim_id.strip().upper()
        assert clean_c_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Target claim does not exist."
        clm = self.claims[clean_c_id]
        assert clm.verdict == CLAIM_PENDING, \
            "[ERR_ALREADY_ADJUDICATED] Claim already adjudicated: " + clm.verdict

        assert clm.pool_id in self.pools, "[ERR_POOL_NOT_FOUND] Warranty pool not found."
        pool = self.pools[clm.pool_id]

        assert clm.policy_id in self.policies, "[ERR_POLICY_NOT_FOUND] Policy not found."
        pol = self.policies[clm.policy_id]

        # Fail-Closed Evidence Ingestion
        try:
            advisory_text = gl.get_webpage(clm.advisory_url)
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Consensus could not fetch security advisory from " + clm.advisory_url)

        assert advisory_text is not None and len(advisory_text.strip()) >= 30, \
            "[ERR_EVIDENCE_FETCH_FAILED] Security advisory response was empty or insufficient (< 30 characters)."

        prompt = (
            "You are a GenLayer autonomous cybersecurity and CVE breach warranty validator.\n"
            "Vendor & Product: " + pool.vendor_product_name + "\n"
            "Claimed Incident CVE: " + clm.cve_id + "\n"
            "Official Advisory Text fetched from " + clm.advisory_url + ":\n"
            "\"\"\"\n" + advisory_text[:2500] + "\n\"\"\"\n\n"
            "TASK: Evaluate whether the advisory confirms a High or Critical severity breach (CVSS >= 8.0) affecting the vendor product.\n"
            "Respond STRICTLY in valid JSON with exactly three keys:\n"
            "\"verdict\": one of [\"BREACH_INDEMNIFIED\", \"CLAIM_REFUTED\", \"SCOPE_INCONCLUSIVE\"]\n"
            "\"cvss_score\": float between 0.0 and 10.0\n"
            "\"rationale\": a concise 1-sentence technical justification."
        )

        raw_resp = gl.exec_prompt(prompt)
        verdict = CLAIM_INCONCLUSIVE
        rationale = "Consensus fallback resolution."
        cvss = 0.0

        try:
            clean_json = raw_resp.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()
            parsed = json.loads(clean_json)
            cand = str(parsed.get("verdict", "")).strip().upper()
            if cand in (CLAIM_INDEMNIFIED, CLAIM_REFUTED, CLAIM_INCONCLUSIVE):
                verdict = cand
            cvss = float(parsed.get("cvss_score", 0.0))
            rationale = str(parsed.get("rationale", "")).strip()[:200]
        except Exception:
            pass

        now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        clm.adjudicated_at = u256(now_utc)
        clm.verdict = verdict
        clm.adjudication_rationale = rationale

        bond_amount = int(clm.claim_bond)
        awarded_indemnity = 0

        if verdict == CLAIM_INDEMNIFIED:
            requested = int(clm.requested_indemnity)
            reserves = int(pool.capital_reserves)
            # Cap payout at available pool reserves
            awarded_indemnity = requested if requested <= reserves else reserves

            total_disbursement = awarded_indemnity + bond_amount
            clm.indemnity_awarded = u256(awarded_indemnity)
            pool.capital_reserves -= u256(awarded_indemnity)
            pool.total_indemnities_paid += u256(awarded_indemnity)
            pol.total_claims_paid += u256(awarded_indemnity)

            self.total_indemnities_distributed += u256(awarded_indemnity)
            if int(self.total_volume_locked) >= total_disbursement:
                self.total_volume_locked -= u256(total_disbursement)
            else:
                self.total_volume_locked = u256(0)

            clm.has_claimed = True

            # Direct transfer with fallback to claimable_balances
            transfer_succeeded = False
            try:
                gl.emit_transfer(Address(clm.claimant), u256(total_disbursement))
                transfer_succeeded = True
            except Exception:
                try:
                    target = gl.get_contract_at(clm.claimant)
                    target.emit_transfer(value=u256(total_disbursement), on='finalized')
                    transfer_succeeded = True
                except Exception:
                    transfer_succeeded = False

            if not transfer_succeeded:
                cur = int(self.claimable_balances.get(clm.claimant, u256(0)))
                self.claimable_balances[clm.claimant] = u256(cur + total_disbursement)

        elif verdict == CLAIM_REFUTED:
            # Frivolous claim bond slashed to underwriter reserves
            pool.capital_reserves += u256(bond_amount)
            clm.indemnity_awarded = u256(0)
            clm.has_claimed = True

        else: # SCOPE_INCONCLUSIVE
            # 100% Refund claim bond to claimant, 0 indemnity awarded
            clm.indemnity_awarded = u256(0)
            clm.has_claimed = True
            if int(self.total_volume_locked) >= bond_amount:
                self.total_volume_locked -= u256(bond_amount)
            else:
                self.total_volume_locked = u256(0)

            transfer_succeeded = False
            try:
                gl.emit_transfer(Address(clm.claimant), u256(bond_amount))
                transfer_succeeded = True
            except Exception:
                try:
                    target = gl.get_contract_at(clm.claimant)
                    target.emit_transfer(value=u256(bond_amount), on='finalized')
                    transfer_succeeded = True
                except Exception:
                    transfer_succeeded = False

            if not transfer_succeeded:
                cur = int(self.claimable_balances.get(clm.claimant, u256(0)))
                self.claimable_balances[clm.claimant] = u256(cur + bond_amount)

        self.claims[clean_c_id] = clm
        self.pools[clm.pool_id] = pool
        self.policies[clm.policy_id] = pol
        self.total_claims_adjudicated += 1

        return (
            "CLAIM_ADJUDICATED: " + clean_c_id + " | Verdict: " + verdict
            + " | Indemnity: " + str(awarded_indemnity) + " wei | Rationale: " + rationale
        )

    # --------------------------------------------------------------------------
    # Core Function 6: Recoverable Claimable Withdrawal
    # --------------------------------------------------------------------------
    @gl.public.write
    def withdraw_claimable(self) -> str:
        """
        Enables claimants whose native transfers previously failed to safely withdraw
        their accumulated claimable balances. Preserves and restores balance upon failure.
        """
        sender_hex = self._validate_eth_address(str(gl.message.sender), "Caller").lower()
        assert sender_hex in self.claimable_balances, \
            "[ERR_NO_CLAIMABLE] No claimable funds found for caller."
        bal = int(self.claimable_balances[sender_hex])
        assert bal > 0, "[ERR_ZERO_CLAIMABLE] Claimable balance is zero."

        # Optimistically zero balance before transfer
        self.claimable_balances[sender_hex] = u256(0)

        transfer_succeeded = False
        try:
            gl.emit_transfer(Address(sender_hex), u256(bal))
            transfer_succeeded = True
        except Exception:
            try:
                target = gl.get_contract_at(sender_hex)
                target.emit_transfer(value=u256(bal), on='finalized')
                transfer_succeeded = True
            except Exception:
                transfer_succeeded = False

        if not transfer_succeeded:
            # Preserve and restore balance upon failed transfer
            self.claimable_balances[sender_hex] = u256(bal)
            raise AssertionError(
                "[ERR_WITHDRAWAL_FAILED] Native transfer failed during withdrawal. Claimable balance restored: "
                + str(bal) + " wei."
            )

        return "WITHDRAW_SUCCESS: " + sender_hex + " | Amount: " + str(bal) + " wei"

    # --------------------------------------------------------------------------
    # Public Gateway Views
    # --------------------------------------------------------------------------
    @gl.public.view
    def get_pool_count(self) -> int:
        return int(self.total_pools_created)

    @gl.public.view
    def get_policy_count(self) -> int:
        return int(self.total_policies_enrolled)

    @gl.public.view
    def get_claim_count(self) -> int:
        return int(self.total_claims_filed)

    @gl.public.view
    def get_total_volume_locked(self) -> str:
        return str(int(self.total_volume_locked))

    @gl.public.view
    def get_total_indemnities_distributed(self) -> str:
        return str(int(self.total_indemnities_distributed))

    @gl.public.view
    def get_claimable_balance(self, user_address: str) -> str:
        clean_u = self._validate_eth_address(user_address, "User address").lower()
        return str(int(self.claimable_balances.get(clean_u, u256(0))))

    @gl.public.view
    def get_pool_overview(self, pool_id: str) -> dict:
        clean_p_id = pool_id.strip().upper()
        if clean_p_id not in self.pools:
            return {"exists": False}
        p = self.pools[clean_p_id]
        return {
            "exists": True,
            "pool_id": p.pool_id,
            "underwriter": p.underwriter,
            "vendor_product_name": p.vendor_product_name,
            "capital_reserves": str(int(p.capital_reserves)),
            "total_indemnities_paid": str(int(p.total_indemnities_paid)),
            "active_policies_count": int(p.active_policies_count),
            "is_active": p.is_active,
            "created_at": int(p.created_at)
        }

    @gl.public.view
    def get_client_policy(self, policy_id: str) -> dict:
        clean_pol_id = policy_id.strip().upper()
        if clean_pol_id not in self.policies:
            return {"exists": False}
        pol = self.policies[clean_pol_id]
        return {
            "exists": True,
            "policy_id": pol.policy_id,
            "pool_id": pol.pool_id,
            "client": pol.client,
            "tier": pol.tier,
            "premium_paid": str(int(pol.premium_paid)),
            "max_coverage_limit": str(int(pol.max_coverage_limit)),
            "remaining_coverage": str(int(pol.max_coverage_limit) - int(pol.total_claims_paid)),
            "start_time": int(pol.start_time),
            "expiration_time": int(pol.expiration_time),
            "total_claims_paid": str(int(pol.total_claims_paid)),
            "status": pol.status
        }

    @gl.public.view
    def get_claim_details(self, claim_id: str) -> dict:
        clean_c_id = claim_id.strip().upper()
        if clean_c_id not in self.claims:
            return {"exists": False}
        clm = self.claims[clean_c_id]
        return {
            "exists": True,
            "claim_id": clm.claim_id,
            "policy_id": clm.policy_id,
            "pool_id": clm.pool_id,
            "claimant": clm.claimant,
            "cve_id": clm.cve_id,
            "advisory_url": clm.advisory_url,
            "requested_indemnity": str(int(clm.requested_indemnity)),
            "claim_bond": str(int(clm.claim_bond)),
            "verdict": clm.verdict,
            "indemnity_awarded": str(int(clm.indemnity_awarded)),
            "has_claimed": clm.has_claimed,
            "filed_at": int(clm.filed_at),
            "adjudicated_at": int(clm.adjudicated_at),
            "adjudication_rationale": clm.adjudication_rationale
        }
