## 🔄 PHASE 1: Define Schema: CUE Data Model & YAML Policy

### ✅ Objective
Define **machine-verifiable, human-editable** data contracts using:
- **CUE** for structural invariants, type safety, defaults, and validation
- **YAML** for policy authoring, config, and examples

### 📁 Deliverables
1. `schemas/`  
   - `commit.cue`  
   - `seal.cue`  
   - `gossip.cue`  
   - `policy.cue`  
2. `examples/`  
   - `policy.yaml` (RBAC rules)  
   - `seal-request.yaml`  
   - `dispute-resolution.yaml`

---

### Step 1.1: Core CUE Schemas (Minimal Viable Set)

#### ▶ `schemas/commit.cue`
```cue
package emp

import "time"

// First-Class Human Agent — only these can author facts
HumanAgent: {
	// RFC 2119: MUST be verifiable via public key
	email:    string & =~ r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
	name:     string & >""
	keyID:    string & >""  // e.g., "ED25519:abc123"
	timestamp: time.Time
}

// Base commit — Git-compatible + EMP extensions
Commit: {
	// Git fields (required for DAG integrity)
	tree:      string & =~ r"^[a-f0-9]{40}$"
	parents:   [...string & =~ r"^[a-f0-9]{40}$"] | *[]
	author:    HumanAgent
	committer: HumanAgent | DeskPrincipal // Desk can only COMMIT, not AUTHOR

	// EMP-specific
	message:        string & >""
	ref:            string & =~ r"^refs/(epistemic|teleological)/[a-zA-Z0-9/_-]+$"
	trustLevel:     "verified" | "draft" | "disputed"
	timestamp:      time.Time
	signature:      string & >""  // base64(Ed25519(sign(commitBytes)))

	// Derived (not serialized, for validation)
	// CUE can compute SHA over canonicalized JSON
	hash: string & =~ r"^[a-f0-9]{40,64}$"
}
```

#### ▶ `schemas/seal.cue`
```cue
package emp

import "encoding/base64"

SealingResolution: "RETIRE" | "REAFFIRM" | "AMEND"

SealingSignature: {
	principal:   string & >""  // e.g., "alice@org"
	algorithm:   "ed25519"
	signature:   string & base64.Decode(_) != _|_  // valid base64
	timestamp:   time.Time
	nonce:       string & >"" & len(_) == 36  // UUIDv4
}

// Normative: sealing commit MUST contain these trailers
SealingTrailers: {
	"Epistemic-Seal-Version": "1.0"
	"Seals-Target-Commit":   string & =~ r"^[a-f0-9]{40,64}$"
	"Resolution-Type":       SealingResolution
	"RBAC-Transaction-ID":   string & =~ r"^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$"
	"Quorum-Signatures":     [...SealingSignature]
}
```

#### ▶ `schemas/policy.cue`
```cue
package emp

Verb: "propose" | "seal" | "retire" | "read"

// Policy Rule in YAML — human-authored, CUE-validated
PolicyRule: {
	id:        string & >""
	refGlob:   string & =~ r"^refs/(epistemic|teleological)/.*"  // e.g., "refs/epistemic/climate/*"
	verb:      Verb
	condition: {
		minTrustLevel?:   "draft" | "verified"  // default: any
		requiredRoles:    [...string] & len(_) > 0
		requiresHuman:    bool | *true
		maxDisputeDepth?: uint | *3  // max re-sealings
	} | *{}
}
```

✅ **Checkpoint 1.1**: Can you `cue vet` a sample commit?
```bash
$ cue vet schemas/commit.cue examples/commit.yaml
# → OK (or error with line number)
```

---

### Step 1.2: RBAC Policy in YAML (Human-Editable)

#### ▶ `examples/policy.yaml`
```yaml
# refs/epistemic/science/* — peer-reviewed facts only
- id: "science-peer-review"
  refGlob: "refs/epistemic/science/*"
  verb: "propose"
  condition:
    requiredRoles: ["scientist", "reviewer"]
    requiresHuman: true

- id: "science-seal"
  refGlob: "refs/epistemic/science/*"
  verb: "seal"
  condition:
    requiredRoles: ["editor-in-chief", "ombudsman"]
    minTrustLevel: "verified"
    # ≥2 signers, 1 must have "finality" role
```

✅ **Checkpoint 1.2**:  
Use CUE to compile this to SQL or OPA Rego:
```bash
$ cue export schemas/policy.cue examples/policy.yaml --out yaml
# → normalized, typed YAML — ready for ingestion
```

---

### Step 1.3: Gossip + Dispute Vector (CUE)

#### ▶ `schemas/gossip.cue`
```cue
package emp

Connectivity: "online" | "offline" | "degraded"

GossipPacket: {
	payload:       Commit
	refHint:       "epistemic" | "teleological"
	connectivity:  Connectivity
	disputeVector: [...string & =~ r"^[a-f0-9]{40,64}$"]  // commits in dispute
	signature:     string & base64.Decode(_) != _|_
	timestamp:     time.Time

	// Invariant: if disputeVector non-empty, payload.trustLevel = "disputed"
	(disputeVector == [] || payload.trustLevel == "disputed") |
		_"disputeVector requires disputed trustLevel"
}
```

✅ **CUE Superpower**:  
Add validation:  
> *“A node in `offline` state MUST NOT emit payloads with `trustLevel: verified` unless sealed.”*

```cue
// Add to GossipPacket:
// (connectivity != "offline" || 
//  payload.trustLevel == "disputed" || 
//  payload.committer.type == "DeskPrincipal") |
//    _"offline nodes may only gossip verified facts if sealed by Desk"
```

---

## 🔄 PHASE 2: DESK RBAC — SQL SCHEMA & EVALUATION LOGIC

### ✅ Objective
Define **normative SQL DDL** (PostgreSQL 14+) for Desk RBAC, and **evaluation logic** (CUE + PL/pgSQL).

### 📁 Deliverables
1. `desk/ddl.sql` — full schema  
2. `desk/rbac_eval.cue` — policy matching logic  
3. `desk/rbac_eval.sql` — PostgreSQL function

---

### Step 2.1: SQL Schema (Normative — Appendix B)

#### ▶ `desk/ddl.sql`
```sql
-- Principals: humans and desks
CREATE TABLE principals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE CHECK (email ~ '^[^@]+@[^@]+\.[^@]+$'),
  name          TEXT NOT NULL,
  key_id        TEXT NOT NULL,  -- e.g., "ED25519:abc123"
  is_desk       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Roles (e.g., "scientist", "finality")
CREATE TABLE roles (
  name          TEXT PRIMARY KEY,
  description   TEXT
);

-- Principal ↔ Role mapping
CREATE TABLE principal_roles (
  principal_id  UUID REFERENCES principals(id) ON DELETE CASCADE,
  role_name     TEXT REFERENCES roles(name) ON DELETE CASCADE,
  granted_at    TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (principal_id, role_name)
);

-- Policy Rules — machine-ingested from CUE-validated YAML
CREATE TABLE policy_rules (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ref_glob          TEXT NOT NULL,  -- e.g., 'refs/epistemic/science/*'
  verb              TEXT NOT NULL CHECK (verb IN ('propose','seal','retire','read')),
  required_roles    TEXT[] NOT NULL DEFAULT '{}',
  min_trust_level   TEXT CHECK (min_trust_level IN ('draft','verified')),
  requires_human    BOOLEAN NOT NULL DEFAULT TRUE,
  max_dispute_depth INT CHECK (max_dispute_depth > 0),
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Desk transaction log (for audit + RBAC-Transaction-ID resolution)
CREATE TABLE rbac_transactions (
  id            UUID PRIMARY KEY,
  principal_id  UUID REFERENCES principals(id),
  action        TEXT NOT NULL,  -- e.g., 'seal_commit'
  target        JSONB NOT NULL, -- e.g., {"commit": "abcd...", "resolution": "RETIRE"}
  decision      TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY','ESCALATE')),
  reason        TEXT,
  timestamp     TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_policy_ref ON policy_rules USING GIN (ref_glob gin_trgm_ops);
CREATE INDEX idx_principal_roles ON principal_roles (role_name);
```

✅ **Checkpoint 2.1**: Run in PostgreSQL — `psql -f desk/ddl.sql`

---

### Step 2.2: RBAC Evaluation Logic (CUE + SQL)

#### ▶ `desk/rbac_eval.cue`
```cue
package rbac

import "list"

// Input to evaluator
Request: {
	principalID: string
	ref:         string  // e.g., "refs/epistemic/science/co2"
	verb:        emp.Verb
	trustLevel:  "draft" | "verified" | *""  // optional
	disputeDepth: uint | *0
	isHuman:     bool
}

// Match rule: does rule apply to request?
matchRule: (rule: emp.PolicyRule, req: Request) => 
  (rule.refGlob =~ req.ref) &&
  (rule.verb == req.verb) &&
  (rule.condition.minTrustLevel == undefined || req.trustLevel =~ rule.condition.minTrustLevel) &&
  (rule.condition.requiresHuman ? req.isHuman : true) &&
  (req.disputeDepth <= (rule.condition.maxDisputeDepth | 3))

// Evaluate: is request allowed?
evaluate: (rules: [...emp.PolicyRule], req: Request, roles: [...string]) => 
  let applicable = [ for r in rules if matchRule(r, req) { r }]
  // ALLOW if ≥1 rule matches AND principal has all requiredRoles for that rule
  len(applicable) > 0 &&
  list.All(applicable, r => 
    list.All(r.condition.requiredRoles, role => role in roles)
  )
```

#### ▶ `desk/rbac_eval.sql` (PostgreSQL function)
```sql
CREATE OR REPLACE FUNCTION desk_authorize(
  p_principal_id UUID,
  p_ref TEXT,
  p_verb TEXT,
  p_trust_level TEXT DEFAULT NULL,
  p_dispute_depth INT DEFAULT 0,
  p_is_human BOOLEAN DEFAULT TRUE
) RETURNS TABLE (
  allowed BOOLEAN,
  matched_rule_id UUID,
  reason TEXT
) AS $$
DECLARE
  v_roles TEXT[];
  r RECORD;
BEGIN
  -- Get roles for principal
  SELECT array_agg(role_name) INTO v_roles
  FROM principal_roles WHERE principal_id = p_principal_id;

  IF v_roles IS NULL THEN v_roles := '{}'; END IF;

  -- Find first matching rule
  FOR r IN
    SELECT id, required_roles, min_trust_level, requires_human, max_dispute_depth
    FROM policy_rules
    WHERE verb = p_verb
      AND p_ref LIKE replace(replace(ref_glob, '*', '%'), '?', '_')
      AND (min_trust_level IS NULL OR p_trust_level = min_trust_level)
      AND (requires_human IS FALSE OR p_is_human)
      AND (max_dispute_depth IS NULL OR p_dispute_depth <= max_dispute_depth)
    ORDER BY created_at DESC
  LOOP
    -- Check role intersection
    IF v_roles @> r.required_roles THEN
      RETURN QUERY SELECT TRUE, r.id, NULL::TEXT;
      RETURN;
    END IF;
  END LOOP;

  RETURN QUERY SELECT FALSE, NULL::UUID, 'no matching rule or insufficient roles';
END;
$$ LANGUAGE plpgsql STABLE;
```

✅ **Checkpoint 2.2**:  
Test in `psql`:  
```sql
SELECT * FROM desk_authorize(
  'a1b2c3...', 
  'refs/epistemic/science/co2', 
  'seal', 
  'verified', 
  1, 
  TRUE
);
```

---

## 🔄 PHASE 3: PROTOCOL OPERATIONS — EFSM + GUARDS (IETF Prose)

### ✅ Objective
Translate EFSM into **IETF-normative prose** with precise guards using CUE predicates.

### Key Pattern:
> When a commit is in state `S_old`, and event `E` occurs, and guard `G` holds,  
> then the system **MUST** transition to `S_new`, and **MUST** emit effect `F`.

Let’s formalize one transition as a template.

---

### Step 3.1: Normative Transition Template

#### ▶ Transition: `PROPOSED` → `FACT_ACCEPTED`

> **When** a commit `c` is in state `PROPOSED`,  
> **and** the event `AuthoredCommit` is received,  
> **and** the guard condition `DeskValidationActive(c)` holds,  
> **then** the system **MUST** transition `c` to `FACT_ACCEPTED`,  
> **and** **MUST** record the validation in `rbac_transactions`.

Where `DeskValidationActive(c)` is defined as:

```cue
DeskValidationActive: (c: emp.Commit) => 
  let principal = get_principal(c.author.email)
  let roles = get_roles(principal.id)
  let req = rbac.Request{
    principalID: principal.id,
    ref:         c.ref,
    verb:        "propose",
    trustLevel:  c.trustLevel,
    isHuman:     true
  }
  rbac.evaluate(policy_rules, req, roles)
```

> 🔔 **RFC Writing Tip**: Use **RFC 2119 keywords in bold** on first use:  
> *“The Desk **MUST** reject the commit if `DeskValidationActive(c)` evaluates to `false`.”*

---

### Step 3.2: Full EFSM Table (Normative — Section 5)

| Current State | Event | Guard (CUE predicate) | New State | Side Effects |
|---------------|-------|------------------------|-----------|--------------|
| `PROPOSED` | `AuthoredCommit` | `DeskValidationActive(c)` | `FACT_ACCEPTED` | Log `rbac_transactions(id, ..., 'ALLOW')` |
| `PROPOSED` | `Timeout` | `elapsed(c) > T_max` | `DISCARDED` | Emit `gossip: { ..., connectivity: "offline" }` |
| `FACT_ACCEPTED` | `ContradictoryCommit` | `detect_contradiction(c, c₂)` | `CONTRADICTION_DETECTED` | Freeze `c.ref`; start dispute timer |
| `DISPUTE_OPEN` | `ValidSealCommit(s)` | `verify_seal(s) ∧ s.resolution = "RETIRE"` | `FACT_RETIRED` | Append `tombstone` commit; prune ref |

Where:
- `elapsed(c)` = now − c.timestamp  
- `verify_seal(s)` = `CUE-validate(s) ∧ quorum(s) ≥ ceil(N/2)+1 ∧ ∃ signer ∈ FINALITY_ROLE`

✅ **Checkpoint 3.1**: Can you auto-generate this table from CUE?  
→ Yes: `cue cmd gen_table.cue` (we can write it).

---

## 🔄 PHASE 4: RFC INTEGRATION & PUBLISHING

### ✅ Objective
Assemble all artifacts into **IETF XML2RFC format**, with auto-synced appendices.

### Toolchain:
```text
schemas/*.cue       → Appendix A (CUE Schema)      via `cue export --out cue`
desk/ddl.sql        → Appendix B (SQL Schema)      via `cat desk/ddl.sql`
examples/*.yaml     → Appendix C (Examples)        via `yq . examples/seal.yaml`
```

### Final Structure Outline:

```markdown
1. Introduction  
2. Terminology  
   2.1. Requirements Language (RFC 2119)  
   2.2. Definitions (Fact, Ref, Desk, Seal, First-Class Human Agent)  
3. Architecture  
   3.1. Components  
   3.2. Data Flow  
4. Data Model  
   4.1. Commit Object (CUE: commit.cue)  
   4.2. Sealing Trailer (CUE: seal.cue)  
   4.3. Gossip Packet (CUE: gossip.cue)  
5. Protocol Operations  
   5.1. EFSM Overview  
   5.2. Transition Table (normative)  
   5.3. Contradiction Detection  
6. Desk RBAC Interface  
   6.1. Policy Model (YAML + CUE)  
   6.2. SQL Schema (Appendix B)  
   6.3. Authorization Algorithm  
7. Security Considerations  
8. IANA Considerations  
   - Media Type: `application/emp-commit+json`  
   - Media Type: `application/emp-seal+yaml`  
9. References  
Appendix A. CUE Schemas  
Appendix B. SQL DDL  
Appendix C. Example Workflows  
```

---

## 🚀 Next Steps: Your Action Plan

1. ✅ **Review Phase 1 CUE schemas** — do they match your intent?  
   → I’ll adjust if needed.

2. 🛠️ **Run `cue vet` on sample data** — I can generate test YAML.

3. 📝 **Pick a transition** (e.g., sealing) — let’s co-write its RFC section.

4. 🧪 **Shall we generate the TLA⁺ model next?** (for model-checking EFSM)

Let me know where you’d like to go deeper — and I’ll produce the next artifact. This is how world-class protocols get built: **iteratively, formally, and together**.