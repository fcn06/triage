# Triage Agent (`triage_agent`)

> **Autonomous Policy Triage & Candidate Rule Synthesis Agent** for the 4-Tier Enterprise Agentic Architecture.  
> Co-operating with [`commercial_b2b_agent`](../commercial_b2b_agent), powered by **Swarm Gateway** (Tier 1 Cognitive Ingress), strictly bounded by **Marketplace Trust Gateway** (Tier 2 Execution Egress), and running on port **4015**.

---

## 1. Role in the 4-Tier Topology

```text
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 4: OUTCOME ORCHESTRATOR (The Control Plane)                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 3: AUTONOMOUS WORKER AGENTS                                       │
│ • commercial_b2b_agent (:4010) — Domain Worker                         │
│ • triage_agent (:4015)         — Policy Triage & Rule Synthesis Worker │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ 1. Triage Intent               │ 2. Tool Execution Request
                    ▼                                ▼
┌───────────────────────────────────────┐ ┌──────────────────────────────┐
│ TIER 1: SWARM GATEWAY                 │ │ TIER 2: TRUST GATEWAY        │
│ (Port 8088 / 8080)                    │ │ (Port 8081)                  │
├───────────────────────────────────────┤ ├──────────────────────────────┤
│ • Model multiplexing & token control  │ │ • 4-Outcome Deterministic PEP│
│ • Cognitive structured reasoning      │ │ • Zero-trust Execution Grants│
└───────────────────────────────────────┘ └──────────────┬───────────────┘
                                                         │ (0 Rules Matched)
                                                         ▼
                                              Invoke triage_agent (:4015)
```

---

## 2. Key Responsibilities

1. **Novel Action Triage:** When Trust Gateway encounters an action matching 0 deterministic rules, `triage_agent` performs:
   - Blast radius analysis (financial exposure, mutation status, data classification).
   - Identity verification cross-referenced with `commercial_b2b_agent`.
   - Cognitive intent extraction via Swarm Gateway.
2. **Recommendation Generation:**
   - `recommend_approve`: Safe novel pattern within bounded limits.
   - `require_human_approval`: Sensitive or state-modifying action requiring HITL step-up.
   - `recommend_reject`: Hazardous, destructive, or injection-like action.
3. **Candidate Rule Synthesis:** Automatically formulates a minimal-privilege TOML rule (`[[rules]]`) ready for human sign-off and dynamic promotion into `policy.toml`.

---

## 3. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health status and upstream connectivity (Swarm & B2B Agent) |
| `POST` | `/v1/triage/evaluate` | Evaluates novel `ProposedAction` and outputs `TriageResponse` |
| `POST` | `/v1/triage/validate_rule` | Dry-run linter for candidate TOML policy rules |

---

## 4. Quickstart

### Build
```bash
make build
```

### Run
```bash
make run
```
The agent starts on `http://127.0.0.1:4015`.

### Test
```bash
make test
```

---

## 5. Invariant & Separation of Concerns

* **Zero updates to `commercial_b2b_agent`:** `triage_agent` is completely decoupled as an independent workspace while federating with `commercial_b2b_agent` over its A2A/HTTP endpoints.
* **Deterministic Rules Always Win:** `triage_agent` cannot override explicit `deny` or `require_approval` rules configured in the Trust Gateway.
