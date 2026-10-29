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

## 2. Key Responsibilities & Architectural Guardrails

1. **Dual-Plane Grounding (Watching the Watcher for Trust Gateway):**
   - **Plane A (Trust Gateway TCB Grounding):** Deterministic schema inspection (`schema_inspector.rs`) calculates state mutation, HTTP verbs, IAM scope impacts, and strict financial bounds independently of the LLM, guaranteeing the **Trust Gateway** PEP relies only on verifiable facts.
   - **Plane B (Advisory Context for Trust Gateway & Reviewer):** Semantic intent and contextual analysis delivered to the **Trust Gateway** approval queue (derived via cognitive reasoning), explicitly badged as untrusted advisory context strictly outside the **Trust Gateway** Trusted Computing Base (TCB).
2. **Never-Bypass Invariant:**
   - Candidate rules synthesized for novel actions **never grant direct bypass (`action = "allow"`)**.
   - All approved novel patterns emit structured escalation rules (`action = "require_approval"`) with parameter projection masks (`projected_fields`).
3. **Probationary "Babysitting" Lifecycle:**
   - Adopted rules enter a state machine (`Draft` -> `Probationary` -> `Graduated` / `Quarantined`).
   - Requires $K$ confirmations (default 5) across $\ge 2$ independent approvers before qualifying for parameter-bounded graduation.
   - A single human rejection trips an immediate quarantine tripwire.

---

## 3. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Health status, dependency connectivity, and active guardrails |
| `POST` | `/v1/triage/evaluate` | Evaluates novel `ProposedAction` and outputs Dual-Plane `TriageResponse` |
| `POST` | `/v1/triage/validate_rule` | Dry-run linter enforcing never-bypass and safety constraints |
| `POST` | `/v1/triage/probation/record_confirmation` | Records human confirmation/rejection, tracking quorum & graduation |
| `POST` | `/v1/triage/probation/check_status` | Queries probation progress, unique approvers, and lifecycle status |

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
