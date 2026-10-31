use triage_agent::b2b_connector::CommercialB2bConnector;
use triage_agent::cognitive::SwarmClient;
use triage_agent::evaluator::TriageEvaluator;
use triage_agent::models::*;
use triage_agent::probation_store::ProbationStore;
use triage_agent::rule_synthesizer::RuleSynthesizer;

#[tokio::test]
async fn test_rule_synthesizer_never_allows_direct_bypass() {
    let synth = RuleSynthesizer::default();
    let req = TriageRequest {
        triage_id: "trg_test_01".to_string(),
        action_id: "act_01".to_string(),
        trace_id: "trc_01".to_string(),
        tenant_id: "default".to_string(),
        caller_did: "did:web:enterprise:worker".to_string(),
        tool_name: "query_vendor_catalog".to_string(),
        operation_kind: "read".to_string(),
        arguments: serde_json::json!({ "query": "servers", "category": "it" }),
        skill_manifest: None,
        call_chain_context: None,
    };

    // Even for RecommendApprove, candidate rule MUST be require_approval with Probationary lifecycle
    let candidate = synth.synthesize_rule(
        &req,
        &TriageRecommendation::RecommendApprove,
        0,
        vec!["category".to_string(), "query".to_string()],
    );

    assert_eq!(candidate.action, "require_approval");
    assert_eq!(candidate.lifecycle_state, RuleLifecycleState::Probationary);
    assert_eq!(candidate.probation_target, 5);
    assert_eq!(candidate.confirmations_count, 0);
    assert_eq!(candidate.required_approver_quorum, 2);
    assert_eq!(candidate.priority, 15);
    assert_eq!(candidate.tool_names, Some(vec!["query_vendor_catalog".to_string()]));
    assert!(candidate.projected_fields.contains(&"category".to_string()));

    let validation = synth.validate_rule(&candidate);
    assert!(validation.valid);
    assert!(validation.errors.is_empty());
    let toml = validation.formatted_toml.unwrap();
    assert!(toml.contains("lifecycle_state = \"probationary\""));
    assert!(toml.contains("probation_target = 5"));
    assert!(toml.contains("action = \"require_approval\""));
}

#[tokio::test]
async fn test_rule_synthesizer_rejects_synthetic_allow() {
    let synth = RuleSynthesizer::default();
    let candidate = CandidatePolicyRule {
        name: "Illegal allow rule".to_string(),
        tool_names: Some(vec!["safe_query".to_string()]),
        operation_kind: Some("read".to_string()),
        min_amount_cents: None,
        min_auth_level: Some(3),
        action: "allow".to_string(), // VIOLATION
        priority: 15,
        justification: "test".to_string(),
        lifecycle_state: RuleLifecycleState::Draft,
        probation_target: 5,
        confirmations_count: 0,
        required_approver_quorum: 2,
        projected_fields: vec![],
        escalation_role: None,
    };

    let validation = synth.validate_rule(&candidate);
    assert!(!validation.valid);
    assert!(validation
        .errors
        .iter()
        .any(|e| e.contains("Security Invariant Violation") && e.contains("cannot grant direct bypass")));
}

#[tokio::test]
async fn test_rule_synthesizer_disallow_wildcards() {
    let synth = RuleSynthesizer::default();
    let mut candidate = CandidatePolicyRule {
        name: "Illegal wildcard rule".to_string(),
        tool_names: Some(vec!["*".to_string()]),
        operation_kind: Some("write".to_string()),
        min_amount_cents: None,
        min_auth_level: Some(3),
        action: "require_approval".to_string(),
        priority: 15,
        justification: "test".to_string(),
        lifecycle_state: RuleLifecycleState::Probationary,
        probation_target: 5,
        confirmations_count: 0,
        required_approver_quorum: 2,
        projected_fields: vec![],
        escalation_role: None,
    };

    let validation = synth.validate_rule(&candidate);
    assert!(!validation.valid);
    assert!(validation.errors.iter().any(|e| e.contains("Wildcard")));

    // Priority out of bounds
    candidate.tool_names = Some(vec!["safe_tool".to_string()]);
    candidate.priority = 99; // Above max priority 19
    let validation2 = synth.validate_rule(&candidate);
    assert!(!validation2.valid);
    assert!(validation2.errors.iter().any(|e| e.contains("out of allowed range")));
}

#[tokio::test]
async fn test_evaluator_hazardous_action() {
    let swarm = SwarmClient::new("http://127.0.0.1:8080", "test-model", None);
    let b2b = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:web:b2b");
    let synth = RuleSynthesizer::default();
    let evaluator = TriageEvaluator::new(swarm, b2b, synth);

    let req = TriageRequest {
        triage_id: "trg_hazard".to_string(),
        action_id: "act_hazard".to_string(),
        trace_id: "trc_hazard".to_string(),
        tenant_id: "default".to_string(),
        caller_did: "did:web:unknown".to_string(),
        tool_name: "purge_database_tables".to_string(),
        operation_kind: "destructive".to_string(),
        arguments: serde_json::json!({ "target": "all" }),
        skill_manifest: None,
        call_chain_context: None,
    };

    let response = evaluator.evaluate(&req).await;
    assert_eq!(response.recommendation, TriageRecommendation::RecommendReject);
    assert_eq!(response.dossier.blast_radius.risk_level, "Critical");
    assert!(response.dossier.deterministic_metrics.is_mutation);
    assert_eq!(response.dossier.deterministic_metrics.reversibility, "Irreversible");
    assert_eq!(
        response.candidate_rule.unwrap().action,
        "deny"
    );
}

#[tokio::test]
async fn test_dual_plane_grounding_and_projected_fields() {
    let swarm = SwarmClient::new("http://127.0.0.1:8080", "test-model", None);
    let b2b = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:web:b2b");
    let synth = RuleSynthesizer::default();
    let evaluator = TriageEvaluator::new(swarm, b2b, synth);

    let req = TriageRequest {
        triage_id: "trg_amend".to_string(),
        action_id: "act_amend".to_string(),
        trace_id: "trc_amend".to_string(),
        tenant_id: "default".to_string(),
        caller_did: "did:web:enterprise:buyer".to_string(),
        tool_name: "vendor_contract_amendment".to_string(),
        operation_kind: "mutation".to_string(),
        arguments: serde_json::json!({
            "vendor_id": "V-2210",
            "change": "extend_term",
            "months": 12,
            "amount": 2500.00
        }),
        skill_manifest: None,
        call_chain_context: None,
    };

    let response = evaluator.evaluate(&req).await;
    assert_eq!(response.recommendation, TriageRecommendation::RequireHumanApproval);

    // Plane A: Deterministic Facts
    let plane_a = &response.dossier.deterministic_metrics;
    assert!(plane_a.is_mutation);
    assert_eq!(plane_a.financial_exposure_cents, 250000);
    assert!(plane_a.touched_iam_scopes.contains(&"contracts:manage".to_string()));
    assert!(plane_a.touched_iam_scopes.contains(&"finance:disburse".to_string()));
    assert!(plane_a.projected_fields.contains(&"vendor_id".to_string()));
    assert!(plane_a.projected_fields.contains(&"months".to_string()));

    // Plane B: Cognitive Advisory
    let plane_b = &response.dossier.cognitive_advisory;
    assert!(plane_b.advisory_notice.contains("outside the Trusted Computing Base"));

    // Candidate Rule: Must NOT be allow
    let candidate = response.candidate_rule.unwrap();
    assert_eq!(candidate.action, "require_approval");
    assert_eq!(candidate.lifecycle_state, RuleLifecycleState::Probationary);
    assert_eq!(candidate.min_amount_cents, Some(250000));
    assert!(candidate.projected_fields.contains(&"vendor_id".to_string()));
}

#[tokio::test]
async fn test_probation_lifecycle_quorum_and_graduation() {
    let store = ProbationStore::new();
    let rule_name = "Auto-synthesized: require_approval for 'test_tool'";
    store.register_candidate(rule_name, 5, 2).await;

    // Confirmations 1 to 4 by user_A only -> Not graduated yet
    for i in 1..=4 {
        let resp = store
            .record_confirmation(RecordConfirmationRequest {
                rule_name: rule_name.to_string(),
                approver_did: "did:web:reviewer_alpha".to_string(),
                caller_did: format!("did:web:caller_{}", i),
                action_id: format!("act_{}", i),
                trace_id: format!("trc_{}", i),
                approved: true,
                rejection_reason: None,
            })
            .await;
        assert_eq!(resp.lifecycle_state, RuleLifecycleState::Probationary);
        assert!(!resp.graduated);
        assert!(!resp.quorum_satisfied); // Only 1 distinct approver
    }

    // Confirmation 5 by user_A -> Hit target 5, but quorum (2 approvers) still not satisfied!
    let resp5 = store
        .record_confirmation(RecordConfirmationRequest {
            rule_name: rule_name.to_string(),
            approver_did: "did:web:reviewer_alpha".to_string(),
            caller_did: "did:web:caller_5".to_string(),
            action_id: "act_5".to_string(),
            trace_id: "trc_5".to_string(),
            approved: true,
            rejection_reason: None,
        })
        .await;
    assert_eq!(resp5.lifecycle_state, RuleLifecycleState::Probationary);
    assert!(!resp5.graduated);
    assert!(!resp5.quorum_satisfied);

    // Confirmation 6 by a DIFFERENT approver user_B -> Quorum satisfied, rule graduates!
    let resp6 = store
        .record_confirmation(RecordConfirmationRequest {
            rule_name: rule_name.to_string(),
            approver_did: "did:web:reviewer_beta".to_string(),
            caller_did: "did:web:caller_6".to_string(),
            action_id: "act_6".to_string(),
            trace_id: "trc_6".to_string(),
            approved: true,
            rejection_reason: None,
        })
        .await;
    assert_eq!(resp6.lifecycle_state, RuleLifecycleState::Graduated);
    assert!(resp6.graduated);
    assert!(resp6.quorum_satisfied);

    // Tripwire test: A rejection on another rule quarantines immediately
    let rule_name_2 = "Auto-synthesized: require_approval for 'risky_tool'";
    store.register_candidate(rule_name_2, 5, 2).await;

    let reject_resp = store
        .record_confirmation(RecordConfirmationRequest {
            rule_name: rule_name_2.to_string(),
            approver_did: "did:web:security_officer".to_string(),
            caller_did: "did:web:caller_x".to_string(),
            action_id: "act_x".to_string(),
            trace_id: "trc_x".to_string(),
            approved: false,
            rejection_reason: Some("Discovered unauthorized payload drift".to_string()),
        })
        .await;
    assert_eq!(reject_resp.lifecycle_state, RuleLifecycleState::Quarantined);
    assert!(reject_resp.quarantined);
}

#[tokio::test]
async fn test_probation_store_restart_preserves_quarantined_state() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("probation_test_restart_{}.db", uuid::Uuid::new_v4()));

    // 1. First run: register rule and tripwire into Quarantined
    {
        let store = ProbationStore::open(&db_path).expect("Failed to open SQLite store");
        let rule_name = "synthesized_rule_for_restart_test";
        store.register_candidate(rule_name, 5, 2).await;

        let reject_resp = store
            .record_confirmation(RecordConfirmationRequest {
                rule_name: rule_name.to_string(),
                approver_did: "did:web:security_officer".to_string(),
                caller_did: "did:web:caller_01".to_string(),
                action_id: "act_restart_01".to_string(),
                trace_id: "trc_restart_01".to_string(),
                approved: false,
                rejection_reason: Some("Manual security veto".to_string()),
            })
            .await;
        assert_eq!(reject_resp.lifecycle_state, RuleLifecycleState::Quarantined);

        let status = store.get_status(rule_name).await.expect("Status must exist");
        assert_eq!(status.lifecycle_state, RuleLifecycleState::Quarantined);
    } // store dropped (simulating daemon restart)

    // 2. Second run: reopen DB and verify Quarantined state persisted across restart (OB-INV-08)
    {
        let store_restarted = ProbationStore::open(&db_path).expect("Failed to reopen SQLite store");
        let rule_name = "synthesized_rule_for_restart_test";
        let status = store_restarted.get_status(rule_name).await.expect("Status must exist after restart");
        assert_eq!(status.lifecycle_state, RuleLifecycleState::Quarantined);
    }

    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn test_probation_store_deleted_file_fails_closed_to_quarantined() {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("probation_test_failclosed_{}.db", uuid::Uuid::new_v4()));

    let store = ProbationStore::open(&db_path).expect("Failed to open SQLite store");
    let rule_name = "synthesized_rule_for_failclosed_test";
    store.register_candidate(rule_name, 5, 2).await;

    // Delete the database file from disk while store is active
    let _ = std::fs::remove_file(&db_path);
    assert!(!db_path.exists());

    // When store file is missing, query MUST fail closed to Quarantined (OB-INV-08)
    let status = store.get_status(rule_name).await.expect("Fail-closed response must exist");
    assert_eq!(status.lifecycle_state, RuleLifecycleState::Quarantined);

    let unknown_status = store.get_status("any_unknown_rule").await.expect("Fail-closed response for unknown must exist");
    assert_eq!(unknown_status.lifecycle_state, RuleLifecycleState::Quarantined);

    let confirm_resp = store
        .record_confirmation(RecordConfirmationRequest {
            rule_name: rule_name.to_string(),
            approver_did: "did:web:security_officer".to_string(),
            caller_did: "did:web:caller_02".to_string(),
            action_id: "act_fc_01".to_string(),
            trace_id: "trc_fc_01".to_string(),
            approved: true,
            rejection_reason: None,
        })
        .await;
    assert_eq!(confirm_resp.lifecycle_state, RuleLifecycleState::Quarantined);
    assert!(confirm_resp.quarantined);
}

#[tokio::test]
async fn test_server_healthz_remains_open_without_auth() {
    use std::sync::Arc;
    use tower::ServiceExt;

    let swarm_client = SwarmClient::new("http://127.0.0.1:8088", "test", None);
    let b2b_connector = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:twin:test");
    let evaluator = Arc::new(TriageEvaluator::new(swarm_client, b2b_connector, RuleSynthesizer::default()));
    let store = Arc::new(ProbationStore::new());
    let router = triage_agent::server::create_router(evaluator, store);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_server_unauthenticated_call_returns_401() {
    use std::sync::Arc;
    use tower::ServiceExt;

    let swarm_client = SwarmClient::new("http://127.0.0.1:8088", "test", None);
    let b2b_connector = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:twin:test");
    let evaluator = Arc::new(TriageEvaluator::new(swarm_client, b2b_connector, RuleSynthesizer::default()));
    let store = Arc::new(ProbationStore::new());
    let router = triage_agent::server::create_router(evaluator, store);

    // Call without X-Service-Envelope header -> must return 401
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/triage/probation/check_status")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{\"rule_name\": \"test_rule\"}"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_server_wrong_audience_returns_403() {
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tower::ServiceExt;
    use trust_sdk::envelope::ServiceRequestEnvelope;

    let seed = [11u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let identity = trust_sdk::did::create_did_key_from_seed(seed);

    let swarm_client = SwarmClient::new("http://127.0.0.1:8088", "test", None);
    let b2b_connector = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:twin:test");
    let evaluator = Arc::new(TriageEvaluator::new(swarm_client, b2b_connector, RuleSynthesizer::default()));
    let store = Arc::new(ProbationStore::new());
    let router = triage_agent::server::create_router_with_audience(evaluator, store, "http://127.0.0.1:4015");

    let body_bytes = b"{\"rule_name\": \"test_rule\"}";
    let body_hash = format!("{:x}", Sha256::digest(body_bytes));
    let now = chrono::Utc::now().timestamp() as u64;

    let mut envelope = ServiceRequestEnvelope::new(
        &identity.did,
        "http://wrong-audience.internal", // Mismatch audience!
        "POST",
        "/v1/triage/probation/check_status",
        &body_hash,
        now,
        now + 25,
        "jti_aud_test_01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )
    .unwrap();
    envelope.sign(&signing_key);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/triage/probation/check_status")
        .header("content-type", "application/json")
        .header("x-service-envelope", serde_json::to_string(&envelope).unwrap())
        .body(axum::body::Body::from(body_bytes.to_vec()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_server_replayed_envelope_returns_409() {
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tower::ServiceExt;
    use trust_sdk::envelope::ServiceRequestEnvelope;

    let seed = [22u8; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let identity = trust_sdk::did::create_did_key_from_seed(seed);

    let swarm_client = SwarmClient::new("http://127.0.0.1:8088", "test", None);
    let b2b_connector = CommercialB2bConnector::new("http://127.0.0.1:4010", "did:twin:test");
    let evaluator = Arc::new(TriageEvaluator::new(swarm_client, b2b_connector, RuleSynthesizer::default()));
    let store = Arc::new(ProbationStore::new());
    let router = triage_agent::server::create_router_with_audience(evaluator, store, "http://127.0.0.1:4015");

    let body_bytes = b"{\"rule_name\": \"test_rule\"}";
    let body_hash = format!("{:x}", Sha256::digest(body_bytes));
    let now = chrono::Utc::now().timestamp() as u64;

    let mut envelope = ServiceRequestEnvelope::new(
        &identity.did,
        "http://127.0.0.1:4015",
        "POST",
        "/v1/triage/probation/check_status",
        &body_hash,
        now,
        now + 25,
        "jti_replay_test_01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )
    .unwrap();
    envelope.sign(&signing_key);
    let env_json = serde_json::to_string(&envelope).unwrap();

    // First call: authenticated, passes auth layer (not found since rule not registered, but passes auth)
    let req1 = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/triage/probation/check_status")
        .header("content-type", "application/json")
        .header("x-service-envelope", env_json.clone())
        .body(axum::body::Body::from(body_bytes.to_vec()))
        .unwrap();

    let resp1 = router.clone().oneshot(req1).await.unwrap();
    assert_ne!(resp1.status(), axum::http::StatusCode::UNAUTHORIZED);
    assert_ne!(resp1.status(), axum::http::StatusCode::FORBIDDEN);
    assert_ne!(resp1.status(), axum::http::StatusCode::CONFLICT);

    // Second call with EXACT same envelope (same jti) -> must return 409 Conflict
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/triage/probation/check_status")
        .header("content-type", "application/json")
        .header("x-service-envelope", env_json)
        .body(axum::body::Body::from(body_bytes.to_vec()))
        .unwrap();

    let resp2 = router.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), axum::http::StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_drift_deduplication_and_candidate_amendment() {
    let store = ProbationStore::new();

    let details = serde_json::json!({
        "mismatched_field": "currency",
        "expected": "USD",
        "actual": "EUR"
    });
    let fingerprint = "fp_drift_currency_eur_001";

    // 1st drift occurrence
    let resp1 = store
        .record_drift("stripe_create_charge", fingerprint, &details)
        .expect("record drift 1 failed");
    assert_eq!(resp1.occurrence_count, 1);
    assert!(!resp1.deduplicated);
    assert!(resp1.candidate_amendment.is_none());

    // 2nd drift occurrence (deduplicated)
    let resp2 = store
        .record_drift("stripe_create_charge", fingerprint, &details)
        .expect("record drift 2 failed");
    assert_eq!(resp2.occurrence_count, 2);
    assert!(resp2.deduplicated);
    assert_eq!(resp2.drift_id, resp1.drift_id);
    assert!(resp2.candidate_amendment.is_none());

    // 3rd drift occurrence (threshold reached -> auto-synthesizes candidate amendment)
    let resp3 = store
        .record_drift("stripe_create_charge", fingerprint, &details)
        .expect("record drift 3 failed");
    assert_eq!(resp3.occurrence_count, 3);
    assert!(resp3.deduplicated);
    assert_eq!(resp3.drift_id, resp1.drift_id);
    assert!(resp3.candidate_amendment.is_some());
    let amendment = resp3.candidate_amendment.unwrap();
    assert!(amendment.contains("Auto-generated drift rule for stripe_create_charge"));
    assert!(amendment.contains("action = \"require_approval\""));
}

#[tokio::test]
async fn test_policy_promotion_quorum_signature_flow() {
    use ed25519_dalek::Signer;

    let store = ProbationStore::new();
    let rule_name = "probationary_api_rule";
    store.register_candidate(rule_name, 5, 2).await;

    // 1. Create or get promotion
    let promo = store
        .create_or_get_promotion(rule_name)
        .expect("create promotion failed");
    assert_eq!(promo.status, "pending_signatures");
    assert_eq!(promo.required_signatures, 2);
    assert_eq!(promo.signatures.len(), 0);

    // 2. Setup Signer 1 and Signer 2
    let seed1 = [51u8; 32];
    let key1 = ed25519_dalek::SigningKey::from_bytes(&seed1);
    let identity1 = trust_sdk::did::create_did_key_from_seed(seed1);

    let seed2 = [52u8; 32];
    let key2 = ed25519_dalek::SigningKey::from_bytes(&seed2);
    let identity2 = trust_sdk::did::create_did_key_from_seed(seed2);

    let sig1 = key1.sign(promo.canonical_hash.as_bytes());
    let sig1_hex = hex::encode(sig1.to_bytes());

    // 3. Submit first signature
    let sig_req_1 = SubmitPromotionSignatureRequest {
        promotion_id: promo.promotion_id.clone(),
        signer_did: identity1.did.clone(),
        signature_hex: sig1_hex.clone(),
    };
    let res1 = store
        .submit_promotion_signature(&sig_req_1)
        .expect("submit sig1 failed");
    assert_eq!(res1.status, "pending_signatures");
    assert_eq!(res1.signatures_count, 1);

    // 4. Negative test: Signer 1 attempts to sign again (replay / duplicate signer)
    let dup_res = store.submit_promotion_signature(&sig_req_1);
    assert!(dup_res.is_err());
    let err_msg = dup_res.unwrap_err().to_string();
    assert!(err_msg.contains("already signed this promotion"));

    // 5. Submit second signature by distinct approver
    let sig2 = key2.sign(promo.canonical_hash.as_bytes());
    let sig2_hex = hex::encode(sig2.to_bytes());

    let sig_req_2 = SubmitPromotionSignatureRequest {
        promotion_id: promo.promotion_id.clone(),
        signer_did: identity2.did.clone(),
        signature_hex: sig2_hex,
    };
    let res2 = store
        .submit_promotion_signature(&sig_req_2)
        .expect("submit sig2 failed");
    assert_eq!(res2.status, "promoted");
    assert_eq!(res2.signatures_count, 2);

    // 6. Verify rule has now graduated in the probation store
    let status = store.get_status(rule_name).await.expect("status must exist");
    assert_eq!(status.lifecycle_state, RuleLifecycleState::Graduated);
}
