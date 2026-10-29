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
