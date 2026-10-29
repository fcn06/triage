use triage_agent::b2b_connector::CommercialB2bConnector;
use triage_agent::cognitive::SwarmClient;
use triage_agent::evaluator::TriageEvaluator;
use triage_agent::models::*;
use triage_agent::rule_synthesizer::RuleSynthesizer;

#[tokio::test]
async fn test_rule_synthesizer_allow_rule() {
    let synth = RuleSynthesizer::default();
    let req = TriageRequest {
        triage_id: "trg_test_01".to_string(),
        action_id: "act_01".to_string(),
        trace_id: "trc_01".to_string(),
        tenant_id: "default".to_string(),
        caller_did: "did:web:enterprise:worker".to_string(),
        tool_name: "query_vendor_catalog".to_string(),
        operation_kind: "read".to_string(),
        arguments: serde_json::json!({ "query": "servers" }),
        skill_manifest: None,
        call_chain_context: None,
    };

    let candidate = synth.synthesize_rule(&req, &TriageRecommendation::RecommendApprove, 0);
    assert_eq!(candidate.action, "allow");
    assert_eq!(candidate.priority, 12);
    assert_eq!(candidate.tool_names, Some(vec!["query_vendor_catalog".to_string()]));

    let validation = synth.validate_rule(&candidate);
    assert!(validation.valid);
    assert!(validation.errors.is_empty());
    assert!(validation.formatted_toml.unwrap().contains("[[rules]]"));
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
        action: "allow".to_string(),
        priority: 15,
        justification: "test".to_string(),
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
}
