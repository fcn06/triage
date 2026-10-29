use crate::evaluator::TriageEvaluator;
use crate::models::{
    ProbationStatusRequest, RecordConfirmationRequest, RuleValidationRequest,
    RuleValidationResult, TriageRequest, TriageResponse,
};
use crate::probation_store::ProbationStore;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tracing::info;

pub struct AppState {
    pub evaluator: Arc<TriageEvaluator>,
    pub probation_store: Arc<ProbationStore>,
}

pub fn create_router(
    evaluator: Arc<TriageEvaluator>,
    probation_store: Arc<ProbationStore>,
) -> Router {
    let state = Arc::new(AppState {
        evaluator,
        probation_store,
    });

    Router::new()
        .route("/healthz", get(health_handler))
        .route("/v1/triage/evaluate", post(evaluate_handler))
        .route("/v1/triage/validate_rule", post(validate_rule_handler))
        .route(
            "/v1/triage/probation/record_confirmation",
            post(record_confirmation_handler),
        )
        .route(
            "/v1/triage/probation/check_status",
            post(check_probation_status_handler),
        )
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let swarm_ok = state.evaluator.swarm_client.check_health().await;
    let b2b_ok = state.evaluator.b2b_connector.check_b2b_status().await;

    let payload = serde_json::json!({
        "status": "healthy",
        "service": "triage_agent",
        "version": env!("CARGO_PKG_VERSION"),
        "guardrails": {
            "never_bypass_enforced": true,
            "deterministic_schema_grounding": true,
            "probationary_babysitting_enabled": true,
        },
        "dependencies": {
            "swarm_gateway_reachable": swarm_ok,
            "commercial_b2b_agent_reachable": b2b_ok,
        }
    });

    (StatusCode::OK, Json(payload))
}

async fn evaluate_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TriageRequest>,
) -> impl IntoResponse {
    info!("📥 Received triage evaluation request: {}", payload.triage_id);
    let response: TriageResponse = state.evaluator.evaluate(&payload).await;

    // Automatically register candidate rule into probation store if synthesized
    if let Some(ref candidate) = response.candidate_rule {
        state
            .probation_store
            .register_candidate(
                &candidate.name,
                candidate.probation_target,
                candidate.required_approver_quorum,
            )
            .await;
    }

    (StatusCode::OK, Json(response))
}

async fn validate_rule_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RuleValidationRequest>,
) -> impl IntoResponse {
    let result: RuleValidationResult = state
        .evaluator
        .rule_synthesizer
        .validate_rule(&payload.candidate_rule);
    (StatusCode::OK, Json(result))
}

async fn record_confirmation_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecordConfirmationRequest>,
) -> impl IntoResponse {
    info!(
        "📝 Recording probation confirmation for rule '{}' by approver '{}' (approved: {})",
        payload.rule_name, payload.approver_did, payload.approved
    );
    let response = state.probation_store.record_confirmation(payload).await;
    (StatusCode::OK, Json(response))
}

async fn check_probation_status_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProbationStatusRequest>,
) -> impl IntoResponse {
    if let Some(status) = state.probation_store.get_status(&payload.rule_name).await {
        (StatusCode::OK, Json(serde_json::to_value(status).unwrap_or_default()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Rule not found in probation store" })),
        )
    }
}
