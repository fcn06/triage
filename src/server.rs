use crate::evaluator::TriageEvaluator;
use crate::models::{RuleValidationRequest, RuleValidationResult, TriageRequest, TriageResponse};
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
}

pub fn create_router(evaluator: Arc<TriageEvaluator>) -> Router {
    let state = Arc::new(AppState { evaluator });

    Router::new()
        .route("/healthz", get(health_handler))
        .route("/v1/triage/evaluate", post(evaluate_handler))
        .route("/v1/triage/validate_rule", post(validate_rule_handler))
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let swarm_ok = state.evaluator.swarm_client.check_health().await;
    let b2b_ok = state.evaluator.b2b_connector.check_b2b_status().await;

    let payload = serde_json::json!({
        "status": "healthy",
        "service": "triage_agent",
        "version": env!("CARGO_PKG_VERSION"),
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
