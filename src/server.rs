use crate::evaluator::TriageEvaluator;
use crate::models::{
    ProbationStatusRequest, RecordConfirmationRequest, RecordDriftRequest,
    RuleValidationRequest, RuleValidationResult, SubmitPromotionSignatureRequest,
    TriageRequest, TriageResponse,
};
use crate::probation_store::ProbationStore;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use trust_sdk::envelope::ServiceRequestEnvelope;

pub struct AppState {
    pub evaluator: Arc<TriageEvaluator>,
    pub probation_store: Arc<ProbationStore>,
    pub nonces: Arc<RwLock<HashMap<String, i64>>>,
    pub expected_audience: String,
}

pub fn create_router(
    evaluator: Arc<TriageEvaluator>,
    probation_store: Arc<ProbationStore>,
) -> Router {
    create_router_with_audience(evaluator, probation_store, "http://127.0.0.1:4015")
}

pub fn create_router_with_audience(
    evaluator: Arc<TriageEvaluator>,
    probation_store: Arc<ProbationStore>,
    expected_audience: impl Into<String>,
) -> Router {
    let state = Arc::new(AppState {
        evaluator,
        probation_store,
        nonces: Arc::new(RwLock::new(HashMap::new())),
        expected_audience: expected_audience.into(),
    });

    let triage_routes = Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/validate_rule", post(validate_rule_handler))
        .route(
            "/probation/record_confirmation",
            post(record_confirmation_handler),
        )
        .route(
            "/probation/check_status",
            post(check_probation_status_handler),
        )
        .route("/drift/record", post(record_drift_handler))
        .route("/probation/promote", post(promote_handler))
        .route("/probation/sign_promotion", post(sign_promotion_handler))
        .layer(from_fn_with_state(state.clone(), envelope_auth_middleware));

    Router::new()
        .route("/healthz", get(health_handler))
        .nest("/v1/triage", triage_routes)
        .with_state(state)
}

/// Zero-Trust Inter-Tier Service Request Envelope Verification Middleware (OB-INV-07, OB-INV-11)
async fn envelope_auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract envelope header (X-Service-Envelope)
    let env_header = req
        .headers()
        .get("x-service-envelope")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let envelope: ServiceRequestEnvelope =
        serde_json::from_str(env_header).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // 2. Read request body bytes to verify integrity
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // 3. Audience check
    let expected = state.expected_audience.trim_end_matches('/');
    let actual = envelope.audience.trim_end_matches('/');
    if actual != expected && actual != "triage_agent" && !actual.ends_with(":4015") {
        return Err(StatusCode::FORBIDDEN);
    }

    // 4. Freshness & TTL check (OB-INV-07: max 30s TTL, 5s clock skew grace)
    let now = chrono::Utc::now().timestamp() as u64;
    if now + 5 < envelope.iat || now > envelope.exp + 5 || envelope.exp.saturating_sub(envelope.iat) > 30 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 5. Body SHA-256 integrity check
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let computed_hash = format!("{:x}", hasher.finalize());
    if computed_hash != envelope.body_sha256.to_lowercase() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 6. Replay protection (consume nonce)
    let nonce_key = format!("{}_{}", envelope.caller_did, envelope.jti);
    {
        let mut nonces = state.nonces.write().await;
        if let Some(&exp) = nonces.get(&nonce_key) {
            if (now as i64) < exp {
                return Err(StatusCode::CONFLICT);
            }
        }
        nonces.insert(nonce_key, (now + 30) as i64);
    }

    // 7. Verify Ed25519 signature
    let pubkey_bytes = if envelope.caller_did.starts_with("did:key:") {
        trust_sdk::did::extract_did_key_ed25519_pubkey(&envelope.caller_did)
            .map_err(|_| StatusCode::UNAUTHORIZED)?
    } else if envelope.caller_did.starts_with("did:twin:") {
        trust_sdk::did::extract_did_twin_ed25519_pubkey(&envelope.caller_did)
            .map_err(|_| StatusCode::UNAUTHORIZED)?
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    envelope
        .verify_signature(&verifying_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Reconstruct request and forward down the pipeline
    let reconstructed_req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    Ok(next.run(reconstructed_req).await)
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
            "authenticated_service_mesh": true,
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

async fn record_drift_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RecordDriftRequest>,
) -> impl IntoResponse {
    match state.probation_store.record_drift(&payload.tool_name, &payload.diff_fingerprint, &payload.details) {
        Ok(res) => (StatusCode::OK, Json(serde_json::to_value(res).unwrap_or_default())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

#[derive(serde::Deserialize)]
pub struct PromoteRequest {
    pub rule_name: String,
}

async fn promote_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<PromoteRequest>,
) -> impl IntoResponse {
    match state.probation_store.create_or_get_promotion(&payload.rule_name) {
        Ok(res) => (StatusCode::OK, Json(serde_json::to_value(res).unwrap_or_default())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn sign_promotion_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SubmitPromotionSignatureRequest>,
) -> impl IntoResponse {
    match state.probation_store.submit_promotion_signature(&payload) {
        Ok(res) => (StatusCode::OK, Json(serde_json::to_value(res).unwrap_or_default())).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}
