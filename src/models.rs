use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub triage_id: String,
    pub action_id: String,
    pub trace_id: String,
    pub tenant_id: String,
    pub caller_did: String,
    pub tool_name: String,
    pub operation_kind: String,
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub skill_manifest: Option<serde_json::Value>,
    #[serde(default)]
    pub call_chain_context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageRecommendation {
    RecommendApprove,
    RequireHumanApproval,
    RecommendReject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    pub data_classification: String,
    pub financial_exposure_cents: u64,
    pub reversibility: String,
    pub risk_level: String, // "Low", "Medium", "High", "Critical"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageDossier {
    pub intent_summary: String,
    pub blast_radius: BlastRadius,
    pub risk_factors: Vec<String>,
    pub mitigation_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePolicyRule {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_amount_cents: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_auth_level: Option<u8>,
    pub action: String, // "allow", "require_approval", "deny"
    pub priority: i32,
    pub justification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResponse {
    pub triage_id: String,
    pub action_id: String,
    pub recommendation: TriageRecommendation,
    pub confidence_score: f64,
    pub dossier: TriageDossier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_rule: Option<CandidatePolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationRequest {
    pub candidate_rule: CandidatePolicyRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub formatted_toml: Option<String>,
}
