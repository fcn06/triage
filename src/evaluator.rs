use crate::b2b_connector::CommercialB2bConnector;
use crate::cognitive::SwarmClient;
use crate::models::*;
use crate::rule_synthesizer::RuleSynthesizer;
use tracing::info;

pub struct TriageEvaluator {
    pub swarm_client: SwarmClient,
    pub b2b_connector: CommercialB2bConnector,
    pub rule_synthesizer: RuleSynthesizer,
}

impl TriageEvaluator {
    pub fn new(
        swarm_client: SwarmClient,
        b2b_connector: CommercialB2bConnector,
        rule_synthesizer: RuleSynthesizer,
    ) -> Self {
        Self {
            swarm_client,
            b2b_connector,
            rule_synthesizer,
        }
    }

    pub async fn evaluate(&self, req: &TriageRequest) -> TriageResponse {
        info!("🔎 Evaluating novel action '{}' for caller {}", req.tool_name, req.caller_did);

        let amount_cents = extract_amount_cents(&req.arguments);
        let op_kind = req.operation_kind.to_lowercase();
        let tool_lower = req.tool_name.to_lowercase();

        // 1. Check B2B context from commercial_b2b_agent
        let b2b_ctx = self
            .b2b_connector
            .query_b2b_context(&req.tenant_id, &req.caller_did, &req.tool_name)
            .await
            .unwrap_or_else(|_| crate::b2b_connector::B2bContextResponse {
                is_registered_partner: false,
                trust_tier: "Unknown".to_string(),
                active_sla: None,
            });

        // 2. Perform Blast Radius & Security Classification
        let mut risk_factors = Vec::new();
        let mut is_hazardous = false;

        // Check destructive signatures
        if op_kind == "destructive"
            || tool_lower.contains("delete")
            || tool_lower.contains("drop")
            || tool_lower.contains("purge")
            || tool_lower.contains("destroy")
        {
            is_hazardous = true;
            risk_factors.push("Action targets destructive or irreversible mutation".to_string());
        }

        // Check financial exposure
        if amount_cents > 100_000 {
            risk_factors.push(format!("High financial exposure: ${:.2}", amount_cents as f64 / 100.0));
        } else if amount_cents > 0 {
            risk_factors.push(format!("Financial mutation detected: ${:.2}", amount_cents as f64 / 100.0));
        }

        // Check caller affiliation
        if !b2b_ctx.is_registered_partner {
            risk_factors.push(format!("Caller '{}' is not a registered enterprise partner in commercial_b2b_agent registry", req.caller_did));
        }

        let (recommendation, risk_level, confidence) = if is_hazardous {
            (TriageRecommendation::RecommendReject, "Critical", 0.98)
        } else if amount_cents > 50_000 || op_kind == "write" || op_kind == "mutation" || !b2b_ctx.is_registered_partner {
            (TriageRecommendation::RequireHumanApproval, "Medium", 0.91)
        } else if op_kind == "read" && amount_cents == 0 {
            (TriageRecommendation::RecommendApprove, "Low", 0.95)
        } else {
            (TriageRecommendation::RequireHumanApproval, "Medium", 0.88)
        };

        // 3. Cognitive reasoning via Swarm Gateway if available
        let system_prompt = "You are the Enterprise Trust Triage AI Evaluator. Analyze the tool execution request and summarize intent, risks, and mitigations in JSON.";
        let user_content = format!(
            "Tool: {}\nOperation: {}\nCaller: {}\nArguments: {}\nRisk Factors: {:?}",
            req.tool_name, req.operation_kind, req.caller_did, req.arguments, risk_factors
        );

        let cognitive_intent = match self.swarm_client.complete_prompt(system_prompt, &user_content).await {
            Ok(summary) => summary,
            Err(_) => format!(
                "Action '{}' requests '{}' operation with arguments '{}'. Evaluated under expert triage heuristics.",
                req.tool_name, req.operation_kind, req.arguments
            ),
        };

        let blast_radius = BlastRadius {
            data_classification: if op_kind == "read" { "InternalRead".to_string() } else { "InternalMutation".to_string() },
            financial_exposure_cents: amount_cents,
            reversibility: if is_hazardous { "Irreversible".to_string() } else { "AuditedJournal".to_string() },
            risk_level: risk_level.to_string(),
        };

        let dossier = TriageDossier {
            intent_summary: cognitive_intent,
            blast_radius,
            risk_factors,
            mitigation_notes: match recommendation {
                TriageRecommendation::RecommendApprove => "Action verified safe for bounded execution; within automated risk limits.".to_string(),
                TriageRecommendation::RequireHumanApproval => "Human approval recommended due to state modification or partner verification boundaries.".to_string(),
                TriageRecommendation::RecommendReject => "Hazardous action detected. Recommend immediate denial.".to_string(),
            },
        };

        // 4. Synthesize candidate rule
        let candidate_rule = Some(self.rule_synthesizer.synthesize_rule(req, &recommendation, amount_cents));

        TriageResponse {
            triage_id: req.triage_id.clone(),
            action_id: req.action_id.clone(),
            recommendation,
            confidence_score: confidence,
            dossier,
            candidate_rule,
        }
    }
}

pub fn extract_amount_cents(args: &serde_json::Value) -> u64 {
    if let serde_json::Value::Object(map) = args {
        for key in &["amount_cents", "amount", "price", "cost", "total", "value"] {
            if let Some(val) = map.get(*key) {
                if let Some(n) = val.as_u64() {
                    if *key == "amount" || *key == "price" || *key == "cost" || *key == "total" || *key == "value" {
                        return n * 100;
                    }
                    return n;
                }
                if let Some(f) = val.as_f64() {
                    return (f * 100.0) as u64;
                }
            }
        }
    }
    0
}
