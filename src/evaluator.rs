use crate::b2b_connector::CommercialB2bConnector;
use crate::cognitive::SwarmClient;
use crate::models::*;
use crate::rule_synthesizer::RuleSynthesizer;
use crate::schema_inspector::SchemaInspector;
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

        // 1. DETERMINISTIC PLANE A: Schema & Mutation Grounding (TCB)
        // Calculated deterministically before any cognitive models are invoked.
        let deterministic_metrics = SchemaInspector::inspect(
            &req.tool_name,
            &req.operation_kind,
            &req.arguments,
            req.skill_manifest.as_ref(),
        );

        // 2. Query B2B Context from Commercial B2B Agent
        let b2b_ctx = self
            .b2b_connector
            .query_b2b_context(&req.tenant_id, &req.caller_did, &req.tool_name)
            .await
            .unwrap_or_else(|_| crate::b2b_connector::B2bContextResponse {
                is_registered_partner: false,
                trust_tier: "Unknown".to_string(),
                active_sla: None,
            });

        // 3. Grounded Risk & Recommendation Synthesis
        let mut risk_factors = Vec::new();
        if deterministic_metrics.risk_classification == "Critical" {
            risk_factors.push("Action targets destructive or irreversible mutation".to_string());
        }
        if deterministic_metrics.financial_indeterminate {
            risk_factors.push("Financial parameters are indeterminate or ambiguous".to_string());
        } else if deterministic_metrics.financial_exposure_cents > 100_000 {
            risk_factors.push(format!(
                "High financial exposure: ${:.2}",
                deterministic_metrics.financial_exposure_cents as f64 / 100.0
            ));
        } else if deterministic_metrics.financial_exposure_cents > 0 {
            risk_factors.push(format!(
                "Financial mutation detected: ${:.2}",
                deterministic_metrics.financial_exposure_cents as f64 / 100.0
            ));
        }
        if !b2b_ctx.is_registered_partner {
            risk_factors.push(format!(
                "Caller '{}' is not a registered enterprise partner in commercial_b2b_agent registry",
                req.caller_did
            ));
        }

        let (recommendation, confidence) = if deterministic_metrics.risk_classification == "Critical" {
            (TriageRecommendation::RecommendReject, 0.99)
        } else if deterministic_metrics.is_mutation
            || deterministic_metrics.financial_exposure_cents > 0
            || deterministic_metrics.financial_indeterminate
            || !b2b_ctx.is_registered_partner
        {
            (TriageRecommendation::RequireHumanApproval, 0.92)
        } else if !deterministic_metrics.is_mutation
            && deterministic_metrics.financial_exposure_cents == 0
            && b2b_ctx.is_registered_partner
        {
            (TriageRecommendation::RecommendApprove, 0.95)
        } else {
            (TriageRecommendation::RequireHumanApproval, 0.88)
        };

        // 4. COGNITIVE PLANE B: Advisory Semantic Context (Non-TCB)
        let system_prompt = "You are the Enterprise Trust Triage AI Evaluator. Analyze the tool execution request and summarize intent, risks, and mitigations in JSON.";
        let user_content = format!(
            "Tool: {}\nOperation: {}\nCaller: {}\nArguments: {}\nDeterministic Metrics: {:?}\nRisk Factors: {:?}",
            req.tool_name, req.operation_kind, req.caller_did, req.arguments, deterministic_metrics, risk_factors
        );

        let cognitive_intent = match self.swarm_client.complete_prompt(system_prompt, &user_content).await {
            Ok(summary) => summary,
            Err(_) => format!(
                "Action '{}' requests '{}' operation with arguments '{}'. Grounded under deterministic schema rules.",
                req.tool_name, req.operation_kind, req.arguments
            ),
        };

        let cognitive_advisory = CognitiveAdvisory {
            intent_summary: cognitive_intent.clone(),
            risk_factors: risk_factors.clone(),
            mitigation_notes: match recommendation {
                TriageRecommendation::RecommendApprove => "Action verified read-only and within bounded limits. Rule enters probation with mandatory initial approvals.".to_string(),
                TriageRecommendation::RequireHumanApproval => "Human approval required: state modification, financial impact, or unverified caller.".to_string(),
                TriageRecommendation::RecommendReject => "Critical hazardous action detected. Recommend immediate denial.".to_string(),
            },
            advisory_notice: "Plane B Advisory Context: strictly outside the Trusted Computing Base (TCB). Blast radius is grounded by Plane A deterministic schema verification.".to_string(),
        };

        let blast_radius = BlastRadius {
            data_classification: if deterministic_metrics.is_mutation {
                "InternalMutation".to_string()
            } else {
                "InternalRead".to_string()
            },
            financial_exposure_cents: deterministic_metrics.financial_exposure_cents,
            reversibility: deterministic_metrics.reversibility.clone(),
            risk_level: deterministic_metrics.risk_classification.clone(),
        };

        let dossier = TriageDossier {
            deterministic_metrics: deterministic_metrics.clone(),
            cognitive_advisory: cognitive_advisory.clone(),
            intent_summary: cognitive_intent,
            blast_radius,
            risk_factors,
            mitigation_notes: cognitive_advisory.mitigation_notes,
        };

        // 5. Synthesize candidate rule (Enforces Non-Bypass & Probationary Lifecycle)
        let candidate_rule = Some(self.rule_synthesizer.synthesize_rule(
            req,
            &recommendation,
            deterministic_metrics.financial_exposure_cents,
            deterministic_metrics.projected_fields,
        ));

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
