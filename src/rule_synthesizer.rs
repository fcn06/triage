use crate::models::{
    CandidatePolicyRule, RuleLifecycleState, RuleValidationResult, TriageRecommendation,
    TriageRequest,
};

pub struct RuleSynthesizer {
    pub min_priority: i32,
    pub max_priority: i32,
}

impl Default for RuleSynthesizer {
    fn default() -> Self {
        Self {
            min_priority: 11,
            max_priority: 19,
        }
    }
}

impl RuleSynthesizer {
    pub fn synthesize_rule(
        &self,
        req: &TriageRequest,
        recommendation: &TriageRecommendation,
        extracted_amount: u64,
        projected_fields: Vec<String>,
    ) -> CandidatePolicyRule {
        // STRUCTURAL INVARIANT: Candidate rules NEVER grant direct bypass ("allow").
        // Even when triage assesses the novel action as RecommendApprove, the rule MUST enter
        // the policy as "require_approval" under Probationary babysitting mode.
        let (action_str, priority, lifecycle, justification) = match recommendation {
            TriageRecommendation::RecommendApprove => (
                "require_approval".to_string(),
                15,
                RuleLifecycleState::Probationary,
                format!(
                    "Candidate rule under Probationary Babysitting: Requires 5 verified approvals before parameter-bounded graduation. Triage ID: {}",
                    req.triage_id
                ),
            ),
            TriageRecommendation::RequireHumanApproval => (
                "require_approval".to_string(),
                15,
                RuleLifecycleState::Probationary,
                format!(
                    "Synthesized structured escalation rule requiring HITL verification for caller {}. Triage ID: {}",
                    req.caller_did, req.triage_id
                ),
            ),
            TriageRecommendation::RecommendReject => (
                "deny".to_string(),
                18,
                RuleLifecycleState::Draft,
                format!(
                    "Candidate deny rule for hazardous/destructive novel pattern. Triage ID: {}",
                    req.triage_id
                ),
            ),
        };

        let min_amount = if extracted_amount > 0 {
            Some(extracted_amount)
        } else {
            None
        };

        let clean_tool_name = req.tool_name.trim().to_string();
        let name = format!(
            "Auto-synthesized: {} for '{}'",
            action_str, clean_tool_name
        );

        CandidatePolicyRule {
            name,
            tool_names: Some(vec![clean_tool_name]),
            operation_kind: Some(req.operation_kind.clone()),
            min_amount_cents: min_amount,
            min_auth_level: Some(3),
            action: action_str,
            priority,
            justification,
            lifecycle_state: lifecycle,
            probation_target: 5,
            confirmations_count: 0,
            required_approver_quorum: 2,
            projected_fields,
            escalation_role: Some("security_reviewer".to_string()),
        }
    }

    pub fn validate_rule(&self, rule: &CandidatePolicyRule) -> RuleValidationResult {
        let mut errors = Vec::new();

        // 1. Tool name safety
        if let Some(ref tools) = rule.tool_names {
            if tools.is_empty() {
                errors.push("tool_names cannot be empty".to_string());
            }
            for tool in tools {
                if tool == "*" || tool.contains('%') || tool.contains('$') {
                    errors.push(format!("Wildcard or illegal characters forbidden in tool name: '{tool}'"));
                }
            }
        } else {
            errors.push("Explicit tool_names required for synthesized rules".to_string());
        }

        // 2. Structural Invariant: NEVER allow direct bypass
        let act = rule.action.to_lowercase();
        if act == "allow" {
            errors.push(
                "Security Invariant Violation: Candidate rules synthesized from meta-level triage cannot grant direct bypass ('allow'). Novel actions must enter 'require_approval' under probationary babysitting mode.".to_string(),
            );
        } else if act != "require_approval" && act != "deny" {
            errors.push(format!(
                "Invalid synthetic action '{}', must be 'require_approval' or 'deny'",
                rule.action
            ));
        }

        // 3. Priority bounds
        if rule.priority < self.min_priority || rule.priority > self.max_priority {
            errors.push(format!(
                "Priority {} out of allowed range [{}, {}]",
                rule.priority, self.min_priority, self.max_priority
            ));
        }

        // 4. TOML serialization check
        let formatted_toml = if errors.is_empty() {
            Some(self.format_toml(rule))
        } else {
            None
        };

        RuleValidationResult {
            valid: errors.is_empty(),
            errors,
            formatted_toml,
        }
    }

    pub fn format_toml(&self, rule: &CandidatePolicyRule) -> String {
        let mut toml = String::new();
        toml.push_str("[[rules]]\n");
        toml.push_str(&format!("name = \"{}\"\n", rule.name));
        if let Some(ref tools) = rule.tool_names {
            let tools_json = serde_json::to_string(tools).unwrap_or_else(|_| "[]".to_string());
            toml.push_str(&format!("tool_names = {}\n", tools_json));
        }
        if let Some(ref op) = rule.operation_kind {
            toml.push_str(&format!("operation_kind = \"{}\"\n", op));
        }
        if let Some(min_amt) = rule.min_amount_cents {
            toml.push_str(&format!("min_amount_cents = {}\n", min_amt));
        }
        if let Some(min_auth) = rule.min_auth_level {
            toml.push_str(&format!("min_auth_level = {}\n", min_auth));
        }
        toml.push_str(&format!("action = \"{}\"\n", rule.action));
        toml.push_str(&format!("priority = {}\n", rule.priority));
        toml.push_str(&format!("lifecycle_state = \"{}\"\n", rule.lifecycle_state));
        toml.push_str(&format!("probation_target = {}\n", rule.probation_target));
        toml.push_str(&format!("confirmations_count = {}\n", rule.confirmations_count));
        toml.push_str(&format!("required_approver_quorum = {}\n", rule.required_approver_quorum));
        let proj_json = serde_json::to_string(&rule.projected_fields).unwrap_or_else(|_| "[]".to_string());
        toml.push_str(&format!("projected_fields = {}\n", proj_json));
        if let Some(ref role) = rule.escalation_role {
            toml.push_str(&format!("escalation_role = \"{}\"\n", role));
        }
        toml.push_str(&format!("justification = \"{}\"\n", rule.justification));
        toml
    }
}
