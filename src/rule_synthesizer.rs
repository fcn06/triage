use crate::models::{CandidatePolicyRule, RuleValidationResult, TriageRecommendation, TriageRequest};

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
    ) -> CandidatePolicyRule {
        let (action_str, priority) = match recommendation {
            TriageRecommendation::RecommendApprove => ("allow".to_string(), 12),
            TriageRecommendation::RequireHumanApproval => ("require_approval".to_string(), 15),
            TriageRecommendation::RecommendReject => ("deny".to_string(), 18),
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
            justification: format!(
                "Synthesized from novel triage {} for caller {}",
                req.triage_id, req.caller_did
            ),
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

        // 2. Action validity
        let act = rule.action.to_lowercase();
        if act != "allow" && act != "require_approval" && act != "deny" {
            errors.push(format!("Invalid action '{}', must be 'allow', 'require_approval', or 'deny'", rule.action));
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
        toml
    }
}
