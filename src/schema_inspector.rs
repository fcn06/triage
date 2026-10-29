use crate::models::DeterministicMetrics;
use serde_json::Value;

pub struct SchemaInspector;

impl SchemaInspector {
    pub fn inspect(
        tool_name: &str,
        operation_kind: &str,
        arguments: &Value,
        skill_manifest: Option<&Value>,
    ) -> DeterministicMetrics {
        let tool_lower = tool_name.trim().to_lowercase();
        let op_lower = operation_kind.trim().to_lowercase();

        // 1. Manifest-backed inspection if provided
        let manifest_op = skill_manifest
            .and_then(|m| m.get("policy_defaults"))
            .and_then(|pd| pd.get("operation_kind"))
            .and_then(|op| op.as_str())
            .map(|s| s.to_lowercase());

        let effective_op = manifest_op.unwrap_or_else(|| op_lower.clone());

        // 2. Mutation & Destructive detection
        let is_destructive = effective_op == "destructive"
            || tool_lower.contains("delete")
            || tool_lower.contains("drop")
            || tool_lower.contains("purge")
            || tool_lower.contains("destroy");

        let is_mutation = is_destructive
            || effective_op == "write"
            || effective_op == "mutation"
            || effective_op == "update"
            || effective_op == "create"
            || effective_op == "amend"
            || effective_op == "execute"
            || effective_op == "post"
            || effective_op == "put"
            || effective_op == "patch"
            || tool_lower.contains("update")
            || tool_lower.contains("set")
            || tool_lower.contains("amend")
            || tool_lower.contains("create")
            || tool_lower.contains("transfer")
            || tool_lower.contains("send")
            || tool_lower.contains("grant")
            || tool_lower.contains("revoke")
            || tool_lower.contains("modify");

        let is_idempotent = !is_mutation && (effective_op == "read" || tool_lower.starts_with("get") || tool_lower.starts_with("query"));

        let reversibility = if is_destructive {
            "Irreversible".to_string()
        } else if is_mutation {
            "AuditedJournal".to_string()
        } else {
            "N/A - Read-Only".to_string()
        };

        // 3. Deterministic financial extraction
        let (financial_exposure_cents, financial_indeterminate) = extract_deterministic_financials(arguments);

        // 4. IAM Scope Mapping
        let mut touched_iam_scopes = Vec::new();
        if tool_lower.contains("vendor") || tool_lower.contains("contract") {
            touched_iam_scopes.push("contracts:manage".to_string());
        }
        if financial_exposure_cents > 0 || tool_lower.contains("billing") || tool_lower.contains("transfer") {
            touched_iam_scopes.push("finance:disburse".to_string());
        }
        if tool_lower.contains("iam") || tool_lower.contains("auth") || tool_lower.contains("role") {
            touched_iam_scopes.push("iam:credentials_manage".to_string());
        }
        if is_destructive {
            touched_iam_scopes.push("system:destructive_purge".to_string());
        }
        if touched_iam_scopes.is_empty() {
            if is_mutation {
                touched_iam_scopes.push("data:mutation_general".to_string());
            } else {
                touched_iam_scopes.push("data:read_restricted".to_string());
            }
        }

        // 5. Projected Fields
        let projected_fields = extract_projected_fields(arguments);

        // 6. Risk classification
        let risk_classification = if is_destructive {
            "Critical".to_string()
        } else if financial_exposure_cents > 100_000 || financial_indeterminate {
            "High".to_string()
        } else if is_mutation || financial_exposure_cents > 0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };

        DeterministicMetrics {
            schema_verified: skill_manifest.is_some(),
            is_mutation,
            operation_kind: effective_op,
            financial_exposure_cents,
            financial_indeterminate,
            touched_iam_scopes,
            reversibility,
            is_idempotent,
            projected_fields,
            risk_classification,
        }
    }
}

fn extract_deterministic_financials(args: &Value) -> (u64, bool) {
    let mut total_cents = 0u64;
    let mut indeterminate = false;

    if let Value::Object(map) = args {
        let keys = ["amount_cents", "amount", "price", "cost", "total", "value", "transfer_amount", "budget"];
        for key in keys {
            if let Some(val) = map.get(key) {
                match val {
                    Value::Number(n) => {
                        if let Some(u) = n.as_u64() {
                            if key == "amount_cents" {
                                total_cents += u;
                            } else {
                                total_cents += u.saturating_mul(100);
                            }
                        } else if let Some(f) = n.as_f64() {
                            if f >= 0.0 {
                                total_cents += (f * 100.0) as u64;
                            } else {
                                indeterminate = true;
                            }
                        }
                    }
                    Value::String(s) => {
                        let clean = s.trim_start_matches(['$', '€', '£', '¥', ' ']).replace(',', "");
                        if let Ok(parsed) = clean.parse::<f64>() {
                            if parsed >= 0.0 {
                                total_cents += (parsed * 100.0) as u64;
                            } else {
                                indeterminate = true;
                            }
                        } else {
                            indeterminate = true;
                        }
                    }
                    Value::Array(_) | Value::Object(_) => {
                        indeterminate = true;
                    }
                    _ => {}
                }
            }
        }
    }

    (total_cents, indeterminate)
}

fn extract_projected_fields(args: &Value) -> Vec<String> {
    let mut fields = Vec::new();
    if let Value::Object(map) = args {
        // High priority keys to always project
        let priority_keys = [
            "vendor_id", "id", "contract_id", "account_id", "user_id",
            "amount", "amount_cents", "price", "months", "change",
            "target", "destination", "recipient", "role",
        ];

        for key in priority_keys {
            if map.contains_key(key) && !fields.contains(&key.to_string()) {
                fields.push(key.to_string());
            }
        }

        // If total keys is manageable (<= 6), include remaining top-level keys
        if map.len() <= 6 {
            for key in map.keys() {
                if !fields.contains(key) {
                    fields.push(key.clone());
                }
            }
        }
    }
    fields.sort();
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_schema_inspector_read_safe() {
        let args = json!({ "query": "servers", "category": "it" });
        let metrics = SchemaInspector::inspect("query_catalog", "read", &args, None);

        assert!(!metrics.is_mutation);
        assert!(metrics.is_idempotent);
        assert_eq!(metrics.financial_exposure_cents, 0);
        assert!(!metrics.financial_indeterminate);
        assert_eq!(metrics.risk_classification, "Low");
        assert!(metrics.projected_fields.contains(&"category".to_string()));
        assert!(metrics.projected_fields.contains(&"query".to_string()));
    }

    #[test]
    fn test_schema_inspector_mutation_and_financials() {
        let args = json!({
            "vendor_id": "V-2210",
            "change": "extend_term",
            "months": 12,
            "cost": 1500.50
        });
        let metrics = SchemaInspector::inspect("vendor_contract_amendment", "write", &args, None);

        assert!(metrics.is_mutation);
        assert!(!metrics.is_idempotent);
        assert_eq!(metrics.financial_exposure_cents, 150050);
        assert_eq!(metrics.risk_classification, "High");
        assert!(metrics.touched_iam_scopes.contains(&"contracts:manage".to_string()));
        assert!(metrics.touched_iam_scopes.contains(&"finance:disburse".to_string()));
        assert!(metrics.projected_fields.contains(&"vendor_id".to_string()));
        assert!(metrics.projected_fields.contains(&"months".to_string()));
    }

    #[test]
    fn test_schema_inspector_destructive() {
        let args = json!({ "target": "all_records" });
        let metrics = SchemaInspector::inspect("purge_database_tables", "destructive", &args, None);

        assert!(metrics.is_mutation);
        assert_eq!(metrics.reversibility, "Irreversible");
        assert_eq!(metrics.risk_classification, "Critical");
        assert!(metrics.touched_iam_scopes.contains(&"system:destructive_purge".to_string()));
    }

    #[test]
    fn test_schema_inspector_indeterminate_financial() {
        let args = json!({ "amount": "unparseable_string" });
        let metrics = SchemaInspector::inspect("wire_funds", "write", &args, None);

        assert!(metrics.financial_indeterminate);
        assert_eq!(metrics.risk_classification, "High");
    }
}
