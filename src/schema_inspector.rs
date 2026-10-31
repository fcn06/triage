use crate::models::DeterministicMetrics;
use serde_json::Value;
use trust_inspect::classifier::OperationClassifier;

pub struct SchemaInspector;

impl SchemaInspector {
    pub fn inspect(
        tool_name: &str,
        operation_kind: &str,
        arguments: &Value,
        skill_manifest: Option<&Value>,
    ) -> DeterministicMetrics {
        let classifier = OperationClassifier::default();
        let m = classifier.inspect(tool_name, operation_kind, arguments, skill_manifest);

        DeterministicMetrics {
            schema_verified: m.schema_verified,
            is_mutation: m.is_mutation,
            operation_kind: m.operation_kind,
            financial_exposure_cents: m.financial_exposure_cents,
            financial_indeterminate: m.financial_indeterminate,
            touched_iam_scopes: m.touched_iam_scopes,
            reversibility: m.reversibility,
            is_idempotent: m.is_idempotent,
            projected_fields: m.projected_fields,
            risk_classification: m.risk_classification,
        }
    }
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
