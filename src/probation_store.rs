use crate::models::{
    ProbationConfirmationRecord, ProbationStatusResponse, RecordConfirmationRequest,
    RecordConfirmationResponse, RuleLifecycleState,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct StoredRuleProbation {
    rule_name: String,
    lifecycle_state: RuleLifecycleState,
    probation_target: u32,
    required_approver_quorum: u32,
    history: Vec<ProbationConfirmationRecord>,
}

#[derive(Clone, Default)]
pub struct ProbationStore {
    rules: Arc<RwLock<HashMap<String, StoredRuleProbation>>>,
}

impl ProbationStore {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_candidate(&self, rule_name: &str, target: u32, quorum: u32) {
        let mut map = self.rules.write().await;
        if !map.contains_key(rule_name) {
            map.insert(
                rule_name.to_string(),
                StoredRuleProbation {
                    rule_name: rule_name.to_string(),
                    lifecycle_state: RuleLifecycleState::Probationary,
                    probation_target: target,
                    required_approver_quorum: quorum,
                    history: Vec::new(),
                },
            );
        }
    }

    pub async fn record_confirmation(
        &self,
        req: RecordConfirmationRequest,
    ) -> RecordConfirmationResponse {
        let mut map = self.rules.write().await;
        let entry = map.entry(req.rule_name.clone()).or_insert_with(|| StoredRuleProbation {
            rule_name: req.rule_name.clone(),
            lifecycle_state: RuleLifecycleState::Probationary,
            probation_target: 5,
            required_approver_quorum: 2,
            history: Vec::new(),
        });

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = ProbationConfirmationRecord {
            approver_did: req.approver_did.clone(),
            caller_did: req.caller_did.clone(),
            action_id: req.action_id.clone(),
            trace_id: req.trace_id.clone(),
            timestamp_epoch_secs: now_secs,
            approved: req.approved,
            rejection_reason: req.rejection_reason.clone(),
        };

        entry.history.push(record);

        // Tripwire: Human rejection immediately trips rule into Quarantined
        if !req.approved {
            entry.lifecycle_state = RuleLifecycleState::Quarantined;
            return RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: RuleLifecycleState::Quarantined,
                confirmations_count: entry.history.iter().filter(|h| h.approved).count() as u32,
                probation_target: entry.probation_target,
                unique_approvers_count: 0,
                quorum_satisfied: false,
                graduated: false,
                quarantined: true,
                message: format!(
                    "Tripwire tripped: rule quarantined immediately due to reviewer rejection: {}",
                    req.rejection_reason.unwrap_or_else(|| "unspecified reason".to_string())
                ),
            };
        }

        let approved_records: Vec<&ProbationConfirmationRecord> =
            entry.history.iter().filter(|h| h.approved).collect();
        let confirmations_count = approved_records.len() as u32;

        let unique_approvers: HashSet<&String> =
            approved_records.iter().map(|h| &h.approver_did).collect();
        let unique_count = unique_approvers.len();
        let quorum_satisfied = unique_count >= entry.required_approver_quorum as usize;

        if confirmations_count >= entry.probation_target && quorum_satisfied {
            entry.lifecycle_state = RuleLifecycleState::Graduated;
            RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: RuleLifecycleState::Graduated,
                confirmations_count,
                probation_target: entry.probation_target,
                unique_approvers_count: unique_count,
                quorum_satisfied: true,
                graduated: true,
                quarantined: false,
                message: format!(
                    "Rule '{}' satisfied all probation criteria ({} confirmations, {} distinct approvers) and graduated to parameter-bounded execution.",
                    entry.rule_name, confirmations_count, unique_count
                ),
            }
        } else {
            RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: entry.lifecycle_state,
                confirmations_count,
                probation_target: entry.probation_target,
                unique_approvers_count: unique_count,
                quorum_satisfied,
                graduated: false,
                quarantined: false,
                message: format!(
                    "Probation progress: {}/{} confirmations. Unique approvers: {}/{} required.",
                    confirmations_count, entry.probation_target, unique_count, entry.required_approver_quorum
                ),
            }
        }
    }

    pub async fn get_status(&self, rule_name: &str) -> Option<ProbationStatusResponse> {
        let map = self.rules.read().await;
        map.get(rule_name).map(|entry| {
            let approved_records: Vec<&ProbationConfirmationRecord> =
                entry.history.iter().filter(|h| h.approved).collect();
            let unique_approvers: Vec<String> = approved_records
                .iter()
                .map(|h| h.approver_did.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let unique_callers: Vec<String> = approved_records
                .iter()
                .map(|h| h.caller_did.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            ProbationStatusResponse {
                rule_name: entry.rule_name.clone(),
                lifecycle_state: entry.lifecycle_state,
                confirmations_count: approved_records.len() as u32,
                probation_target: entry.probation_target,
                required_approver_quorum: entry.required_approver_quorum,
                unique_approvers,
                unique_callers,
                history: entry.history.clone(),
            }
        })
    }
}
