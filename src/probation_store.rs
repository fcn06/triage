use crate::models::{
    PolicyPromotion, ProbationConfirmationRecord, ProbationStatusResponse,
    PromotionSignature, RecordConfirmationRequest, RecordConfirmationResponse,
    RecordDriftResponse, RuleLifecycleState,
    SubmitPromotionSignatureRequest, SubmitPromotionSignatureResponse,
};
use ed25519_dalek::Verifier;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Digest;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ProbationStore {
    db_path: Option<PathBuf>,
    conn: Arc<Mutex<Option<Connection>>>,
}

impl Default for ProbationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbationStore {
    /// In-memory store (for testing and fallback)
    pub fn new() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed");
        Self::init(conn, None)
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Self {
        Self::new()
    }

    /// Open or create on-disk SQLite database
    pub fn open(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(&p)?;
        Ok(Self::init(conn, Some(p)))
    }

    fn init(conn: Connection, path: Option<PathBuf>) -> Self {
        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS rule_probation (
                 rule_name TEXT PRIMARY KEY,
                 lifecycle_state TEXT NOT NULL,
                 probation_target INTEGER NOT NULL,
                 required_approver_quorum INTEGER NOT NULL,
                 confirmations_json TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS drift_records (
                 drift_id TEXT PRIMARY KEY,
                 diff_fingerprint TEXT NOT NULL UNIQUE,
                 tool_name TEXT NOT NULL,
                 first_seen_epoch_secs INTEGER NOT NULL,
                 last_seen_epoch_secs INTEGER NOT NULL,
                 occurrence_count INTEGER NOT NULL,
                 details_json TEXT NOT NULL,
                 candidate_amendment TEXT
             );
             CREATE TABLE IF NOT EXISTS policy_promotions (
                 promotion_id TEXT PRIMARY KEY,
                 rule_name TEXT NOT NULL UNIQUE,
                 candidate_action TEXT NOT NULL,
                 required_signatures INTEGER NOT NULL,
                 signatures_json TEXT NOT NULL,
                 status TEXT NOT NULL,
                 canonical_hash TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );",
        );
        Self {
            db_path: path,
            conn: Arc::new(Mutex::new(Some(conn))),
        }
    }

    /// Fail-closed check: if the store file is missing or corrupted, all rules are treated as Quarantined (OB-INV-08)
    pub fn is_missing_or_corrupt(&self) -> bool {
        if let Some(ref path) = self.db_path {
            if !path.exists() {
                return true;
            }
        }
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match *guard {
            Some(ref conn) => {
                let mut stmt = match conn.prepare("PRAGMA quick_check;") {
                    Ok(s) => s,
                    Err(_) => return true,
                };
                let check_res: Result<String, _> = stmt.query_row([], |row| row.get(0));
                !matches!(check_res, Ok(ref s) if s == "ok")
            }
            None => true,
        }
    }

    pub async fn register_candidate(&self, rule_name: &str, target: u32, quorum: u32) {
        if self.is_missing_or_corrupt() {
            return;
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(ref conn) = *guard {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO rule_probation (
                     rule_name, lifecycle_state, probation_target, required_approver_quorum, confirmations_json, updated_at
                 ) VALUES (?, 'probationary', ?, ?, '[]', ?);",
                params![rule_name, target, quorum, now_secs],
            );
        }
    }

    pub async fn record_confirmation(
        &self,
        req: RecordConfirmationRequest,
    ) -> RecordConfirmationResponse {
        // Fail-closed safeguard: if missing or corrupt, immediately quarantine
        if self.is_missing_or_corrupt() {
            return RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: RuleLifecycleState::Quarantined,
                confirmations_count: 0,
                probation_target: 5,
                unique_approvers_count: 0,
                quorum_satisfied: false,
                graduated: false,
                quarantined: true,
                message: "Store is missing or corrupt: rule treated as quarantined (fail-closed, OB-INV-08)"
                    .to_string(),
            };
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let conn = match *guard {
            Some(ref c) => c,
            None => {
                return RecordConfirmationResponse {
                    rule_name: req.rule_name,
                    lifecycle_state: RuleLifecycleState::Quarantined,
                    confirmations_count: 0,
                    probation_target: 5,
                    unique_approvers_count: 0,
                    quorum_satisfied: false,
                    graduated: false,
                    quarantined: true,
                    message: "Database connection unavailable: fail-closed to quarantined".to_string(),
                };
            }
        };

        // Fetch or initialize rule row
        let row_opt = conn.query_row(
            "SELECT lifecycle_state, probation_target, required_approver_quorum, confirmations_json
             FROM rule_probation WHERE rule_name = ?;",
            params![req.rule_name],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        );

        let (current_state, probation_target, required_quorum, mut history) = match row_opt {
            Ok((state_str, target, quorum, json_str)) => {
                let hist: Vec<ProbationConfirmationRecord> =
                    serde_json::from_str(&json_str).unwrap_or_default();
                (parse_lifecycle_state(&state_str), target, quorum, hist)
            }
            Err(_) => (RuleLifecycleState::Probationary, 5, 2, Vec::new()),
        };

        let record = ProbationConfirmationRecord {
            approver_did: req.approver_did.clone(),
            caller_did: req.caller_did.clone(),
            action_id: req.action_id.clone(),
            trace_id: req.trace_id.clone(),
            timestamp_epoch_secs: now_secs,
            approved: req.approved,
            rejection_reason: req.rejection_reason.clone(),
        };
        history.push(record);

        // Tripwire: Human rejection immediately trips rule into Quarantined
        if !req.approved {
            let hist_json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
            let _ = conn.execute(
                "INSERT INTO rule_probation (rule_name, lifecycle_state, probation_target, required_approver_quorum, confirmations_json, updated_at)
                 VALUES (?1, 'quarantined', ?2, ?3, ?4, ?5)
                 ON CONFLICT(rule_name) DO UPDATE SET
                     lifecycle_state = 'quarantined',
                     confirmations_json = ?4,
                     updated_at = ?5;",
                params![req.rule_name, probation_target, required_quorum, hist_json, now_secs],
            );

            return RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: RuleLifecycleState::Quarantined,
                confirmations_count: history.iter().filter(|h| h.approved).count() as u32,
                probation_target,
                unique_approvers_count: 0,
                quorum_satisfied: false,
                graduated: false,
                quarantined: true,
                message: format!(
                    "Tripwire tripped: rule quarantined immediately due to reviewer rejection: {}",
                    req.rejection_reason
                        .unwrap_or_else(|| "unspecified reason".to_string())
                ),
            };
        }

        let approved_records: Vec<&ProbationConfirmationRecord> =
            history.iter().filter(|h| h.approved).collect();
        let confirmations_count = approved_records.len() as u32;
        let unique_approvers: HashSet<&String> =
            approved_records.iter().map(|h| &h.approver_did).collect();
        let unique_count = unique_approvers.len();
        let quorum_satisfied = unique_count >= required_quorum as usize;

        if confirmations_count >= probation_target && quorum_satisfied {
            let hist_json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
            let _ = conn.execute(
                "INSERT INTO rule_probation (rule_name, lifecycle_state, probation_target, required_approver_quorum, confirmations_json, updated_at)
                 VALUES (?1, 'graduated', ?2, ?3, ?4, ?5)
                 ON CONFLICT(rule_name) DO UPDATE SET
                     lifecycle_state = 'graduated',
                     confirmations_json = ?4,
                     updated_at = ?5;",
                params![req.rule_name, probation_target, required_quorum, hist_json, now_secs],
            );

            RecordConfirmationResponse {
                rule_name: req.rule_name.clone(),
                lifecycle_state: RuleLifecycleState::Graduated,
                confirmations_count,
                probation_target,
                unique_approvers_count: unique_count,
                quorum_satisfied: true,
                graduated: true,
                quarantined: false,
                message: format!(
                    "Rule '{}' satisfied all probation criteria ({} confirmations, {} distinct approvers) and graduated to parameter-bounded execution.",
                    req.rule_name, confirmations_count, unique_count
                ),
            }
        } else {
            let hist_json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
            let state_str = current_state.to_string();
            let _ = conn.execute(
                "INSERT INTO rule_probation (rule_name, lifecycle_state, probation_target, required_approver_quorum, confirmations_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(rule_name) DO UPDATE SET
                     lifecycle_state = ?2,
                     confirmations_json = ?5,
                     updated_at = ?6;",
                params![req.rule_name, state_str, probation_target, required_quorum, hist_json, now_secs],
            );

            RecordConfirmationResponse {
                rule_name: req.rule_name,
                lifecycle_state: current_state,
                confirmations_count,
                probation_target,
                unique_approvers_count: unique_count,
                quorum_satisfied,
                graduated: false,
                quarantined: false,
                message: format!(
                    "Probation progress: {}/{} confirmations. Unique approvers: {}/{} required.",
                    confirmations_count, probation_target, unique_count, required_quorum
                ),
            }
        }
    }

    pub async fn get_status(&self, rule_name: &str) -> Option<ProbationStatusResponse> {
        // Fail-closed safeguard: if missing or corrupt, treat rule as Quarantined (OB-INV-08)
        if self.is_missing_or_corrupt() {
            return Some(ProbationStatusResponse {
                rule_name: rule_name.to_string(),
                lifecycle_state: RuleLifecycleState::Quarantined,
                confirmations_count: 0,
                probation_target: 5,
                required_approver_quorum: 2,
                unique_approvers: Vec::new(),
                unique_callers: Vec::new(),
                history: Vec::new(),
            });
        }

        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let conn = (*guard).as_ref()?;

        conn.query_row(
            "SELECT lifecycle_state, probation_target, required_approver_quorum, confirmations_json
             FROM rule_probation WHERE rule_name = ?;",
            params![rule_name],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .ok()
        .map(|(state_str, target, quorum, json_str)| {
            let history: Vec<ProbationConfirmationRecord> =
                serde_json::from_str(&json_str).unwrap_or_default();
            let approved_records: Vec<&ProbationConfirmationRecord> =
                history.iter().filter(|h| h.approved).collect();
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
                rule_name: rule_name.to_string(),
                lifecycle_state: parse_lifecycle_state(&state_str),
                confirmations_count: approved_records.len() as u32,
                probation_target: target,
                required_approver_quorum: quorum,
                unique_approvers,
                unique_callers,
                history,
            }
        })
    }

    pub fn record_drift(
        &self,
        tool_name: &str,
        diff_fingerprint: &str,
        details: &serde_json::Value,
    ) -> Result<RecordDriftResponse, anyhow::Error> {
        let lock = self.conn.lock().unwrap();
        let conn = lock.as_ref().ok_or_else(|| anyhow::anyhow!("Store closed"))?;
        let now = chrono::Utc::now().timestamp() as u64;

        let existing: Option<(String, u32, Option<String>)> = conn
            .query_row(
                "SELECT drift_id, occurrence_count, candidate_amendment FROM drift_records WHERE diff_fingerprint = ?1",
                params![diff_fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        if let Some((drift_id, count, amendment)) = existing {
            let new_count = count + 1;
            let candidate = if new_count >= 3 && amendment.is_none() {
                Some(format!(
                    "# Suggested Policy Rule for repeating drift (fingerprint: {})\n[[rules]]\nname = \"Auto-generated drift rule for {}\"\ntool_names = [\"{}\"]\naction = \"require_approval\"\npriority = 25\n",
                    diff_fingerprint, tool_name, tool_name
                ))
            } else {
                amendment
            };

            conn.execute(
                "UPDATE drift_records SET occurrence_count = ?1, last_seen_epoch_secs = ?2, candidate_amendment = ?3 WHERE drift_id = ?4",
                params![new_count, now, candidate, drift_id],
            )?;

            Ok(RecordDriftResponse {
                drift_id,
                diff_fingerprint: diff_fingerprint.to_string(),
                occurrence_count: new_count,
                deduplicated: true,
                candidate_amendment: candidate,
            })
        } else {
            let drift_id = format!("drf_{}", uuid::Uuid::new_v4());
            let details_json = serde_json::to_string(details)?;

            conn.execute(
                "INSERT INTO drift_records (drift_id, diff_fingerprint, tool_name, first_seen_epoch_secs, last_seen_epoch_secs, occurrence_count, details_json, candidate_amendment)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, NULL)",
                params![drift_id, diff_fingerprint, tool_name, now, now, details_json],
            )?;

            Ok(RecordDriftResponse {
                drift_id,
                diff_fingerprint: diff_fingerprint.to_string(),
                occurrence_count: 1,
                deduplicated: false,
                candidate_amendment: None,
            })
        }
    }

    pub fn create_or_get_promotion(&self, rule_name: &str) -> Result<PolicyPromotion, anyhow::Error> {
        let lock = self.conn.lock().unwrap();
        let conn = lock.as_ref().ok_or_else(|| anyhow::anyhow!("Store closed"))?;

        let existing: Option<(String, String, u32, String, String, String)> = conn
            .query_row(
                "SELECT promotion_id, candidate_action, required_signatures, signatures_json, status, canonical_hash FROM policy_promotions WHERE rule_name = ?1",
                params![rule_name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()?;

        if let Some((promotion_id, candidate_action, required_signatures, sigs_json, status, canonical_hash)) = existing {
            let signatures: Vec<PromotionSignature> = serde_json::from_str(&sigs_json)?;
            return Ok(PolicyPromotion {
                promotion_id,
                rule_name: rule_name.to_string(),
                candidate_action,
                required_signatures,
                signatures,
                status,
                canonical_hash,
            });
        }

        let promotion_id = format!("prm_{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp() as u64;
        let mut hasher = sha2::Sha256::new();
        hasher.update(format!("{promotion_id}:{rule_name}:allow").as_bytes());
        let canonical_hash = format!("{:x}", hasher.finalize());

        conn.execute(
            "INSERT INTO policy_promotions (promotion_id, rule_name, candidate_action, required_signatures, signatures_json, status, canonical_hash, created_at)
             VALUES (?1, ?2, 'allow', 2, '[]', 'pending_signatures', ?3, ?4)",
            params![promotion_id, rule_name, canonical_hash, now],
        )?;

        Ok(PolicyPromotion {
            promotion_id,
            rule_name: rule_name.to_string(),
            candidate_action: "allow".to_string(),
            required_signatures: 2,
            signatures: vec![],
            status: "pending_signatures".to_string(),
            canonical_hash,
        })
    }

    pub fn submit_promotion_signature(
        &self,
        req: &SubmitPromotionSignatureRequest,
    ) -> Result<SubmitPromotionSignatureResponse, anyhow::Error> {
        let lock = self.conn.lock().unwrap();
        let conn = lock.as_ref().ok_or_else(|| anyhow::anyhow!("Store closed"))?;
        let now = chrono::Utc::now().timestamp() as u64;

        let row: (String, String, u32, String, String) = conn.query_row(
            "SELECT rule_name, candidate_action, required_signatures, signatures_json, canonical_hash FROM policy_promotions WHERE promotion_id = ?1",
            params![req.promotion_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;

        let (rule_name, _action, req_sigs, sigs_json, canonical_hash) = row;
        let mut signatures: Vec<PromotionSignature> = serde_json::from_str(&sigs_json)?;

        if signatures.iter().any(|s| s.signer_did == req.signer_did) {
            anyhow::bail!("Signer '{}' has already signed this promotion; distinct human approvers required", req.signer_did);
        }

        let pubkey_bytes = if req.signer_did.starts_with("did:key:") {
            trust_sdk::did::extract_did_key_ed25519_pubkey(&req.signer_did)
                .map_err(|e| anyhow::anyhow!("Invalid did:key: {e}"))?
        } else if req.signer_did.starts_with("did:twin:") {
            trust_sdk::did::extract_did_twin_ed25519_pubkey(&req.signer_did)
                .map_err(|e| anyhow::anyhow!("Invalid did:twin: {e}"))?
        } else {
            anyhow::bail!("Unsupported DID method for signer: {}", req.signer_did);
        };

        let sig_bytes = hex::decode(&req.signature_hex)?;
        if sig_bytes.len() != 64 {
            anyhow::bail!("Invalid signature length: expected 64 bytes");
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)?;
        verifying_key.verify(canonical_hash.as_bytes(), &sig)?;

        signatures.push(PromotionSignature {
            signer_did: req.signer_did.clone(),
            signature_hex: req.signature_hex.clone(),
            timestamp_epoch_secs: now,
        });

        let new_status = if signatures.len() >= (req_sigs as usize) {
            conn.execute(
                "UPDATE rule_probation SET lifecycle_state = 'graduated', updated_at = ?1 WHERE rule_name = ?2",
                params![now, rule_name],
            )?;
            "promoted"
        } else {
            "pending_signatures"
        };

        let new_sigs_json = serde_json::to_string(&signatures)?;
        conn.execute(
            "UPDATE policy_promotions SET signatures_json = ?1, status = ?2 WHERE promotion_id = ?3",
            params![new_sigs_json, new_status, req.promotion_id],
        )?;

        Ok(SubmitPromotionSignatureResponse {
            promotion_id: req.promotion_id.clone(),
            status: new_status.to_string(),
            signatures_count: signatures.len(),
            required_signatures: req_sigs,
            message: format!("Signature recorded. Status: {new_status} ({}/{} signatures)", signatures.len(), req_sigs),
        })
    }
}

fn parse_lifecycle_state(s: &str) -> RuleLifecycleState {
    match s.to_lowercase().as_str() {
        "graduated" => RuleLifecycleState::Graduated,
        "quarantined" => RuleLifecycleState::Quarantined,
        "draft" => RuleLifecycleState::Draft,
        _ => RuleLifecycleState::Probationary,
    }
}
