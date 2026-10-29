use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B2bContextQuery {
    pub tenant_id: String,
    pub caller_did: String,
    pub tool_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B2bContextResponse {
    pub is_registered_partner: bool,
    pub trust_tier: String,
    pub active_sla: Option<String>,
}

#[derive(Clone)]
pub struct CommercialB2bConnector {
    pub b2b_agent_url: String,
    #[allow(dead_code)]
    pub agent_did: String,
    pub client: reqwest::Client,
}

impl CommercialB2bConnector {
    pub fn new(b2b_agent_url: impl Into<String>, agent_did: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            b2b_agent_url: b2b_agent_url.into(),
            agent_did: agent_did.into(),
            client,
        }
    }

    pub async fn check_b2b_status(&self) -> bool {
        let health_url = format!("{}/healthz", self.b2b_agent_url.trim_end_matches('/'));
        match self.client.get(&health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn query_b2b_context(
        &self,
        tenant_id: &str,
        caller_did: &str,
        tool_name: &str,
    ) -> Result<B2bContextResponse> {
        let url = format!("{}/v1/b2b/context", self.b2b_agent_url.trim_end_matches('/'));
        let query = B2bContextQuery {
            tenant_id: tenant_id.to_string(),
            caller_did: caller_did.to_string(),
            tool_name: tool_name.to_string(),
        };

        match self.client.post(&url).json(&query).send().await {
            Ok(resp) if resp.status().is_success() => {
                let context = resp.json::<B2bContextResponse>().await?;
                Ok(context)
            }
            _ => {
                // Heuristic fallback if commercial_b2b_agent is in autonomous mode
                Ok(B2bContextResponse {
                    is_registered_partner: caller_did.contains("enterprise") || caller_did.contains("b2b"),
                    trust_tier: "StandardB2B".to_string(),
                    active_sla: None,
                })
            }
        }
    }
}
