use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmChatRequest {
    pub model: String,
    pub messages: Vec<SwarmMessage>,
    pub temperature: f32,
    pub response_format: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmChoice {
    pub message: SwarmMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmChatResponse {
    pub choices: Vec<SwarmChoice>,
}

#[derive(Clone)]
pub struct SwarmClient {
    pub gateway_url: String,
    pub model_id: String,
    pub token: Option<String>,
    pub client: reqwest::Client,
}

impl SwarmClient {
    pub fn new(gateway_url: impl Into<String>, model_id: impl Into<String>, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            gateway_url: gateway_url.into(),
            model_id: model_id.into(),
            token,
            client,
        }
    }

    pub async fn check_health(&self) -> bool {
        let health_url = format!("{}/healthz", self.gateway_url.trim_end_matches('/'));
        match self.client.get(&health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn complete_prompt(&self, system_prompt: &str, user_content: &str) -> Result<String> {
        let url = format!("{}/v1/chat/completions", self.gateway_url.trim_end_matches('/'));
        let req = SwarmChatRequest {
            model: self.model_id.clone(),
            messages: vec![
                SwarmMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                SwarmMessage {
                    role: "user".to_string(),
                    content: user_content.to_string(),
                },
            ],
            temperature: 0.1,
            response_format: Some(serde_json::json!({ "type": "json_object" })),
        };

        let mut req_builder = self.client.post(&url).json(&req);
        if let Some(ref t) = self.token {
            if !t.is_empty() {
                req_builder = req_builder.bearer_auth(t);
            }
        }

        let resp = req_builder
            .send()
            .await
            .context("Failed to dispatch request to Swarm Gateway")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Swarm Gateway returned error status {}: {}", status, body);
        }

        let chat_resp: SwarmChatResponse = resp
            .json()
            .await
            .context("Failed to parse Swarm Gateway JSON response")?;

        let content = chat_resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(content)
    }
}
