use clap::Parser;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod b2b_connector;
mod cognitive;
mod evaluator;
mod models;
mod probation_store;
mod rule_synthesizer;
mod schema_inspector;
mod server;

use b2b_connector::CommercialB2bConnector;
use cognitive::SwarmClient;
use evaluator::TriageEvaluator;
use probation_store::ProbationStore;
use rule_synthesizer::RuleSynthesizer;

#[derive(Parser, Debug)]
#[clap(
    name = "triage_agent",
    about = "Autonomous Policy Triage & Candidate Rule Synthesis Agent for Marketplace Trust Gateway"
)]
struct Args {
    #[clap(short, long, default_value = "configuration/triage_agent_config.toml")]
    config: String,
    #[clap(short, long)]
    port: Option<u16>,
    #[clap(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = dotenvy::dotenv();
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&args.log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🛡️ Starting Triage Agent (Autonomous Policy Triage & Synthesis)...");

    let port = args
        .port
        .or_else(|| std::env::var("TRIAGE_AGENT_PORT").ok().and_then(|p| p.parse().ok()))
        .unwrap_or(4015);

    let host = std::env::var("TRIAGE_AGENT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

    let swarm_url = std::env::var("SWARM_GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let swarm_token = std::env::var("SWARM_GATEWAY_TOKEN").ok();
    let swarm_model = std::env::var("SWARM_MODEL_ID").unwrap_or_else(|_| "openai/gpt-oss-20b".to_string());

    let b2b_agent_url = std::env::var("COMMERCIAL_B2B_AGENT_URL").unwrap_or_else(|_| "http://127.0.0.1:4010".to_string());
    let b2b_did = std::env::var("COMMERCIAL_B2B_AGENT_DID").unwrap_or_else(|_| "did:web:agents.enterprise.internal:commercial-b2b".to_string());

    info!("   • Swarm Gateway: {}", swarm_url);
    info!("   • Commercial B2B Agent: {}", b2b_agent_url);
    info!("   • Binding Port: {}:{}", host, port);

    let swarm_client = SwarmClient::new(swarm_url, swarm_model, swarm_token);
    let b2b_connector = CommercialB2bConnector::new(b2b_agent_url, b2b_did);
    let rule_synthesizer = RuleSynthesizer::default();
    let probation_store = Arc::new(ProbationStore::new());

    let evaluator = Arc::new(TriageEvaluator::new(
        swarm_client,
        b2b_connector,
        rule_synthesizer,
    ));

    let app = server::create_router(evaluator, probation_store);
    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("✅ Triage Agent HTTP server listening on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
