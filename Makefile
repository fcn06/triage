# ─────────────────────────────────────────────────────────────────────────────
# Triage Agent Standalone Makefile
# (Autonomous Policy Triage & Candidate Rule Synthesis Agent)
# ─────────────────────────────────────────────────────────────────────────────

SHELL := /bin/bash
BIN_NAME := triage_agent
CONFIG := configuration/triage_agent_config.toml
PORT := 4015

.PHONY: all build run test fmt clean help

all: build

help:
	@echo "================================================================================"
	@echo " 🛡️ Triage Agent (Autonomous Policy Triage & Candidate Rule Synthesis)"
	@echo "================================================================================"
	@echo "  make build      - Build release binary"
	@echo "  make run        - Run Triage Agent on port $(PORT)"
	@echo "  make test       - Execute all unit and integration tests"
	@echo "  make fmt        - Format all code with cargo fmt"
	@echo "  make clean      - Clean target build directory"
	@echo "================================================================================"

build:
	@echo "==> Building $(BIN_NAME) [Release]..."
	cargo build --release

run:
	@echo "==> Starting Triage Agent on Port $(PORT)..."
	TRIAGE_AGENT_PORT=$${TRIAGE_AGENT_PORT:-$(PORT)} \
	cargo run --release -- --config $(CONFIG)

test:
	@echo "==> Running Triage Agent tests..."
	cargo test -- --nocapture

fmt:
	@echo "==> Formatting code..."
	cargo fmt --all

clean:
	@echo "==> Cleaning build artifacts..."
	cargo clean
