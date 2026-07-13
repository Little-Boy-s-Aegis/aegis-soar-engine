# Aegis SOAR Engine

Executable Layer 2 Security Orchestration, Automation, and Response service for
Little Boy's Aegis. It consumes Layer 1 findings and high-confidence fast-path
events, correlates and independently verifies evidence, asks the versioned
Layer 2 orchestrator for a structured decision, applies safety policy, and
publishes or executes approved response actions.

> Automated containment changes real systems when correctly configured. Keep
> autopilot disabled until connectors, OPA policy, target verification, rate
> limits, rollback, and audit storage have been tested in the staging sandbox.

## Responsibilities

- Consume validated Layer 1 v4 findings from Kafka
- Correlate findings by IP, user, host, account, and short time window
- Process high-fidelity fast-path events separately
- Verify evidence against PostgreSQL security logs
- Load the Layer 2 v8 prompt, schema, playbooks, and risk tables
- Use DashScope/Qwen or Amazon Bedrock for structured analysis
- Persist incident and execution state in Redis
- Gate actions with verification, OPA, execution windows, rate limits, and
  reversible-target checks
- Execute playbooks through firewall, WAF, EDR, identity, dashboard, ticketing,
  messaging, email, MQTT, and webhook connectors
- Maintain a hash-chained audit trail and operational reports
- Support active/standby leadership and a separate queued-action worker

## Processing Flow

```text
Layer 1 agents -------------------> l1.agent.findings -----+
gateway / deterministic detectors -> soar.actions.fast-path|
                                                          v
                                                schema validation
                                                          |
                                                entity correlation
                                                          |
                                        PostgreSQL log verification
                                                          |
                              Layer 2 prompt + risk references + LLM
                                                          |
                                   v8 decision / safety gate / OPA
                                      |                    |
                                      | approved           | deferred
                                      v                    v
                                connectors          soar.actions.queued
                                      |                    |
                                      +------> dashboard <-+
```

The main orchestrator and action worker can be deployed independently. The
worker adds a delay and re-evaluates safety before executing queued actions.

## Safety Model

Environment-changing actions are allowed only when the decision and runtime
checks agree. Important controls include:

- `SOC_AUTOPILOT_ENABLED=true`
- independently confirmed and supported/strong verification
- verified target entity and dangerous-current behavior
- OPA authorization when OPA is enabled
- approved execution window and timezone
- scoped, time-bound, reversible action with rollback data
- per-target and per-action rate-limit capacity in Redis
- explicit exclusion of manual-only critical banking actions

Non-disruptive response-floor actions can still preserve evidence, create
tickets, notify the SOC, and increase monitoring when containment is not
allowed.

## Prerequisites

- Python 3.11+
- Kafka
- Redis
- PostgreSQL with the dashboard/banking security log schema
- A sibling or mounted checkout of
  [`agent-layer-2`](https://github.com/Little-Boy-s-Aegis/agent-layer-2)
- Optional Qdrant/OpenSearch vector store, OPA, Vault, and vendor integrations

The easiest complete environment is provided by `aegis-bank-deployment`.

## Install and Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export AGENT_L2_DIR="$(cd ../agent-layer-2 && pwd)"
python main.py
```

Run the queued-action worker separately when using the split execution model:

```bash
python action_worker.py
```

This is a Kafka worker, not an HTTP server; successful startup is visible in
its broker, Redis, database, and artifact-loading logs.

## Core Configuration

### Kafka and state

| Variable | Default | Purpose |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka-1:29092,kafka-2:29092,kafka-3:29092` | Broker list |
| `L1_FINDINGS_TOPIC` | `l1.agent.findings` | Layer 1 input |
| `SOAR_FAST_PATH_TOPIC` | `soar.actions.fast-path` | Deterministic fast-path input |
| `SOAR_DECISIONS_TOPIC` | `soar.decisions` | Structured decision stream |
| `SOAR_QUEUED_ACTIONS_TOPIC` | `soar.actions.queued` | Deferred action stream |
| `DASHBOARD_EVENTS_TOPIC` | `aegis.security.events` | Dashboard/security events |
| `REDIS_URL` | `redis://redis:6379/0` | State, HA, and rate limiting |
| `DATABASE_URL` | empty | PostgreSQL DSN for independent verification |
| `ACTION_EXECUTION_DELAY_SECONDS` | `2.0` | Worker delay before re-check/execution |
| `SOAR_IDLE_WITHOUT_KAFKA` | `true` | Keep service alive when brokers are unavailable |

### Layer 2 and LLM

| Variable | Default | Purpose |
|---|---|---|
| `AGENT_L2_DIR` | auto-discovered | Layer 2 artifact directory |
| `LAYER_ARTIFACTS_S3_BUCKET` | empty | Optional artifact bucket |
| `LAYER2_ARTIFACTS_S3_PREFIX` | `layer2/` | Bucket prefix |
| `LAYER_ARTIFACTS_LOCAL_DIR` | `/tmp/aegis-layer-artifacts` | Download directory |
| `LLM_ENABLED` | `true` | Enable LLM orchestration |
| `LLM_PROVIDER` | `dashscope` | `dashscope` or `bedrock` |
| `DASHSCOPE_API_KEY` | empty | DashScope credential |
| `QWEN_MODEL_NAME` | `qwen3-plus` | OpenAI-compatible model |
| `QWEN_BASE_URL` | DashScope international endpoint | API base URL |
| `BEDROCK_MODEL_ID` | `qwen.qwen3-coder-next` | Bedrock inference model |
| `BEDROCK_REGION` | `AWS_REGION` / `us-east-1` | Bedrock region |
| `LLM_TIMEOUT_SECONDS` | `10` | Inference timeout |
| `LLM_MAX_TOKENS` | `4096` | Response token limit |

### Policy and execution

| Variable | Default | Purpose |
|---|---|---|
| `SOC_AUTOPILOT_ENABLED` | `false` | Permit eligible automatic containment |
| `OPA_ENABLED` | `false` | Enable OPA decision checks |
| `OPA_URL` | `http://opa:8181` | OPA base URL |
| `EXECUTION_WINDOW_START` | `08:00` | Local action-window start |
| `EXECUTION_WINDOW_END` | `20:00` | Local action-window end |
| `EXECUTION_TIMEZONE` | `Asia/Ho_Chi_Minh` | Window timezone |
| `AEGIS_INTERNAL_TOKEN` | empty | Dashboard/internal service credential |
| `DASHBOARD_API_URL` | `http://dashboard-backend:8082/api` | SOC API base URL |
| `ASSET_INVENTORY_API_URL` | `http://asset-inventory:8083/api/v1/assets/critical` | Critical-asset check |
| `SOAR_AUDIT_LOG_PATH` | `soar_audit.log` | Hash-chained audit file |
| `VAULT_ENABLED` | `false` | Resolve integration secrets from Vault |

Connector-specific settings are read in `connectors/` and cover Fortinet,
CrowdStrike, Entra/AD, AWS WAF, Jira, PagerDuty, Telegram, SMTP, MQTT,
VirusTotal, AbuseIPDB, Shodan, Slack, and generic webhooks. Mock/default tokens
put most connectors into simulation behavior; configure and test each connector
explicitly before enabling autopilot.

## Container

The image runs `main.py`. Mount the Layer 2 contract because it is intentionally
versioned in a separate repository:

```bash
docker build -t aegis-soar-engine .
docker run --rm \
  -e KAFKA_BOOTSTRAP_SERVERS=host.docker.internal:9094 \
  -e REDIS_URL=redis://host.docker.internal:6379/0 \
  -e DATABASE_URL='postgresql://postgres:<password>@host.docker.internal:5432/aegis' \
  -e AGENT_L2_DIR=/app/agent-layer-2 \
  -e LLM_ENABLED=false \
  -v "$(cd ../agent-layer-2 && pwd):/app/agent-layer-2:ro" \
  aegis-soar-engine
```

Use the deployment repository for the multi-process HA orchestrator, action
workers, OPA, Vault, Qdrant, and sandbox wiring.

## Tests and Validation

```bash
pytest -q
python3 -m py_compile *.py connectors/*.py
python3 -m json.tool playbooks.json >/dev/null
python verify_audit_integrity.py
```

Focused suites cover schema/playbook handling, policy gates, rate limits,
rollback, dry-run behavior, fast-path safety, audit integrity, vector storage,
email alerts, reports, sandbox integration, and guardrail tuning. Tests that
exercise external services may require the deployment stack or mocks.

Useful operational utilities:

```bash
python ingest_to_vector_db.py
python generate_weekly_report.py
python tune_guardrails.py
python stress_test_soar.py
```

Review their environment variables and target endpoints before running them.

## Repository Layout

```text
connectors/                 # Security and notification integrations
main.py                     # Kafka orchestrator entrypoint
action_worker.py            # Deferred-action consumer
orchestrator.py             # Layer 2 reasoning and risk decision
schema_validator.py         # L1/L2 Pydantic contracts
db_verifier.py              # Independent PostgreSQL evidence lookup
policy_evaluator.py         # OPA and critical-asset checks
safety_gate.py              # Final action eligibility
playbook_executor.py        # Decision/action coordination
playbook_runner.py          # JSON playbook dispatcher
audit_logger.py             # Hash-chained audit events
ha_manager.py               # Redis leader election
prekill_monitor.py          # Temporary-control expiry monitoring
scheduler.py                # Digests, reports, and scheduled enrichment
playbooks.json              # Executable playbook catalog
```

## Related Repositories

- [`agent-layer-1`](https://github.com/Little-Boy-s-Aegis/agent-layer-1) — sensor contracts
- [`agent-layer-2`](https://github.com/Little-Boy-s-Aegis/agent-layer-2) — prompt, schema, playbooks, and risk references
- [`aegis-staging-sandbox`](https://github.com/Little-Boy-s-Aegis/aegis-staging-sandbox) — safe connector target
- [`dashboard`](https://github.com/Little-Boy-s-Aegis/dashboard) — SOC API and UI
- [`aegis-bank-deployment`](https://github.com/Little-Boy-s-Aegis/aegis-bank-deployment) — integrated runtime
