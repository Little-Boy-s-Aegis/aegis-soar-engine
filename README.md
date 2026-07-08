# Aegis Bank SOAR Decision Engine (Layer 2)

The **Aegis SOAR (Security Orchestration, Automation, and Response) Decision Engine** serves as the Layer 2 central brain of the Aegis Bank defensive security ecosystem. It sits between the read-only Layer 1 specialist sensor agents (EDR, WAF, UEBA, ATM) and the SOC reporting layer (SOC Dashboard).

The engine ingests security alerts, correlates findings, verifies incidents against database access logs, executes security playbooks, and performs automated containment under strict policy guardrails.

---

## Key Features & Architecture

### 1. Multi-Stream Ingestion & Fast-Path Routing
The engine runs a Kafka consumer pipeline listening to two main channels:
* **Layer 1 Findings (`aegis.security.findings.l1`)**: Telemetry findings from sensors that require correlation, log verification, and AI orchestration.
* **Fast-Path Attacks (`aegis.security.fastpath`)**: High-fidelity alerts (such as obvious WAF/API Gateway blocks) that bypass LLM reasoning and trigger immediate containment blocks.

### 2. Entity Correlation Buffer
To avoid duplicate alerts and analyze multi-stage attacks, incoming L1 alerts enter an in-memory sliding correlation window (default: `2.0` seconds). Alerts are grouped by primary entity:
* **IP Addresses** (e.g., `ip:198.51.100.45`)
* **Usernames** (e.g., `user:alice`)
* **Agent ID fallback**

Once the correlation window expires, the entire group of findings is processed as a unified incident.

### 3. Independent Log Verification
Before acting on a Layer 1 finding, the SOAR engine crosschecks the alert by querying clean PostgreSQL database access logs (`log_entries`). This determines if the malicious pattern reported actually occurred on the backend, setting a `verification_strength` indicator (`strong`, `supported`, or `none`).

### 4. AI-Powered Security Orchestration
The engine utilizes a custom Security Agent prompt (powered by **Qwen 3 Plus** or OpenAI-compatible LLMs) to analyze the correlated findings and log evidence. The AI agent:
* References offline threat knowledge tables (`risk_scoring/attack_vector_risk_scores.md` and `risk_scoring/capec_risk_scores.md`).
* Dynamically calculates final risk scores on a `0 - 10` scale, applying risk caps if logs do not support the alert.
* Triggers a non-disruptive response floor for incidents scored `> 6.0` (notifies SOC, preserves logs, opens tickets).

### 5. Redis State Tracking
All incidents and playbook executions maintain live state in a Redis database. State transitions (`NEW` -> `ANALYZED` -> `MITIGATED` / `CONTAINED` -> `CLOSED`) are recorded with timestamps, action completion rates, and transaction rollbacks.

### 6. Auto-Containment Policy Gates
Environment-changing actions (like firewall blocks, WAF updates, or CrowdStrike host containment) are only executed if all the following gates pass:
* **Autopilot Mode**: The `SOC_AUTOPILOT_ENABLED` setting is explicitly set to `True`.
* **Verification**: `verification_state` is `confirmed` and `verification_strength` is `supported` or `strong`.
* **OPA Authorization**: Open Policy Agent authorization returns `allow`.
* **Time Windows & Safety**: The action is not marked as `manual-only` (such as core banking or HSM isolation) and runs within approved hours.

---

## Folder Structure

```text
soar-engine/
├── connectors/              # Integrations with Defensive Sandbox (Fortinet, WAF, etc.)
├── risk_scoring/            # Authoritative offline MITRE ATT&CK & CAPEC risk tables
├── main.py                  # Main consumer application loop & Kafka broker entrypoint
├── orchestrator.py          # AI analysis coordinator & risk calculation engine
├── playbook_executor.py     # Dispatches actions to staging-sandbox or dashboard
├── playbook_runner.py       # Logic for executing actions defined in playbooks.json
├── policy_evaluator.py      # OPA and autopilot security policy enforcement
├── requirements.txt         # Python dependencies
├── Dockerfile               # Production multi-stage build manifest
└── README.md                # This documentation
```

---

## Getting Started

### Prerequisites
* **Python 3.11+**
* **Apache Kafka & Redis** (can be spun up via the orchestration stack)
* **PostgreSQL Database** (with a `log_entries` table seeded by the banking app)

### Environment Variables
Configure the engine using these environment variables (or define them in your `.env` file):

| Variable | Default Value | Description |
|---|---|---|
| `KAFKA_BROKERS` | `localhost:9094` | Comma-separated Kafka broker endpoints |
| `REDIS_URL` | `redis://localhost:6379/0` | Connection string for Redis state tracking |
| `DATABASE_URL` | `postgres://postgres:1@localhost:5432/aegis` | Postgres DSN for independent verifications |
| `DASHSCOPE_API_KEY` | *(Required)* | API key to access Qwen LLM endpoint |
| `SOC_AUTOPILOT_ENABLED` | `False` | Set to `True` to allow automatic containment |
| `AEGIS_SECURITY_SYNC_TOKEN` | `admin123` | Secret for Basic Auth requests to sandboxes |

### Running the SOAR Engine

#### Local (Host Mode)
1. Install Python requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the engine:
   ```bash
   python main.py
   ```

#### Standalone Container Mode
To build and run the engine via Docker:
```bash
docker build -t aegis-soar-engine .
docker run -d \
  -e KAFKA_BROKERS=host.docker.internal:9094 \
  -e REDIS_URL=redis://host.docker.internal:6379/0 \
  -e DATABASE_URL=postgresql://postgres:1@host.docker.internal:5432/aegis \
  -e DASHSCOPE_API_KEY="your-api-key" \
  --name aegis-soar-engine-service \
  aegis-soar-engine
```

---

## Testing & Quality Gates

The engine includes a full suite of automated unit and integration tests. Run them using `pytest` inside the `soar-engine` directory:

```bash
# Run all tests
pytest

# Test policy evaluator guardrails
pytest test_policy_evaluator.py

# Verify audit trail integrity (FIM)
pytest test_audit_integrity.py
```
