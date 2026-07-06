import os

# Kafka Config
KAFKA_BROKERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka-1:29092,kafka-2:29092,kafka-3:29092").split(",")
L1_FINDINGS_TOPIC = os.getenv("L1_FINDINGS_TOPIC", "l1.agent.findings")
SOAR_FAST_PATH_TOPIC = os.getenv("SOAR_FAST_PATH_TOPIC", "soar.actions.fast-path")
DASHBOARD_EVENTS_TOPIC = os.getenv("DASHBOARD_EVENTS_TOPIC", "aegis.security.events")
SOAR_DECISIONS_TOPIC = os.getenv("SOAR_DECISIONS_TOPIC", "soar.decisions")
SOAR_QUEUED_ACTIONS_TOPIC = os.getenv("SOAR_QUEUED_ACTIONS_TOPIC", "soar.actions.queued")
ACTION_EXECUTION_DELAY_SECONDS = float(os.getenv("ACTION_EXECUTION_DELAY_SECONDS", "2.0"))

# Database Config
DATABASE_URL = os.getenv("DATABASE_URL", "")  # I-01 fix: no hardcoded credentials fallback

# Dashboard API Config
DASHBOARD_API_URL = os.getenv("DASHBOARD_API_URL", "http://dashboard-backend:8082/api")
AEGIS_INTERNAL_TOKEN = os.getenv("AEGIS_INTERNAL_TOKEN", "")  # I-01 fix: no hardcoded fallback

# Qwen 3.7 Plus LLM Config
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_MODEL_NAME = os.getenv("QWEN_MODEL_NAME", "qwen3-plus")
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "10"))
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"

# SOC Settings
SOC_AUTOPILOT_ENABLED = os.getenv("SOC_AUTOPILOT_ENABLED", "false").lower() == "true"
DEFAULT_EXECUTION_WINDOW_START = os.getenv("EXECUTION_WINDOW_START", "08:00")
DEFAULT_EXECUTION_WINDOW_END = os.getenv("EXECUTION_WINDOW_END", "20:00")
DEFAULT_TIMEZONE = os.getenv("EXECUTION_TIMEZONE", "Asia/Ho_Chi_Minh")

# Path to offline files (mounted from agent-layer-2 directory)
AGENT_L2_DIR = os.getenv("AGENT_L2_DIR", "/app/agent-layer-2")
SYSTEM_PROMPT_PATH = os.path.join(AGENT_L2_DIR, "layer2_orchestrator_system_prompt.md")
OUTPUT_SCHEMA_PATH = os.path.join(AGENT_L2_DIR, "layer2_orchestrator_output_schema.json")
PLAYBOOKS_PATH = os.path.join(AGENT_L2_DIR, "orchestrator_l2_playbooks.md")
RISK_SCORING_DIR = os.path.join(AGENT_L2_DIR, "risk_scoring")
MITRE_ATTACK_JSON_PATH = os.path.join(AGENT_L2_DIR, "mitre_attack_full.json")

# Redis State Database Config
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

