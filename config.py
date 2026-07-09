import os


def _sync_s3_prefix(bucket: str, prefix: str, destination: str) -> None:
    if not bucket or not prefix:
        return
    try:
        from botocore.session import Session

        os.makedirs(destination, exist_ok=True)
        s3 = Session().create_client("s3", region_name=os.getenv("AWS_REGION", "us-east-1"))
        paginator = s3.get_paginator("list_objects_v2")
        normalized_prefix = prefix if prefix.endswith("/") else f"{prefix}/"
        for page in paginator.paginate(Bucket=bucket, Prefix=normalized_prefix):
            for item in page.get("Contents", []):
                key = item.get("Key", "")
                if not key or key.endswith("/"):
                    continue
                relative_key = key[len(normalized_prefix):]
                if not relative_key:
                    continue
                local_path = os.path.join(destination, *relative_key.split("/"))
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                response = s3.get_object(Bucket=bucket, Key=key)
                with open(local_path, "wb") as f:
                    f.write(response["Body"].read())
    except Exception as exc:
        print(f"[config] Layer artifact S3 sync skipped: {exc}")


def _prepare_layer_artifacts_from_s3() -> str:
    local_root = os.getenv("LAYER_ARTIFACTS_LOCAL_DIR", "/tmp/aegis-layer-artifacts")
    bucket = os.getenv("LAYER_ARTIFACTS_S3_BUCKET", "")
    if bucket:
        _sync_s3_prefix(bucket, os.getenv("LAYER2_ARTIFACTS_S3_PREFIX", "layer2/"), os.path.join(local_root, "layer2"))
    return local_root


LAYER_ARTIFACTS_LOCAL_DIR = _prepare_layer_artifacts_from_s3()

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

# LLM Config
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "dashscope").strip().lower()
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_MODEL_NAME = os.getenv("QWEN_MODEL_NAME", "qwen3-plus")
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "qwen.qwen3-coder-next")
BEDROCK_REGION = os.getenv("BEDROCK_REGION", os.getenv("AWS_REGION", "us-east-1"))
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "10"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"

# SOC Settings
SOC_AUTOPILOT_ENABLED = os.getenv("SOC_AUTOPILOT_ENABLED", "false").lower() == "true"
DEFAULT_EXECUTION_WINDOW_START = os.getenv("EXECUTION_WINDOW_START", "08:00")
DEFAULT_EXECUTION_WINDOW_END = os.getenv("EXECUTION_WINDOW_END", "20:00")
DEFAULT_TIMEZONE = os.getenv("EXECUTION_TIMEZONE", "Asia/Ho_Chi_Minh")

# Path to offline files (mounted from agent-layer-2 directory)
def _default_agent_l2_dir():
    repo_neighbor = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "agent-layer-2"))
    downloaded = os.path.join(LAYER_ARTIFACTS_LOCAL_DIR, "layer2")
    for candidate in (downloaded, "/app/agent-layer-2", "/agent-layer-2", repo_neighbor):
        if os.path.exists(os.path.join(candidate, "layer2_orchestrator_system_prompt.md")):
            return candidate
    return "/app/agent-layer-2"


_AGENT_L2_DIR_ENV = os.getenv("AGENT_L2_DIR")
AGENT_L2_DIR = (
    _AGENT_L2_DIR_ENV
    if _AGENT_L2_DIR_ENV and os.path.exists(os.path.join(_AGENT_L2_DIR_ENV, "layer2_orchestrator_system_prompt.md"))
    else _default_agent_l2_dir()
)
SYSTEM_PROMPT_PATH = os.path.join(AGENT_L2_DIR, "layer2_orchestrator_system_prompt.md")
OUTPUT_SCHEMA_PATH = os.path.join(AGENT_L2_DIR, "layer2_orchestrator_output_schema.json")
PLAYBOOKS_PATH = os.path.join(AGENT_L2_DIR, "orchestrator_l2_playbooks.md")
RISK_SCORING_DIR = os.path.join(AGENT_L2_DIR, "risk_scoring")
MITRE_ATTACK_JSON_PATH = os.path.join(AGENT_L2_DIR, "mitre_attack_full.json")

# Redis State Database Config
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
