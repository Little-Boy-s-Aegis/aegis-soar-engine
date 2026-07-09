import os
import json
import hashlib
import random
import math
import logging
import requests
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ingest-vector-db")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
OPENSEARCH_ENDPOINT = os.getenv("OPENSEARCH_ENDPOINT", "").rstrip("/")
OPENSEARCH_L1_INDEX = os.getenv("OPENSEARCH_L1_INDEX", "l1-threat-intel")
OPENSEARCH_L2_INDEX = os.getenv("OPENSEARCH_L2_INDEX", "l2-playbooks")
VECTOR_DB_PROVIDER = os.getenv("VECTOR_DB_PROVIDER", "").strip().lower()
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))


def sync_s3_prefix(bucket, prefix, destination):
    if not bucket or not prefix:
        return
    try:
        from botocore.session import Session

        os.makedirs(destination, exist_ok=True)
        s3 = Session().create_client("s3", region_name=os.getenv("AWS_REGION", "us-east-1"))
        paginator = s3.get_paginator("list_objects_v2")
        normalized_prefix = prefix if prefix.endswith("/") else f"{prefix}/"
        count = 0
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
                s3.download_file(bucket, key, local_path)
                count += 1
        logger.info(f"Synced {count} artifact(s) from s3://{bucket}/{normalized_prefix} to {destination}")
    except Exception as exc:
        logger.warning(f"Layer artifact S3 sync skipped for s3://{bucket}/{prefix}: {exc}")


def prepare_layer_artifacts_from_s3():
    local_root = os.getenv("LAYER_ARTIFACTS_LOCAL_DIR", "/tmp/aegis-layer-artifacts")
    bucket = os.getenv("LAYER_ARTIFACTS_S3_BUCKET", "")
    if bucket:
        sync_s3_prefix(bucket, os.getenv("LAYER1_ARTIFACTS_S3_PREFIX", "layer1/"), os.path.join(local_root, "layer1"))
        sync_s3_prefix(bucket, os.getenv("LAYER2_ARTIFACTS_S3_PREFIX", "layer2/"), os.path.join(local_root, "layer2"))
    return local_root


LAYER_ARTIFACTS_LOCAL_DIR = prepare_layer_artifacts_from_s3()


def first_existing_path(paths, fallback):
    for path in paths:
        if path and os.path.exists(path):
            return path
    return fallback


# Paths relative to this script, with container mount fallbacks.
L1_DIR = first_existing_path(
    [
        os.getenv("AGENT_L1_DIR"),
        os.path.join(LAYER_ARTIFACTS_LOCAL_DIR, "layer1"),
        "/agent-layer-1",
        "/app/agent-layer-1",
        os.path.join(SCRIPT_DIR, "..", "agent-layer-1"),
    ],
    os.path.join(SCRIPT_DIR, "..", "agent-layer-1"),
)
AGENT_L2_DIR = first_existing_path(
    [
        os.getenv("AGENT_L2_DIR"),
        os.path.join(LAYER_ARTIFACTS_LOCAL_DIR, "layer2"),
        "/app/agent-layer-2",
        "/agent-layer-2",
        os.path.join(SCRIPT_DIR, "..", "agent-layer-2"),
    ],
    os.path.join(SCRIPT_DIR, "..", "agent-layer-2"),
)
PLAYBOOKS_JSON_PATH = os.path.join(SCRIPT_DIR, "playbooks.json")
L2_PLAYBOOKS_MD_PATH = os.getenv(
    "L2_PLAYBOOKS_MD_PATH",
    os.path.join(AGENT_L2_DIR, "orchestrator_l2_playbooks.md"),
)

L1_REFERENCE_FILES = [
    "attack_vector_prediction_reference.md",
    "capec_attack_pattern_prediction_reference.md",
    "edge_case_matrix.md",
    "surface_context_matrix.md",
    "agent_a_internal_network_edr_capec_attack_matrix.md",
    "agent_b_ebanking_api_web_capec_attack_matrix.md",
    "agent_c_atm_iam_capec_attack_matrix.md",
]

def qdrant_api(path):
    """Build Qdrant REST URLs without assuming a versioned API prefix."""
    return f"{QDRANT_URL.rstrip('/')}{path}"

def vector_db_provider():
    if VECTOR_DB_PROVIDER:
        return VECTOR_DB_PROVIDER
    if OPENSEARCH_ENDPOINT:
        return "opensearch"
    return "qdrant"

def opensearch_api(path):
    return f"{OPENSEARCH_ENDPOINT}{path}"

def aws_signed_request(method, url, body=None, service=None, timeout=10):
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.session import Session

    payload = json.dumps(body) if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    request = AWSRequest(method=method, url=url, data=payload, headers=headers)
    region = os.getenv("AWS_REGION", "us-east-1")
    parsed = urlparse(url)
    inferred_service = "aoss" if ".aoss." in parsed.netloc else "es"
    credentials = Session().get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials are not available for OpenSearch request signing")
    SigV4Auth(credentials.get_frozen_credentials(), service or os.getenv("OPENSEARCH_SERVICE", inferred_service), region).add_auth(request)
    return requests.request(method, url, data=payload, headers=dict(request.headers), timeout=timeout)

def stable_text_seed(text):
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")

def get_qwen_embedding(text, api_key):
    """Generates embedding using Qwen API, falling back to a deterministic mock vector if offline/mock."""
    if not api_key or api_key.startswith("mock") or api_key == "":
        # Generate stable pseudo-random mock embedding (unit length) based on text hash
        text_hash = stable_text_seed(text)
        random.seed(text_hash)
        vector = [random.uniform(-1.0, 1.0) for _ in range(1024)]
        norm = math.sqrt(sum(x * x for x in vector))
        return [x / norm for x in vector]

    url = f"{QWEN_BASE_URL}/embeddings"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "text-embedding-v3",
        "input": text
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]
    except Exception as e:
        logger.warning(f"Failed to fetch real Qwen embedding ({e}). Falling back to mock vector.")
        random.seed(stable_text_seed(text))
        vector = [random.uniform(-1.0, 1.0) for _ in range(1024)]
        norm = math.sqrt(sum(x * x for x in vector))
        return [x / norm for x in vector]

def ensure_collection(collection_name):
    """Creates Qdrant collection if it doesn't exist."""
    url = qdrant_api(f"/collections/{collection_name}")
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            logger.info(f"Collection '{collection_name}' already exists.")
            return True
    except Exception as e:
        logger.warning(f"Error checking collection '{collection_name}': {e}. Continuing to creation.")

    # Create it
    create_payload = {
        "vectors": {
            "size": 1024,
            "distance": "Cosine"
        }
    }
    try:
        resp = requests.put(url, json=create_payload, timeout=5)
        resp.raise_for_status()
        logger.info(f"Created collection '{collection_name}' successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to create collection '{collection_name}' in Qdrant: {e}")
        return False

def ensure_opensearch_index(index_name):
    if not OPENSEARCH_ENDPOINT:
        logger.error("OPENSEARCH_ENDPOINT is required when VECTOR_DB_PROVIDER=opensearch")
        return False

    url = opensearch_api(f"/{index_name}")
    try:
        resp = aws_signed_request("GET", url, timeout=10)
        if resp.status_code == 200:
            logger.info(f"OpenSearch index '{index_name}' already exists.")
            return True
    except Exception as e:
        logger.warning(f"Error checking OpenSearch index '{index_name}': {e}. Continuing to creation.")

    create_payload = {
        "settings": {
            "index": {
                "knn": True
            }
        },
        "mappings": {
            "properties": {
                "embedding": {
                    "type": "knn_vector",
                    "dimension": 1024
                },
                "payload": {
                    "type": "object",
                    "enabled": True
                }
            }
        }
    }
    try:
        resp = aws_signed_request("PUT", url, body=create_payload, timeout=10)
        if resp.status_code in (200, 201):
            logger.info(f"Created OpenSearch index '{index_name}' successfully.")
            return True
        if resp.status_code == 400 and "resource_already_exists_exception" in resp.text:
            logger.info(f"OpenSearch index '{index_name}' already exists.")
            return True
        logger.error(f"Failed to create OpenSearch index '{index_name}': {resp.status_code} {resp.text[:500]}")
        return False
    except Exception as e:
        logger.error(f"Failed to create OpenSearch index '{index_name}': {e}")
        return False

def upload_opensearch_points(index_name, points, batch_size=50):
    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        lines = []
        for point in batch:
            lines.append(json.dumps({"index": {"_index": index_name, "_id": str(point["id"])}}))
            lines.append(json.dumps({
                "embedding": point["vector"],
                "payload": point["payload"],
            }))
        body = "\n".join(lines) + "\n"
        url = opensearch_api("/_bulk")
        try:
            # Re-sign with newline-delimited JSON instead of standard JSON.
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
            from botocore.session import Session

            headers = {"Content-Type": "application/x-ndjson"}
            request = AWSRequest(method="POST", url=url, data=body, headers=headers)
            region = os.getenv("AWS_REGION", "us-east-1")
            parsed = urlparse(url)
            inferred_service = "aoss" if ".aoss." in parsed.netloc else "es"
            credentials = Session().get_credentials()
            if credentials is None:
                raise RuntimeError("AWS credentials are not available for OpenSearch request signing")
            SigV4Auth(credentials.get_frozen_credentials(), os.getenv("OPENSEARCH_SERVICE", inferred_service), region).add_auth(request)
            resp = requests.post(url, data=body, headers=dict(request.headers), timeout=20)
            resp.raise_for_status()
            if resp.json().get("errors"):
                logger.error(f"OpenSearch bulk upload for '{index_name}' batch {i//batch_size + 1} returned item errors.")
            else:
                logger.info(f"Uploaded OpenSearch batch {i//batch_size + 1} to '{index_name}': {len(batch)} points.")
        except Exception as e:
            logger.error(f"Failed to upload OpenSearch batch {i//batch_size + 1} to '{index_name}': {e}")


def stable_point_id(namespace, *parts):
    text = "|".join([namespace, *[str(p) for p in parts]])
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)


def parse_markdown_tables(file_path):
    rows = []
    headers = None
    with open(file_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line.startswith("|"):
                headers = None
                continue

            parts = [part.strip().strip("`") for part in line.split("|")[1:-1]]
            if not parts:
                continue

            if all(part.replace(":", "").replace("-", "") == "" for part in parts):
                continue

            if headers is None:
                headers = [part.lower().replace(" ", "_") for part in parts]
                continue

            if len(parts) != len(headers):
                continue

            row = dict(zip(headers, parts))
            if any(value for value in row.values()):
                rows.append(row)
    return rows


def row_value(row, *keys):
    for key in keys:
        value = row.get(key)
        if value:
            return value
    return ""


def iter_l1_reference_points():
    if not os.path.isdir(L1_DIR):
        logger.warning(f"Layer 1 directory not found: {L1_DIR}")
        return

    for agent_name in sorted(os.listdir(L1_DIR)):
        agent_dir = os.path.join(L1_DIR, agent_name)
        if not os.path.isdir(agent_dir) or not agent_name.startswith("agent_"):
            continue

        for filename in L1_REFERENCE_FILES:
            file_path = os.path.join(agent_dir, filename)
            if not os.path.exists(file_path):
                continue

            rows = parse_markdown_tables(file_path)
            logger.info(f"Parsed {len(rows)} L1 reference row(s) from {file_path}")
            for index, row in enumerate(rows, start=1):
                intel_id = row_value(row, "attack_id", "capec_id", "id") or f"{agent_name}-{filename}-{index}"
                title = row_value(row, "attack_vector", "attack_pattern", "edge_case", "surface", "watch_focus") or intel_id
                description = row_value(row, "description", "watch_focus", "prediction_context", "data_sources")
                watch_signal = row_value(row, "watch_focus", "prediction_context", "data_sources", "scoped_surfaces")
                source_file = f"{agent_name}/{filename}"
                text_to_embed = (
                    f"Layer 1 {agent_name} reference from {filename}. "
                    f"ID: {intel_id}. Title: {title}. Description: {description}. "
                    f"Watch signal: {watch_signal}. Row: {json.dumps(row, ensure_ascii=False)}"
                )
                yield {
                    "id": stable_point_id("l1", agent_name, filename, index, intel_id, title),
                    "vector": get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY),
                    "payload": {
                        "intel_type": "l1_reference",
                        "agent": agent_name,
                        "source_file": source_file,
                        "id": intel_id,
                        "title": title,
                        "description": description,
                        "watch_signal": watch_signal,
                        "row": row,
                    },
                }


def iter_l2_markdown_playbook_points():
    if not os.path.exists(L2_PLAYBOOKS_MD_PATH):
        logger.warning(f"L2 playbook markdown path not found: {L2_PLAYBOOKS_MD_PATH}")
        return

    with open(L2_PLAYBOOKS_MD_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_id = None
    current_lines = []

    def emit():
        if not current_id or not current_lines:
            return None
        body = "".join(current_lines).strip()
        text_to_embed = f"Layer 2 playbook {current_id}. {body}"
        return {
            "id": stable_point_id("l2-md", current_id),
            "vector": get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY),
            "payload": {
                "playbook_id": current_id,
                "name": current_id,
                "source_file": os.path.basename(L2_PLAYBOOKS_MD_PATH),
                "source_type": "markdown_playbook",
                "body": body,
                "steps": [],
            },
        }

    for line in lines:
        heading = line.strip()
        if heading.startswith("### PB-"):
            point = emit()
            if point:
                yield point
            current_id = heading.replace("#", "").strip().split()[0]
            current_lines = [line]
        elif current_id:
            if heading.startswith("## ") and not heading.startswith("### "):
                point = emit()
                if point:
                    yield point
                current_id = None
                current_lines = []
            else:
                current_lines.append(line)

    point = emit()
    if point:
        yield point


def ingest_l1_threat_intel():
    """Ingests per-agent Layer 1 reference data into the existing vector DB collection."""
    provider = vector_db_provider()
    if provider == "opensearch":
        if not ensure_opensearch_index(OPENSEARCH_L1_INDEX):
            return
    elif not ensure_collection("l1_threat_intel"):
        return

    logger.info(f"Parsing Layer 1 per-agent references from: {L1_DIR}")
    points = list(iter_l1_reference_points() or [])
    if not points:
        logger.warning("No Layer 1 reference points were produced for vector ingestion.")
        return

    if provider == "opensearch":
        upload_opensearch_points(OPENSEARCH_L1_INDEX, points)
        logger.info(f"L1 Threat Intel OpenSearch ingestion complete. Total points: {len(points)}")
        return

    batch_size = 50
    for i in range(0, len(points), batch_size):
        batch = points[i:i + batch_size]
        url = qdrant_api("/collections/l1_threat_intel/points")
        try:
            resp = requests.put(url, json={"points": batch}, timeout=10)
            resp.raise_for_status()
            logger.info(f"Uploaded L1 batch {i//batch_size + 1}: {len(batch)} points.")
        except Exception as e:
            logger.error(f"Failed to upload L1 batch {i//batch_size + 1}: {e}")

    logger.info(f"L1 Threat Intel ingestion complete. Total points: {len(points)}")

def ingest_l2_playbooks():
    """Ingests L2 playbook rules into Qdrant."""
    provider = vector_db_provider()
    if provider == "opensearch":
        if not ensure_opensearch_index(OPENSEARCH_L2_INDEX):
            return
    elif not ensure_collection("l2_playbooks"):
        return

    points = []

    if os.path.exists(PLAYBOOKS_JSON_PATH):
        logger.info(f"Parsing L2 runtime playbooks JSON: {PLAYBOOKS_JSON_PATH}")
        with open(PLAYBOOKS_JSON_PATH, "r", encoding="utf-8") as f:
            playbooks = json.load(f)

        for pb_id, pb in playbooks.items():
            name = pb.get("name", "")
            steps_summary = []
            for step in pb.get("steps", []):
                step_type = step.get("type", "")
                action_type = step.get("action_type", "")
                rationale = step.get("rationale", "")
                steps_summary.append(f"Step type: {step_type}, Action: {action_type}. Rationale: {rationale}")

            steps_text = "; ".join(steps_summary)
            text_to_embed = f"Runtime playbook: {pb_id} - {name}. Steps: {steps_text}"
            embedding = get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY)

            payload = {
                "playbook_id": pb_id,
                "name": name,
                "source_file": os.path.basename(PLAYBOOKS_JSON_PATH),
                "source_type": "runtime_json_playbook",
                "steps": pb.get("steps", []),
            }
            points.append({
                "id": stable_point_id("l2-json", pb_id),
                "vector": embedding,
                "payload": payload,
            })
    else:
        logger.warning(f"Playbooks JSON path not found: {PLAYBOOKS_JSON_PATH}")

    markdown_points = list(iter_l2_markdown_playbook_points() or [])
    logger.info(f"Parsed {len(markdown_points)} L2 canonical markdown playbook point(s).")
    points.extend(markdown_points)

    if points:
        if provider == "opensearch":
            upload_opensearch_points(OPENSEARCH_L2_INDEX, points)
            logger.info(f"L2 Playbooks OpenSearch ingestion complete. Total playbooks: {len(points)}")
            return

        url = qdrant_api("/collections/l2_playbooks/points")
        try:
            resp = requests.put(url, json={"points": points}, timeout=10)
            resp.raise_for_status()
            logger.info(f"Uploaded L2 Playbooks successfully. Total playbooks: {len(points)}")
        except Exception as e:
            logger.error(f"Failed to upload L2 Playbooks: {e}")
    else:
        logger.warning("No L2 playbook points were produced for vector ingestion.")

if __name__ == "__main__":
    logger.info("Starting ingestion of POC & Playbook data into Qdrant...")
    ingest_l1_threat_intel()
    ingest_l2_playbooks()
    logger.info("Ingestion finished.")
