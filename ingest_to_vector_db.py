import os
import csv
import json
import hashlib
import random
import math
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ingest-vector-db")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")

# Paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
L1_DIR = os.path.join(SCRIPT_DIR, "..", "agent-layer-1")
PLAYBOOKS_JSON_PATH = os.path.join(SCRIPT_DIR, "playbooks.json")

def qdrant_api(path):
    """Build Qdrant REST URLs without assuming a versioned API prefix."""
    return f"{QDRANT_URL.rstrip('/')}{path}"

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

def ingest_l1_threat_intel():
    """Ingests L1 CAPEC and MITRE ATT&CK reference data into Qdrant."""
    if not ensure_collection("l1_threat_intel"):
        return

    points = []
    point_id = 1

    # 1. Parse capec_attack_pattern_scores.csv
    capec_csv = os.path.join(L1_DIR, "capec_attack_pattern_scores.csv")
    if os.path.exists(capec_csv):
        logger.info(f"Parsing L1 CAPEC CSV: {capec_csv}")
        with open(capec_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                capec_id = row.get("capec_id", "")
                attack_pattern = row.get("attack_pattern", "")
                description = row.get("description", "")
                
                text_to_embed = f"CAPEC: {capec_id} - {attack_pattern}. Description: {description}"
                embedding = get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY)
                
                payload = {
                    "intel_type": "capec",
                    "id": capec_id,
                    "title": attack_pattern,
                    "description": description,
                    "severity_label": row.get("severity_label", "Unknown"),
                    "score_0_10": float(row.get("score_0_10", "5.0") or "5.0"),
                    "recommended_action": row.get("recommended_action", ""),
                    "auto_containment_allowed": row.get("auto_containment_allowed", "False").lower() == "true",
                    "related_attack_techniques": row.get("related_attack_techniques", "")
                }
                points.append({
                    "id": point_id,
                    "vector": embedding,
                    "payload": payload
                })
                point_id += 1
    else:
        logger.warning(f"L1 CAPEC CSV path not found: {capec_csv}")

    # 2. Parse attack_vector_scores.csv
    attack_csv = os.path.join(L1_DIR, "attack_vector_scores.csv")
    if os.path.exists(attack_csv):
        logger.info(f"Parsing L1 Attack Vectors CSV: {attack_csv}")
        with open(attack_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                attack_id = row.get("attack_id", "")
                attack_vector = row.get("attack_vector", "")
                description = row.get("description", "")
                
                text_to_embed = f"MITRE Technique: {attack_id} - {attack_vector}. Description: {description}"
                embedding = get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY)
                
                payload = {
                    "intel_type": "mitre_attack",
                    "id": attack_id,
                    "title": attack_vector,
                    "description": description,
                    "severity_label": row.get("severity_label", "Unknown"),
                    "score_0_10": float(row.get("score_0_10", "5.0") or "5.0"),
                    "recommended_action": row.get("recommended_action", ""),
                    "auto_containment_allowed": row.get("auto_containment_allowed", "False").lower() == "true",
                    "primary_surfaces": row.get("primary_surfaces", "")
                }
                points.append({
                    "id": point_id,
                    "vector": embedding,
                    "payload": payload
                })
                point_id += 1
    else:
        logger.warning(f"L1 Attack Vectors CSV path not found: {attack_csv}")

    # Upload in batches to Qdrant
    if points:
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
                
        logger.info(f"L1 Threat Intel ingestion complete. Total points: {point_id - 1}")

def ingest_l2_playbooks():
    """Ingests L2 playbook rules into Qdrant."""
    if not ensure_collection("l2_playbooks"):
        return

    if not os.path.exists(PLAYBOOKS_JSON_PATH):
        logger.warning(f"Playbooks JSON path not found: {PLAYBOOKS_JSON_PATH}")
        return

    logger.info(f"Parsing L2 Playbooks: {PLAYBOOKS_JSON_PATH}")
    with open(PLAYBOOKS_JSON_PATH, "r", encoding="utf-8") as f:
        playbooks = json.load(f)

    points = []
    point_id = 10000  # Start L2 point IDs at 10000

    for pb_id, pb in playbooks.items():
        name = pb.get("name", "")
        steps_summary = []
        for step in pb.get("steps", []):
            step_type = step.get("type", "")
            action_type = step.get("action_type", "")
            rationale = step.get("rationale", "")
            steps_summary.append(f"Step type: {step_type}, Action: {action_type}. Rationale: {rationale}")
        
        steps_text = "; ".join(steps_summary)
        text_to_embed = f"Playbook: {pb_id} - {name}. Steps: {steps_text}"
        embedding = get_qwen_embedding(text_to_embed, DASHSCOPE_API_KEY)
        
        payload = {
            "playbook_id": pb_id,
            "name": name,
            "steps": pb.get("steps", [])
        }
        points.append({
            "id": point_id,
            "vector": embedding,
            "payload": payload
        })
        point_id += 1

    if points:
        url = qdrant_api("/collections/l2_playbooks/points")
        try:
            resp = requests.put(url, json={"points": points}, timeout=10)
            resp.raise_for_status()
            logger.info(f"Uploaded L2 Playbooks successfully. Total playbooks: {len(points)}")
        except Exception as e:
            logger.error(f"Failed to upload L2 Playbooks: {e}")

if __name__ == "__main__":
    logger.info("Starting ingestion of POC & Playbook data into Qdrant...")
    ingest_l1_threat_intel()
    ingest_l2_playbooks()
    logger.info("Ingestion finished.")
