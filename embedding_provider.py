import hashlib
import json
import logging
import math
import os
import random

import requests

logger = logging.getLogger("soar-engine.embedding-provider")


def _embedding_dimensions() -> int:
    return int(os.getenv("BEDROCK_EMBEDDING_DIMENSIONS", os.getenv("VECTOR_EMBEDDING_DIMENSIONS", "1024")))


def stable_mock_embedding(text: str, size: int | None = None) -> list[float]:
    dimension = size or _embedding_dimensions()
    seed = int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")
    rng = random.Random(seed)
    vector = [rng.uniform(-1.0, 1.0) for _ in range(dimension)]
    norm = math.sqrt(sum(x * x for x in vector)) or 1.0
    return [x / norm for x in vector]


def _bedrock_client(region: str):
    from botocore.config import Config
    from botocore.session import Session

    timeout_seconds = int(os.getenv("BEDROCK_TIMEOUT_SECONDS", os.getenv("LLM_TIMEOUT_SECONDS", "10")))
    return Session().create_client(
        "bedrock-runtime",
        region_name=region,
        config=Config(
            connect_timeout=min(timeout_seconds, 10),
            read_timeout=timeout_seconds,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )


def _bedrock_embedding(text: str) -> list[float]:
    region = os.getenv("BEDROCK_EMBEDDING_REGION", os.getenv("AWS_REGION", "us-east-1"))
    model_id = os.getenv("BEDROCK_EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0")
    dimensions = _embedding_dimensions()
    payload = {
        "inputText": text,
        "dimensions": dimensions,
        "normalize": True,
    }
    response = _bedrock_client(region).invoke_model(
        modelId=model_id,
        body=json.dumps(payload),
        contentType="application/json",
        accept="application/json",
    )
    data = json.loads(response["body"].read())
    vector = data.get("embedding") or data.get("embeddingsByType", {}).get("float")
    if not vector:
        raise ValueError(f"Bedrock embedding response did not include an embedding vector: {data.keys()}")
    return vector


def _dashscope_embedding(text: str, api_key: str) -> list[float]:
    if not api_key or api_key.startswith("mock"):
        return stable_mock_embedding(text)

    base_url = os.getenv("QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
    model = os.getenv("TEXT_EMBEDDING_MODEL_NAME", "text-embedding-v3")
    response = requests.post(
        f"{base_url}/embeddings",
        json={"model": model, "input": text},
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        timeout=int(os.getenv("EMBEDDING_TIMEOUT_SECONDS", "15")),
    )
    response.raise_for_status()
    return response.json()["data"][0]["embedding"]


def get_text_embedding(text: str, dashscope_api_key: str | None = None) -> list[float]:
    provider = os.getenv("EMBEDDING_PROVIDER", "").strip().lower()
    if not provider:
        provider = "bedrock" if os.getenv("LLM_PROVIDER", "").strip().lower() == "bedrock" else "dashscope"

    try:
        if provider == "bedrock":
            return _bedrock_embedding(text)
        if provider == "dashscope":
            return _dashscope_embedding(text, dashscope_api_key or os.getenv("DASHSCOPE_API_KEY", ""))
        if provider == "mock":
            return stable_mock_embedding(text)
    except Exception as exc:
        logger.warning("Embedding provider %s failed (%s). Falling back to deterministic local vector.", provider, exc)

    return stable_mock_embedding(text)
