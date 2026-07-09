import os
import json
import unittest
from unittest.mock import patch, MagicMock

# Import the functions to test
from ingest_to_vector_db import get_qwen_embedding, ensure_collection
from orchestrator import SoarOrchestrator
# Import llm_agent class
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "aegis-bank-deployment", "log-parser"))
from llm_agent import QwenSecurityAgent

class TestVectorDBIntegration(unittest.TestCase):

    def test_mock_embedding_generation(self):
        """Verify that get_qwen_embedding generates mock vectors when no API key is set."""
        # When DASHSCOPE_API_KEY is empty/missing
        with patch.dict(os.environ, {"EMBEDDING_PROVIDER": "mock"}):
            emb = get_qwen_embedding("test query string", api_key="")
        self.assertEqual(len(emb), 1024)
        # Unit vector check: sum of squares should be very close to 1.0
        sum_sq = sum(x*x for x in emb)
        self.assertAlmostEqual(sum_sq, 1.0, places=5)

    @patch("embedding_provider._bedrock_client")
    def test_bedrock_embedding_generation(self, mock_bedrock_client):
        """Verify Bedrock embedding responses are accepted for Qdrant ingestion."""
        body = MagicMock()
        body.read.return_value = json.dumps({"embedding": [0.1] * 1024}).encode("utf-8")
        mock_bedrock_client.return_value.invoke_model.return_value = {"body": body}

        with patch.dict(os.environ, {
            "EMBEDDING_PROVIDER": "bedrock",
            "BEDROCK_EMBEDDING_DIMENSIONS": "1024",
        }):
            emb = get_qwen_embedding("bedrock embedding test", api_key="")

        self.assertEqual(len(emb), 1024)
        mock_bedrock_client.return_value.invoke_model.assert_called_once()

    def test_ensure_collection_fallback(self):
        """Verify that ensure_collection returns False/handles connection error when Qdrant is offline."""
        # Point QDRANT_URL to an unreachable/invalid address to trigger exception
        with patch("ingest_to_vector_db.QDRANT_URL", "http://127.0.0.1:9999"):
            res = ensure_collection("temp_collection")
            self.assertFalse(res)

    @patch("requests.post")
    @patch("llm_agent.DASHSCOPE_API_KEY", "mock-key")
    def test_l1_agent_vector_query_graceful_failure(self, mock_post):
        """Verify that QwenSecurityAgent._query_vector_db_context degrades gracefully on failure."""
        agent = QwenSecurityAgent()
        
        # Scenario A: Qwen embeddings endpoint returns error
        mock_post.return_value.status_code = 500
        res = agent._query_vector_db_context("some threat log telemetry")
        self.assertEqual(res, "")

        # Scenario B: mock embedding works locally, Qdrant search returns 404
        mock_resp_qdrant = MagicMock()
        mock_resp_qdrant.status_code = 404
        
        mock_post.side_effect = None
        mock_post.return_value = mock_resp_qdrant
        res = agent._query_vector_db_context("some threat log telemetry")
        self.assertEqual(res, "")

    @patch("requests.post")
    @patch("orchestrator.DASHSCOPE_API_KEY", "mock-key")
    def test_l2_orchestrator_vector_query_graceful_failure(self, mock_post):
        """Verify that SoarOrchestrator._query_vector_db_playbooks degrades gracefully on failure."""
        # Disable LLM API Client creation for testing constructor by patching OpenAI
        with patch("orchestrator.OpenAI"), patch("orchestrator.redis.Redis"):
            orch = SoarOrchestrator()
            
            # Scenario A: Qdrant unreachable / HTTP error
            mock_post.return_value.status_code = 500
            res = orch._query_vector_db_playbooks("threat scenario")
            self.assertEqual(res, "")

            # Scenario B: Success returns correct playbooks block
            mock_resp_qdrant = MagicMock()
            mock_resp_qdrant.status_code = 200
            mock_resp_qdrant.json.return_value = {
                "result": [
                    {
                        "payload": {
                            "playbook_id": "PB-WEB-EDGE",
                            "name": "Web Server Edge Containment",
                            "steps": [{"type": "contain", "action_type": "block_ip"}]
                        }
                    }
                ]
            }
            
            mock_post.return_value = mock_resp_qdrant
            res = orch._query_vector_db_playbooks("threat scenario")
            self.assertIn("Playbook: PB-WEB-EDGE", res)
            self.assertIn("Web Server Edge Containment", res)

    def test_bedrock_qwen_response_extraction(self):
        """Verify Bedrock Runtime response bodies can be normalized to raw JSON text."""
        orch = SoarOrchestrator.__new__(SoarOrchestrator)
        raw = orch._extract_bedrock_text({
            "output": {
                "message": {
                    "content": [{"text": "{\"decision\":{\"final\":\"manual_review\"}}"}]
                }
            }
        })
        self.assertIn("manual_review", raw)

if __name__ == "__main__":
    unittest.main()
