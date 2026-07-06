FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code files
COPY main.py .
COPY config.py .
COPY schema_validator.py .
COPY db_verifier.py .
COPY orchestrator.py .
COPY playbook_executor.py .
COPY action_worker.py .
COPY playbook_runner.py .
COPY playbooks.json .
COPY secret_manager.py .
COPY rate_limiter.py .
COPY policy_evaluator.py .
COPY whitelist.json .
COPY audit_logger.py .
COPY connectors/ ./connectors/

ENTRYPOINT ["python", "main.py"]
