FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code files
COPY *.py .
COPY *.json .
COPY connectors/ ./connectors/

ENTRYPOINT ["python", "main.py"]
