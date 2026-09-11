FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NEXSOLVE_ENV=production \
    NEXSOLVE_HOST=0.0.0.0 \
    NEXSOLVE_PORT=8001

# Install system dependencies (libpcap for Scapy capture dissection, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libpcap-dev \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for caching
COPY model_service/requirements.txt /app/model_service/requirements.txt
RUN pip install --no-cache-dir -r /app/model_service/requirements.txt

# Copy application code
COPY nexsolve_core /app/nexsolve_core
COPY ml /app/ml
COPY reporting /app/reporting
COPY demo /app/demo
COPY model_service /app/model_service
COPY data /app/data
COPY MITRE /app/MITRE
COPY conftest.py /app/conftest.py
COPY models /app/models
COPY world_model.py /app/world_model.py

# Create runtime directory and non-root user
RUN mkdir -p /app/runtime && \
    useradd -m -u 1000 nexsolve && \
    chown -R nexsolve:nexsolve /app

USER nexsolve

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "model_service.app:app", "--host", "0.0.0.0", "--port", "8001"]
