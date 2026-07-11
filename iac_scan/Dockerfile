# =============================================================================
# NisargHunter AI IaC/DevOps Configuration Scanner - Container
# =============================================================================
# Offline static analysis of Dockerfiles, docker-compose, Kubernetes manifests,
# GitHub Actions workflows, and Terraform for security misconfigurations.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="NisargHunter AI Project"
LABEL description="IaC/DevOps misconfiguration scanner for NisargHunter AI"

WORKDIR /app

# git is required to shallow-clone target repositories
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY iac_scan/requirements.txt /tmp/iac_scan_requirements.txt
RUN pip install --no-cache-dir -r /tmp/iac_scan_requirements.txt

COPY iac_scan/ ./iac_scan/
COPY graph_db/ ./graph_db/

RUN mkdir -p iac_scan/output

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "iac_scan/main.py"]
