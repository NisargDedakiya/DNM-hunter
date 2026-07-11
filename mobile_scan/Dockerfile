# =============================================================================
# NisargHunter AI Mobile APK Static Analysis - Container
# =============================================================================
# Static analysis of uploaded Android APKs (manifest hardening, exported
# components, dangerous permissions, hardcoded secrets) via androguard.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="NisargHunter AI Project"
LABEL description="Mobile APK static analysis scanner for NisargHunter AI"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY mobile_scan/requirements.txt /tmp/mobile_scan_requirements.txt
RUN pip install --no-cache-dir -r /tmp/mobile_scan_requirements.txt

COPY mobile_scan/ ./mobile_scan/
COPY graph_db/ ./graph_db/

RUN mkdir -p mobile_scan/output

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "mobile_scan/main.py"]
