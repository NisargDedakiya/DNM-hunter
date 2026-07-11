# =============================================================================
# NisargHunter AI Cloud Storage Bucket Enumeration - Container
# =============================================================================
# Unauthenticated, read-only enumeration of public AWS S3 / GCS / Azure Blob
# storage exposure via bucket-name permutation.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="NisargHunter AI Project"
LABEL description="Cloud storage bucket enumeration scanner for NisargHunter AI"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY cloud_recon/requirements.txt /tmp/cloud_recon_requirements.txt
RUN pip install --no-cache-dir -r /tmp/cloud_recon_requirements.txt

COPY cloud_recon/ ./cloud_recon/
COPY graph_db/ ./graph_db/

RUN mkdir -p cloud_recon/output

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "cloud_recon/main.py"]
