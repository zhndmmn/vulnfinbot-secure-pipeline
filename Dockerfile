# Mini-VulnFinBot container image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Pull in Debian security fixes published since the base image was built
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Upgrade the packaging tools, install the app, then delete the ensurepip bundle:
# its old pip wheel (and the setuptools code it carries) was flagged by Trivy
# (CVE-2025-47273) and a runtime container never needs to bootstrap pip.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /usr/local/lib/python3.12/ensurepip

COPY app/ ./app/
COPY run.py .

# Run as an unprivileged user, never root
RUN useradd --system --uid 10001 --no-create-home appuser
USER 10001

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health',timeout=2).status==200 else 1)"

# gunicorn instead of the Flask dev server; listens on all interfaces only inside the container
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "--access-logfile", "-", "run:app"]
