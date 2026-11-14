# WARNING: This Dockerfile contains INTENTIONAL security flaws for testing.
# V4: Runs as root (no USER instruction) - Hadolint DL3002, Checkov CKV_DOCKER_8
# V5: Uses unpinned base image tag - Hadolint DL3007
# V8: No HEALTHCHECK instruction - Checkov CKV_DOCKER_28
# DO NOT deploy this image.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# V4: No USER instruction - runs as root
# V5: Base image uses -slim without digest pinning
# V8: No HEALTHCHECK

EXPOSE 5000

CMD ["python", "app.py"]
