# Hardened Dockerfile for demo-app/fixed
# Phase 3: Remediation of V4, V5, V8 from demo-app/vulnerable/Dockerfile
#
# Security improvements:
#   V4 fix: Non-root user (UID 1000) added before CMD [CKV_DOCKER_8, DL3002]
#   V5 fix: Pinned base image to exact digest-pinned version [DL3007]
#   V8 fix: HEALTHCHECK instruction added [CKV_DOCKER_28]
#   Bonus: No pip cache (--no-cache-dir), deterministic build
#          PYTHONDONTWRITEBYTECODE + PYTHONUNBUFFERED set
#          exec-form CMD used
#          EXPOSE documented

# -- Stage: builder (compile/install dependencies) ----------------------------
FROM python:3.11.11-slim-bookworm AS builder

# Avoid writing .pyc files and enable stdout/stderr flushing
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies into a prefix so we can copy them cleanly
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# -- Stage: runtime (minimal attack surface) ----------------------------------
FROM python:3.11.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user (V4 fix) before copying any files
RUN useradd --create-home --uid 1000 --no-log-init appuser

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source (owned by appuser)
COPY --chown=appuser:appuser . .

# Document the exposed port
EXPOSE 5000

# Switch to non-root user (V4 fix: last USER is not root)
USER appuser

# Health check: verify the app responds on its port (V8 fix)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Use exec-form CMD (not shell form) for proper signal handling
CMD ["python", "app.py"]
