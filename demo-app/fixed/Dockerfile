# Phase 1 baseline. P3 hardens this file in Phase 3.
# Fixed V4: Runs as non-root user (appuser)
# Fixed V5: Pinned base image with specific tag
# Fixed V8: HEALTHCHECK instruction added

FROM python:3.11.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fixed V4: Create and use non-root user
RUN useradd --no-create-home --shell /bin/false appuser
USER appuser

EXPOSE 5000

# Fixed V8: HEALTHCHECK added
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app.py"]
