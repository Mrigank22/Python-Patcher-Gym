# Container image that serves the CyberSec secure-code-repair environment over
# HTTP/WebSocket (OpenEnv). The grader runs candidate code in a subprocess, so
# run the container with limited privileges in production.
#
#   docker build -t cybersec-env -f cybersec_env/server/Dockerfile .
#   docker run --rm -p 8000:8000 cybersec-env
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Create an unprivileged user to run the (untrusted-code-executing) grader.
RUN useradd --create-home --uid 10001 runner

COPY cybersec_env/server/requirements.txt /app/server-requirements.txt
RUN pip install --no-cache-dir -r /app/server-requirements.txt

# The environment serves PyYAML-based tasks, so pyyaml is in the requirements.
COPY cybersec_env /app/cybersec_env
COPY openenv.yaml /app/openenv.yaml

ENV PYTHONPATH=/app
ENV CSE_MAX_SESSIONS=8 CSE_REWARD_MODE=shaped CSE_TIMEOUT=8

USER runner

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

CMD ["uvicorn", "cybersec_env.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
