FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py checks.py run.py ./
EXPOSE 8081

# Persistent GZCTF checker-worker contract. The process stays alive and listens
# on :8081. POST /check with JSON {targetIp, targetPort, flag, round, teamId}
# returns {status, code}; GET /healthz is the readiness probe. Every request
# creates a fresh Target, so flags and team context are never reused between
# checks. Set GZCTF_CHECKER_TOKEN and send X-GZCTF-Checker-Token for auth.
# To add test cases, edit checks.py — no need to touch checker.py or run.py.
ENTRYPOINT ["python3", "run.py"]
