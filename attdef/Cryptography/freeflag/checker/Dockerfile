FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py checks.py run.py ./

# enochecker3 exit-code contract: 0 Ok / 1 Mumble / 2 Offline / 3 InternalError.
# The platform runs this once per (team, tick) with GZCTF_TARGET_IP/PORT +
# GZCTF_FLAG in the environment. Build + push, then set `ad.checkerImage`
# in challenge.yml. To add test cases, edit checks.py — no need to touch
# checker.py or run.py.
ENTRYPOINT ["python3", "run.py"]
