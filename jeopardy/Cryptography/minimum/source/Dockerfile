FROM python:3.12-slim

RUN pip install --no-cache-dir pycryptodome setproctitle

WORKDIR /app
COPY server.py .
COPY utils/ utils/

EXPOSE 13424
CMD ["python3", "server.py"]
