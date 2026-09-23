FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends supervisor socat make vim nano \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py Makefile /app/
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 6969
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
