FROM python:3.12-slim

WORKDIR /app
COPY server.py /app/server.py

RUN useradd -m -u 1000 zkp
USER zkp

EXPOSE 6000

CMD ["python3", "-u", "server.py"]