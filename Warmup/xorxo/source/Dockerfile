FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir pycryptodome

COPY server.py /app/server.py

ENV GZCTF_FLAG="JCC{placeholder}"

EXPOSE 5000

CMD ["python", "server.py"]