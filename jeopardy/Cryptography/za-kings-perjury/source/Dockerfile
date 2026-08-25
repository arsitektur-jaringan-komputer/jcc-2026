FROM python:3.12-slim

WORKDIR /app
COPY server.py /app/server.py
COPY entrypoint.sh /entrypoint.sh 

RUN useradd -m -u 1000 zkp
RUN chmod +x /entrypoint.sh
RUN chown zkp:zkp /app
USER zkp

EXPOSE 6000

CMD ["/entrypoint.sh"]