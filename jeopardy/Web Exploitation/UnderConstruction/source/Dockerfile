FROM denoland/deno:latest

RUN apt update
RUN apt install -y chromium

WORKDIR /app

COPY ./app/deno.json /app/deno.json

RUN deno install

COPY ./app /app

CMD ["deno", "run", "start"]