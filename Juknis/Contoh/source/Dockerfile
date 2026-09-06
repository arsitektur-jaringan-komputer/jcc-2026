FROM python:3.11-alpine

# Install netcat
RUN apk add --no-cache netcat-openbsd

WORKDIR /app
COPY python.py .

# Listen continuously on port 8080 and execute python.py per connection
CMD ["sh", "-c", "while true; do nc -lk -p 8080 -e python python.py; done"]