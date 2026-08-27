FROM python:latest

RUN apt update
RUN apt install socat -y

WORKDIR /app

COPY ./chall.py ./
COPY ./requirements.txt ./

RUN pip install -r requirements.txt

CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"python -u ./chall.py"
