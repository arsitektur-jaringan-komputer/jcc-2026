FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install curl \
    build-essential libcunit1-dev libudev-dev socat

# Proper user + group
RUN useradd -m -u 1000 -s /bin/bash ctf
WORKDIR /home/ctf

COPY chall /home/ctf/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown -R root:root /home/ctf && \
    chmod -R 777 /home/ctf && \
    chmod +x /home/ctf/chall

EXPOSE 1337

# Run socat as ctf directly
USER ctf
CMD ["/entrypoint.sh"]
# ENTRYPOINT ["socat", "TCP-LISTEN:4009,reuseaddr,fork,nodelay", "EXEC:timeout 60 /home/ctf/chall"]
