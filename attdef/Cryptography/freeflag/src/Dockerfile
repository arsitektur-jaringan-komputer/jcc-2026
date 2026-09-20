FROM python:3.12-alpine

# supervisor runs as PID 1 (see supervisord.conf) so the service runs as a child:
# if it crashes, supervisord auto-restarts it in place WITHOUT the container
# exiting, so a botched exploit won't drop the box and the team keeps its
# filesystem patches. NOTE: the platform has no in-place restart action — the
# operator "Force Restart" / team "Reset" destroys + recreates the container from
# this image (new IP), losing patches. Installed via pip to reuse the image python.
RUN apk add --no-cache socat \
	&& pip install --no-cache-dir supervisor pycryptodome

# No baked flag. The platform supplies the live, rotating flag at the path in
# $GZCTF_FLAG_FILE (Docker: /flag bind-mount; Kubernetes: /gzctf-flag/flag,
# written by the flag-pull sidecar). ALWAYS read $GZCTF_FLAG_FILE — a service
# that hardcodes /flag works on Docker but serves a stale value on K8s. There
# is no GZCTF_FLAG env var for the service (it would freeze at start). Treat a
# missing file as "no flag yet" (warmup, before the first flag is planted).
COPY freeflag/server.py /server.py
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 5555

# supervisord as PID 1; it runs service.py (pure stdlib http.server) as a child.
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

