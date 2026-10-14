FROM postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
# Executable at build time: Harbor's runtime chmod fails on a read-only root.
COPY --chmod=0555 test.sh check.py /tests/
# Harbor re-uploads the collected artifact here; copies land only in volumes.
VOLUME ["/candidate", "/logs/artifacts"]
