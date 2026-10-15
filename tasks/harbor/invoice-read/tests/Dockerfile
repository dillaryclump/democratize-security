FROM postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
# Debian's Python 3.11 with the locked versions, compiled separately for 3.11.
COPY verifier-requirements.txt /opt/verifier-requirements.txt
RUN python3 -m venv /opt/verifier \
    && /opt/verifier/bin/pip install --no-cache-dir --no-deps --require-hashes \
       --only-binary :all: -r /opt/verifier-requirements.txt
# Executable at build time: Harbor's runtime chmod fails on a read-only root.
COPY --chmod=0555 test.sh run.py verify.py fixture.py /tests/
# Harbor re-uploads the collected artifact here; copies land only in volumes.
# /candidate is the project-scoped volume shared read-only with the app.
VOLUME ["/logs/artifacts"]
