FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS python_runtime
FROM postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826
COPY --from=python_runtime /usr/local /usr/local
COPY requirements.txt /opt/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/requirements.txt \
    && install -d -o postgres -g postgres -m 0755 /dbsocket \
    && install -d -o 10001 -g 10001 -m 0755 /appsock
COPY --chmod=0555 test.sh check.py reference.py /tests/
COPY expected.sha256 /tests/expected.sha256
VOLUME ["/candidate", "/logs/artifacts"]
