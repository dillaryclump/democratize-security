# Candidate runtime only: dependencies and the trusted launcher, no verifier code.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY app-requirements.txt /opt/app-requirements.txt
RUN python -m venv /opt/app \
    && /opt/app/bin/pip install --no-cache-dir --no-deps --require-hashes \
       --only-binary :all: -r /opt/app-requirements.txt
COPY --chmod=0444 launch.py /opt/launch.py
