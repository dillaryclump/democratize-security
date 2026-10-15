FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# The same locked, hash-checked dependencies the verifier runs the app with.
COPY app-requirements.txt /opt/app-requirements.txt
RUN python -m venv /opt/app \
    && /opt/app/bin/pip install --no-cache-dir --no-deps --require-hashes \
       --only-binary :all: -r /opt/app-requirements.txt
ENV PATH=/opt/app/bin:$PATH
WORKDIR /candidate
COPY app.py /candidate/app.py
RUN chown -R 10001:10001 /candidate
# The root filesystem is read-only. Docker copies files only into volumes, so
# the submission and the oracle's solution upload need image-declared volumes.
VOLUME ["/candidate", "/solution"]
