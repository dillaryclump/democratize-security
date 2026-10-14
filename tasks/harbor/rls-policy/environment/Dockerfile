FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
WORKDIR /candidate
RUN printf '%s\n' '{"enabled":false,"predicate":"all"}' > policy.json \
    && chown -R 10001:10001 /candidate
# The root filesystem is read-only. Docker copies files only into volumes, so
# the submission and the oracle's solution upload need image-declared volumes.
VOLUME ["/candidate", "/solution"]
