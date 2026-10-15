# Trusted collector image: the reviewed script and an output volume only.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY --chmod=0444 collect.py /opt/collect.py
# Docker copies files only into volumes on a read-only root; Harbor collects
# the checked copy from here.
RUN mkdir /candidate && chown 10001:10001 /candidate
VOLUME ["/candidate"]
