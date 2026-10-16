FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
WORKDIR /candidate
# The root filesystem is read-only and /candidate is a size-bounded tmpfs
# volume that Docker does not populate from the image: the entrypoint copies
# this starter in.
RUN mkdir -m 0755 /opt/starter \
    && printf '%s\n' '{"enabled":false,"predicate":"all"}' > /opt/starter/policy.json \
    && chmod 0644 /opt/starter/policy.json
COPY --chmod=0555 seed.sh /opt/seed.sh
ENTRYPOINT ["/opt/seed.sh"]
