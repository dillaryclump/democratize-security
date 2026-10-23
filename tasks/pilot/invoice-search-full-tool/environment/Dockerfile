FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# full_tool only: PostgreSQL for the agent's private self-check cluster. No
# default cluster is created; check-isolation runs initdb in its bounded /tmp.
RUN mkdir -p /etc/postgresql-common \
    && echo 'create_main_cluster = false' > /etc/postgresql-common/createcluster.conf \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-15=15.19-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
# initdb needs a passwd entry for the agent's fixed uid.
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /tmp \
    --shell /usr/sbin/nologin agent
# The same locked, hash-checked dependencies the verifier runs the app with.
COPY app-requirements.txt /opt/app-requirements.txt
RUN python -m venv /opt/app \
    && /opt/app/bin/pip install --no-cache-dir --no-deps --require-hashes \
       --only-binary :all: -r /opt/app-requirements.txt
ENV PATH=/opt/app/bin:$PATH
WORKDIR /candidate
# The self-check: public development probes and data, never the grading data.
COPY --chmod=0555 check-isolation /opt/tools/check-isolation
COPY --chmod=0444 fixture.py verify.py /opt/tools/
# The root filesystem is read-only and /candidate is a size-bounded tmpfs
# volume that Docker does not populate from the image: the entrypoint copies
# this starter in.
COPY app.py /opt/starter/app.py
RUN chmod 0755 /opt/starter && chmod 0644 /opt/starter/app.py
COPY --chmod=0555 seed.sh /opt/seed.sh
ENTRYPOINT ["/opt/seed.sh"]
