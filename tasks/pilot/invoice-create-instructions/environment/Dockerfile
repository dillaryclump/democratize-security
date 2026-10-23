FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
# The same locked, hash-checked dependencies the verifier runs the app with.
COPY app-requirements.txt /opt/app-requirements.txt
RUN python -m venv /opt/app \
    && /opt/app/bin/pip install --no-cache-dir --no-deps --require-hashes \
       --only-binary :all: -r /opt/app-requirements.txt
ENV PATH=/opt/app/bin:$PATH
WORKDIR /candidate
# The root filesystem is read-only and /candidate is a size-bounded tmpfs
# volume that Docker does not populate from the image: the entrypoint copies
# this starter in.
COPY app.py /opt/starter/app.py
RUN chmod 0755 /opt/starter && chmod 0644 /opt/starter/app.py
COPY --chmod=0555 seed.sh /opt/seed.sh
ENTRYPOINT ["/opt/seed.sh"]
