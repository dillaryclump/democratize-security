FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY requirements.txt /opt/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /opt/requirements.txt \
    && install -d -o 999 -g 999 -m 0755 /dbsocket \
    && install -d -o 10001 -g 10001 -m 0755 /appsock
COPY --chmod=0444 app.py /application/app.py
COPY --chmod=0555 start.py /application/start.py
USER 10001:10001
WORKDIR /application
CMD ["python", "-B", "/application/start.py"]
