# NoteVault image.
#
# Fix for F-09 (CWE-250 / CWE-798 / CWE-1104):
#  - base image pinned by digest (python:3.12-slim as of 2026-10-28), so the
#    build is reproducible and a retagged/compromised upstream tag can't be
#    pulled silently; -slim also shrinks the attack surface vs. the full tag
#  - no secret baked into the image (APP_SECRET removed — pass it at runtime
#    via `docker compose` `environment:` / a secrets file instead, never ENV
#    in the image, so it never lands in a layer `docker history` can read)
#  - only the files the app needs at runtime are copied in (requirements
#    first for layer caching, then app.py only) — .git/, *.md, screenshots/
#    etc. never enter the image, instead of relying on COPY . . + a
#    .dockerignore to exclude them after the fact
#  - runs as a dedicated non-root user, so F-07-class RCE lands in a
#    low-privilege account instead of root
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN useradd --no-create-home --uid 10001 notevault && \
    chown -R notevault /app
USER notevault

EXPOSE 8080
CMD ["python", "app.py"]
