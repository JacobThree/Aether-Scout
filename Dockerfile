FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY aether_scout ./aether_scout
RUN pip install --no-cache-dir .

USER nobody
ENTRYPOINT ["aether-scout"]
