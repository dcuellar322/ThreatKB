FROM node:26.10.0-bookworm-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.14.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/threatkb
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libmagic1 git libssl-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
COPY --from=frontend /app/static/workbench ./app/static/workbench
RUN useradd --create-home threatkb && mkdir -p instance && chown -R threatkb:threatkb /opt/threatkb
USER threatkb
EXPOSE 5000
ENTRYPOINT ["/bin/sh", "/opt/threatkb/docker-entrypoint.sh"]
