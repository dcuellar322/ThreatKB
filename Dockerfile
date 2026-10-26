FROM node:26.12.1-bookworm-slim@sha256:28147155d47dc31abe0a46e0d12b59b2fb3d0a2dcc5dc65fce76a074180b16fe AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56 AS python-base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /opt/threatkb
# Package indexes are frozen at the same ten-day cutoff as the language locks.
RUN printf 'Types: deb\nURIs: https://snapshot.debian.org/archive/debian/20261005T000000Z/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n\nTypes: deb\nURIs: https://snapshot.debian.org/archive/debian-security/20261005T000000Z/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\nCheck-Valid-Until: no\n' > /etc/apt/sources.list.d/debian.sources

FROM python-base AS python-dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-build.txt ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements-build.txt && pip wheel --no-cache-dir --no-build-isolation --no-deps --wheel-dir /wheels -r requirements.txt

FROM python-base AS runtime-base
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
COPY --from=python-dependencies /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt && rm -rf /wheels
RUN useradd --create-home --uid 1000 threatkb && mkdir -p instance && chown threatkb:threatkb instance

# The standalone builders do not need a frontend build, database, or Redis.
FROM runtime-base AS content
COPY --chown=threatkb:threatkb threatkb_content/ ./threatkb_content/
COPY --chown=threatkb:threatkb detections/ ./detections/
COPY --chown=threatkb:threatkb scripts/ ./scripts/
USER threatkb
ENTRYPOINT ["python", "-m", "threatkb_content"]

FROM runtime-base AS application
COPY --chown=threatkb:threatkb . .
COPY --from=frontend --chown=threatkb:threatkb /app/static/workbench ./app/static/workbench
USER threatkb
EXPOSE 5000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=4)"
ENTRYPOINT ["/bin/sh", "/opt/threatkb/docker-entrypoint.sh"]

FROM application AS verification
ENV PYTEST_ADDOPTS="-o cache_dir=/tmp/threatkb-pytest-cache" RUFF_CACHE_DIR=/tmp/threatkb-ruff-cache
USER root
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements-dev.txt
USER threatkb

# Keep the default build free of development/test dependencies and compilers.
FROM application AS production

FROM frontend AS frontend-quality
COPY detections/ /detections/
COPY .github/workflows/ /.github/workflows/
COPY docker-compose.yml /docker-compose.yml
COPY package.json /package.json
RUN npm run format:check

FROM verification AS quality
COPY --from=frontend-quality /frontend/package.json /tmp/checked-frontend-package.json
RUN sh scripts/check_backend.sh

FROM application AS default
