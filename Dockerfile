FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/threatkb
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libmagic1 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home threatkb && mkdir -p instance && chown -R threatkb:threatkb /opt/threatkb
USER threatkb
EXPOSE 5000
ENTRYPOINT ["/bin/sh", "/opt/threatkb/docker-entrypoint.sh"]
