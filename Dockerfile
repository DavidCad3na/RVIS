# Dockerfile
# Build : docker build -t rvis .
# Run   : docker run --rm --cap-add=NET_ADMIN rvis -t <target>

FROM python:3.11-slim

LABEL maintainer="RVIS"
LABEL description="Recon Vulnerability Identification System"

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# reports/ output volume
VOLUME ["/app/reports"]

RUN useradd -m rvisuser && chown -R rvisuser:rvisuser /app
USER rvisuser

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
