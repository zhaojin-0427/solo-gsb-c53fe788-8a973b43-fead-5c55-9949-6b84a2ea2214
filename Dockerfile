FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ZIPRECOVER_DATA_DIR=/data

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --system --uid 10001 ziprecover \
    && mkdir -p /data \
    && chown ziprecover /data
USER ziprecover

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
