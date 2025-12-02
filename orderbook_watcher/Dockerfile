FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY jmcore/requirements.txt /app/jmcore/
RUN pip install --no-cache-dir -r /app/jmcore/requirements.txt

# Copy jmcore source (needed for editable install in requirements.txt)
COPY jmcore /app/jmcore

COPY orderbook_watcher/requirements.txt /app/orderbook_watcher/
RUN pip install --no-cache-dir -r /app/orderbook_watcher/requirements.txt

COPY orderbook_watcher/src /app/orderbook_watcher/src
COPY orderbook_watcher/static /app/orderbook_watcher/static

ENV PYTHONPATH=/app/jmcore/src:/app/orderbook_watcher/src

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

CMD ["python", "-m", "orderbook_watcher.main"]
