FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    clickhouse-driver==0.2.7 \
    drain3==0.9.11 \
    pandas \
    pyarrow \
    && rm -rf /root/.cache

COPY collector.py .
COPY parsers/ ./parsers/

CMD ["python", "-u", "collector.py"]