FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/data/pcapdiag.db

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py analysis.py db.py pcaputil.py fragment.py ./
COPY templates ./templates

RUN mkdir -p /data && useradd -r -u 10001 app && chown -R app /data
USER app

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "300", "app:app"]
