FROM python:3.12-slim

RUN useradd --no-create-home --uid 10001 honeypot

WORKDIR /app
COPY services/magnusbilling-tls/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY services/magnusbilling-tls/app /app/app
RUN mkdir -p /certs && chown honeypot:honeypot /certs

USER honeypot
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/app/main.py"]
