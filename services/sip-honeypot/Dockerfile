FROM python:3.12-slim

RUN useradd --no-create-home --uid 10001 honeypot

WORKDIR /app
COPY services/sip-honeypot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY services/sip-honeypot/app /app/app

USER honeypot
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/app/main.py"]
