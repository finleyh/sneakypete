FROM python:3.12-slim

RUN useradd --no-create-home --uid 10001 honeypot

WORKDIR /app
COPY services/magnusbilling-honeypot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY services/magnusbilling-honeypot/app /app/app

USER honeypot
ENV PYTHONUNBUFFERED=1
WORKDIR /app/app
CMD ["python", "run.py"]
