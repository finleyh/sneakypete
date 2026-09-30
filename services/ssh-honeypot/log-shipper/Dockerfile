FROM python:3.12-slim

RUN useradd --no-create-home --uid 10001 honeypot

WORKDIR /app
COPY services/ssh-honeypot/log-shipper/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common /app/common
COPY services/ssh-honeypot/log-shipper/shipper.py /app/shipper.py

USER honeypot
ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/shipper.py"]
