FROM python:3.11-slim

RUN pip install --no-cache-dir paho-mqtt bleak cryptography

WORKDIR /app
COPY bhyve_mqtt_bridge.py .

CMD ["python3", "-u", "bhyve_mqtt_bridge.py"]
