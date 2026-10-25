# Build context = repo root (so we can COPY both the checksystem and the
# black-box checkers that live under services/).
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY infra/checksystem/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY infra/checksystem/ /app/
COPY services/ /app/services/

ENV SERVICES_DIR=/app/services \
    DATA_DIR=/app/data \
    SCOREBOARD_PORT=8080
EXPOSE 8080
CMD ["python", "app.py"]
