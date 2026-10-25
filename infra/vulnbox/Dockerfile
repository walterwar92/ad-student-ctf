# Build context = repo root. One image, run once per team.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Union of what the three services need (web: flask, crypto: flask + bundled
# aescipher.py, depot: stdlib only). No external crypto dep => offline-friendly.
RUN pip install --no-cache-dir flask

COPY services/ /app/services/
COPY infra/vulnbox/supervisor.py /app/supervisor.py

EXPOSE 5001 5002 5003
CMD ["python", "supervisor.py"]
