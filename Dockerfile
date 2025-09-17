FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy source after deps (better cache)
COPY . .

# Cloud Run provides $PORT; default to 8080 locally
ENV PORT=8080
# Default entry module; we use main:app
ENV APP_MODULE=main:app

# Use sh -c so env vars expand
CMD ["sh","-c","uvicorn ${APP_MODULE} --host 0.0.0.0 --port ${PORT}"]
