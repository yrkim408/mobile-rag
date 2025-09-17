import os
import logging
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer

# ---- OpenTelemetry → Cloud Trace ----
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor

try:
    from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
    service_name = os.getenv("OTEL_SERVICE_NAME", "health-smoketest")
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
    trace.set_tracer_provider(provider)
except Exception as e:
    logging.getLogger("uvicorn.error").warning(f"OTel init skipped: {e}")

from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor

app = FastAPI()
FastAPIInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()
tracer = trace.get_tracer(__name__)

# ---- OAuth2 (Authorization Code; PKCE handled by the client) ----
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
)

@app.get("/health", include_in_schema=False)
def health():
    with tracer.start_as_current_span("health-span"):
        return {"status": "OK"}

@app.get("/auth")
def auth(token: str = Depends(oauth2_scheme)):
    # NOTE: For smoke test only. In production, verify JWT (issuer/audience/JWKS).
    with tracer.start_as_current_span("auth-span"):
        return {"message": "Authenticated"}
