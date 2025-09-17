import os
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer

# --- OpenTelemetry setup ---
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor

SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "health-smoketest")

resource = Resource.create({"service.name": SERVICE_NAME})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)

# auto-instrument
app = FastAPI()
FastAPIInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()

# --- OAuth2 (Authorization Code; PKCE happens client-side) ---
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token"  # token exchange endpoint
)

@app.get("/health")
def health():
    with tracer.start_as_current_span("health-span"):
        return {"status": "OK"}

@app.get("/auth")
def auth(token: str = Depends(oauth2_scheme)):
    # NOTE: This smoke test only checks that a Bearer token is presented.
    # In production, VERIFY the token (issuer, audience, signature via JWKS).
    with tracer.start_as_current_span("auth-span"):
        return {"message": "Authenticated"}
