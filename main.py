from fastapi import FastAPI, Depends 
from fastapi.security import OAuth2AuthorizationCodeBearer 
app = FastAPI() 
oauth2_scheme = OAuth2AuthorizationCodeBearer( 
    authorizationUrl="https://accounts.google.com/o/oauth2/auth", 
    tokenUrl="https://oauth2.googleapis.com/token" 
) 
@app.get("/auth") 
async def auth(token: str = Depends(oauth2_scheme)): 
    return {"message": "Authenticated"} 
# OpenTelemetry → Cloud Trace 
from opentelemetry import trace 
from opentelemetry.sdk.trace import TracerProvider 
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter 
from opentelemetry.sdk.trace.export import BatchSpanProcessor 
provider = TracerProvider() 
provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter())) 
trace.set_tracer_provider(provider) 
