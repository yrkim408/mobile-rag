"""Mobile RAG API with OAuth/PKCE and OpenTelemetry"""
import os
import json
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse, JSONResponse
from contextlib import asynccontextmanager
import time
from datetime import datetime

# Import our modules
from app.auth.oauth_manager import OAuthManager
from app.observability.tracing import setup_tracing, instrument_app, traced_operation

# Get project ID from metadata server or environment
def get_project_id():
    """Get GCP project ID from environment or metadata server"""
    project_id = os.environ.get("GCP_PROJECT")
    if not project_id:
        try:
            import requests
            response = requests.get(
                "http://metadata.google.internal/computeMetadata/v1/project/project-id",
                headers={"Metadata-Flavor": "Google"},
                timeout=1
            )
            project_id = response.text
        except:
            project_id = "mobile-rag-dev"  # Fallback for local development
    return project_id

# Initialize services
PROJECT_ID = get_project_id()
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    print(f"Starting Mobile RAG API - Project: {PROJECT_ID}, Environment: {ENVIRONMENT}")
    setup_tracing(PROJECT_ID, f"mobile-rag-api-{ENVIRONMENT}")
    
    # Initialize OAuth manager
    app.state.oauth_manager = OAuthManager(PROJECT_ID)
    
    yield
    
    # Shutdown
    print("Shutting down Mobile RAG API")

# Create FastAPI app
app = FastAPI(
    title="Mobile RAG API",
    description="Mobile RAG with Agentic AI - Sprint 0",
    version="1.0.0",
    lifespan=lifespan
)

# Instrument app with OpenTelemetry
instrument_app(app)

# OAuth2 scheme for security
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl="https://oauth2.googleapis.com/token",
    auto_error=False
)

# Middleware for request tracking
@app.middleware("http")
async def add_request_tracking(request: Request, call_next):
    """Add request ID and timing to all requests"""
    request_id = request.headers.get("X-Request-ID", f"req-{int(time.time()*1000)}")
    start_time = time.time()
    
    # Add to trace context
    from opentelemetry import trace
    tracer = trace.get_tracer(__name__)
    
    with tracer.start_as_current_span("http_request") as span:
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.set_attribute("request.id", request_id)
        
        response = await call_next(request)
        
        # Add response metadata
        process_time = time.time() - start_time
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        
        span.set_attribute("http.status_code", response.status_code)
        span.set_attribute("process.time", process_time)
        
        return response

# Health check endpoint
@app.get("/health")
@traced_operation("health_check")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "project_id": PROJECT_ID,
        "environment": ENVIRONMENT,
        "version": "1.0.0"
    }

# OAuth login endpoint
@app.get("/auth/login")
async def login(request: Request):
    """Initiate OAuth login with PKCE"""
    oauth_manager = request.app.state.oauth_manager
    
    # Generate authorization URL with PKCE
    auth_url, state = oauth_manager.create_authorization_url(
        user_id="temp-user-id"  # In production, generate unique session ID
    )
    
    # In production, store state in Redis/Firestore
    response = RedirectResponse(url=auth_url)
    response.set_cookie(key="oauth_state", value=state, httponly=True, secure=True)
    
    return response

# OAuth callback endpoint
@app.get("/auth/callback")
async def auth_callback(request: Request, code: str, state: str):
    """Handle OAuth callback and token exchange"""
    oauth_manager = request.app.state.oauth_manager
    
    try:
        # Exchange code for tokens
        tokens = await oauth_manager.exchange_code(code, state)
        
        # In production, store tokens securely and create session
        return JSONResponse({
            "status": "success",
            "message": "Authentication successful",
            "access_token": tokens.get("access_token"),
            "expires_in": tokens.get("expires_in")
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Protected endpoint example
@app.get("/api/protected")
async def protected_route(token: Optional[str] = Depends(oauth2_scheme)):
    """Example protected endpoint requiring authentication"""
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # In production, validate token with Google or your auth provider
    return {
        "message": "Access granted to protected resource",
        "token_preview": token[:20] + "..." if len(token) > 20 else token
    }

# Metrics endpoint for monitoring
@app.get("/metrics")
@traced_operation("metrics_export")
def get_metrics():
    """Export basic metrics for monitoring"""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "project_id": PROJECT_ID,
        "environment": ENVIRONMENT,
        "health": "ok",
        "requests_total": 0,  # In production, track with prometheus_client
        "latency_p95": 0.0,  # In production, calculate from traces
        "error_rate": 0.0  # In production, calculate from logs
    }

# Research endpoint stub (for MVP demo)
@app.post("/research")
@traced_operation("research_query")
async def research(query: dict, token: Optional[str] = Depends(oauth2_scheme)):
    """Research endpoint for RAG queries"""
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Placeholder for Sprint 1+ implementation
    return {
        "query": query.get("q", ""),
        "status": "pending",
        "message": "Research endpoint will be implemented in MVP week"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
