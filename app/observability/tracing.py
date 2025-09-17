"""OpenTelemetry configuration for Cloud Trace integration"""
import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes

def setup_tracing(project_id: str, service_name: str = "mobile-rag-api"):
    """Initialize OpenTelemetry with Cloud Trace exporter"""
    
    # Create resource with service information
    resource = Resource.create({
        ResourceAttributes.SERVICE_NAME: service_name,
        ResourceAttributes.SERVICE_VERSION: os.environ.get("SERVICE_VERSION", "1.0.0"),
        "cloud.provider": "gcp",
        "cloud.platform": "gcp_cloud_run",
        "cloud.region": os.environ.get("REGION", "us-central1"),
        "environment": os.environ.get("ENVIRONMENT", "dev")
    })
    
    # Create tracer provider
    provider = TracerProvider(resource=resource)
    
    # Create Cloud Trace exporter
    cloud_trace_exporter = CloudTraceSpanExporter(
        project_id=project_id
    )
    
    # Add batch processor for better performance
    provider.add_span_processor(
        BatchSpanProcessor(
            cloud_trace_exporter,
            max_queue_size=2048,
            max_export_batch_size=512,
            schedule_delay_millis=5000
        )
    )
    
    # Set global tracer provider
    trace.set_tracer_provider(provider)
    
    return trace.get_tracer(__name__)

def instrument_app(app):
    """Instrument FastAPI app with OpenTelemetry"""
    FastAPIInstrumentor.instrument_app(app)
    return app

# Custom span decorators for specific operations
def traced_operation(name: str, attributes: dict = None):
    """Decorator to add tracing to any function"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                try:
                    result = func(*args, **kwargs)
                    span.set_status(trace.Status(trace.StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(
                        trace.Status(trace.StatusCode.ERROR, str(e))
                    )
                    span.record_exception(e)
                    raise
        return wrapper
    return decorator
