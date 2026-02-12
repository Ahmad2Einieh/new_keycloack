import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from routers.auth import auth_router
from routers.user import user_router
from routers.org import org_router
from routers.team import team_router
from core.logger import setup_logging, get_logger, log_http_response

# Setup logging
setup_logging(level="INFO")
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("Application starting up...")
    yield
    logger.info("Application shutting down...")


# Create FastAPI app
app = FastAPI(
    title="Keycloak Advanced RBAC System",
    lifespan=lifespan
)


# Middleware for logging all requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests and responses."""
    start_time = time.time()
    user_id = None

    # Extract user ID from request state if available (set by auth middleware)
    if hasattr(request.state, "user"):
        user_id = request.state.user.get("sub")

    try:
        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000

        log_http_response(
            logger=logger,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            user_id=user_id
        )
        return response

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        log_http_response(
            logger=logger,
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_ms=duration_ms,
            user_id=user_id,
            error=str(e)
        )
        raise


# Exception handlers for detailed error logging
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Log HTTP exceptions."""
    logger.error(
        f"HTTP exception: {exc.status_code} - {exc.detail} | Path: {request.url.path}",
        extra={
            "status_code": exc.status_code,
            "detail": exc.detail,
            "path": request.url.path,
            "method": request.method
        }
    )
    return Response(content=str(exc.detail), status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log validation errors."""
    logger.error(
        f"Validation error: {exc.errors()} | Path: {request.url.path}",
        extra={
            "validation_errors": exc.errors(),
            "path": request.url.path,
            "method": request.method
        }
    )
    return Response(content=str(exc.errors()), status_code=422)


# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(org_router)
app.include_router(team_router)
