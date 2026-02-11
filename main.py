from fastapi import FastAPI
from routers import auth_router, user_router, org_router, team_router

# Create FastAPI app
app = FastAPI(title="Keycloak Advanced RBAC System")

# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(org_router)
app.include_router(team_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Keycloak Advanced RBAC System API"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
