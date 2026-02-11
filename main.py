from fastapi import FastAPI
from routers import auth_router, user_router, org_router, team_router

# Create FastAPI app
app = FastAPI(title="Keycloak Advanced RBAC System")

# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(org_router)
app.include_router(team_router)
