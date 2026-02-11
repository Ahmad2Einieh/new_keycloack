from fastapi import FastAPI
from routers.auth import auth_router
from routers.user import user_router
from routers.org import org_router
from routers.team import team_router

# Create FastAPI app
app = FastAPI(title="Keycloak Advanced RBAC System")

# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(org_router)
app.include_router(team_router)
