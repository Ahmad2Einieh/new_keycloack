from fastapi import APIRouter
from .auth import auth_router
from .user import user_router
from .org import org_router
from .team import team_router

__all__ = ["auth_router", "user_router", "org_router", "team_router"]
