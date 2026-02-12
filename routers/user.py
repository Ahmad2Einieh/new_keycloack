from typing import Optional
from fastapi import APIRouter, Depends, Query
from services.user_service import UserService
from models.user import UserCreate, UserResponse
from core.security import get_current_user, check_super_admin
from core.logger import get_logger, log_error

user_router = APIRouter(prefix="/users", tags=["Users"])
logger = get_logger(__name__)


@user_router.get("", response_model=list[UserResponse])
async def list_users(
    org_name: Optional[str] = Query(
        default=None, description="Optionally scope listing to a single org"),
    team_name: Optional[str] = Query(
        default=None, description="Optionally scope listing to a single team (requires org_name)"),
    user: dict = Depends(get_current_user),
):
    """List users based on role and scope."""
    actor_id = user.get('sub')
    logger.debug(
        f"Listing users - org: {org_name}, team: {team_name}, actor: {actor_id}")
    try:
        result = UserService.list_users(org_name, team_name, user)
        logger.debug(f"Listed {len(result)} users for actor: {actor_id}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "list_users",
            "actor_id": actor_id,
            "org_name": org_name,
            "team_name": team_name
        })
        raise


@user_router.post("", status_code=201)
async def create_user(payload: UserCreate, actor: dict = Depends(get_current_user)):
    """Create a new user."""
    actor_id = actor.get('sub')
    logger.info(f"Creating user - email: {payload.email}, actor: {actor_id}")
    try:
        result = UserService.create_user(payload.dict(), actor)
        logger.info(
            f"User created successfully - id: {result.get('id')}, actor: {actor_id}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "create_user",
            "actor_id": actor_id,
            "email": payload.email
        })
        raise


@user_router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, actor: dict = Depends(get_current_user)):
    """Get user by ID."""
    actor_id = actor.get('sub')
    logger.debug(f"Fetching user - user_id: {user_id}, actor: {actor_id}")
    try:
        result = UserService.get_user(user_id, actor)
        logger.debug(f"User retrieved successfully - user_id: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "get_user",
            "actor_id": actor_id,
            "target_user_id": user_id
        })
        raise


@user_router.delete("/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(check_super_admin)):
    """Delete user by ID (super-admin only)."""
    admin_id = admin.get('sub')
    logger.warning(f"Deleting user - user_id: {user_id}, admin: {admin_id}")
    try:
        result = UserService.delete_user(user_id)
        logger.warning(
            f"User deleted successfully - user_id: {user_id}, admin: {admin_id}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "delete_user",
            "admin_id": admin_id,
            "target_user_id": user_id
        })
        raise
