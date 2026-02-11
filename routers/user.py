from typing import Optional
from fastapi import APIRouter, Depends, Query
from ..services.user_service import UserService
from ..models.user import UserCreate, UserResponse, AddUserRole
from ..core.security import get_current_user, check_super_admin

user_router = APIRouter(prefix="/users", tags=["Users"])


@user_router.get("", response_model=list[UserResponse])
async def list_users(
    org_name: Optional[str] = Query(
        default=None, description="Optionally scope listing to a single org"),
    team_name: Optional[str] = Query(
        default=None, description="Optionally scope listing to a single team (requires org_name)"),
    user: dict = Depends(get_current_user),
):
    """List users based on role and scope."""
    return UserService.list_users(org_name, team_name, user)


@user_router.post("", status_code=201)
async def create_user(payload: UserCreate, actor: dict = Depends(get_current_user)):
    """Create a new user."""
    return UserService.create_user(payload.dict(), actor)


@user_router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str, actor: dict = Depends(get_current_user)):
    """Get user by ID."""
    return UserService.get_user(user_id, actor)


@user_router.delete("/{user_id}")
async def delete_user(user_id: str, admin: dict = Depends(check_super_admin)):
    """Delete user by ID (super-admin only)."""
    return UserService.delete_user(user_id)
