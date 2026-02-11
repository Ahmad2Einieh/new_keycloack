from fastapi import APIRouter, Depends
from ..services.org_service import OrgService
from ..models.org import OrgCreate, OrgResponse
from ..models.user import AddUserRole
from ..core.security import get_current_user, check_super_admin, OrgAdminChecker

org_router = APIRouter(prefix="/organizations", tags=["Organizations"])


@org_router.get("", response_model=list[OrgResponse])
async def list_organizations(user: dict = Depends(get_current_user)):
    """List organizations based on user role."""
    return OrgService.list_organizations(user)


@org_router.post("")
async def create_organization(org: OrgCreate, user: dict = Depends(check_super_admin)):
    """Create a new organization (super-admin only)."""
    return OrgService.create_organization(org.dict())


@org_router.delete("/{org_name}")
async def delete_organization(org_name: str, user: dict = Depends(check_super_admin)):
    """Delete an organization by name (super-admin only)."""
    return OrgService.delete_organization(org_name)


@org_router.post("/{org_name}/admins")
async def add_org_admin(
    org_data: AddUserRole,
    org_name: str,
    user: dict = Depends(check_super_admin)
):
    """Add a user as admin to an organization (super-admin only)."""
    return OrgService.add_org_admin(org_name, org_data.username)


@org_router.delete("/{org_name}/admins/{username}")
async def remove_org_admin(
    username: str,
    org_name: str,
    user: dict = Depends(check_super_admin)
):
    """Remove a user from admin role in an organization (super-admin only)."""
    return OrgService.remove_org_admin(org_name, username)


@org_router.post("/{org_name}/users")
async def add_org_user(
    data: AddUserRole,
    org_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Add a user to an organization's user group."""
    return OrgService.add_org_user(org_name, data.username)
