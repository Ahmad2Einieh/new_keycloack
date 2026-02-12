from fastapi import APIRouter, Depends
from services.org_service import OrgService
from models.org import OrgCreate, OrgResponse
from models.user import AddUserRole
from core.security import get_current_user, check_super_admin, OrgAdminChecker
from core.logger import get_logger, log_error

org_router = APIRouter(prefix="/organizations", tags=["Organizations"])
logger = get_logger(__name__)


@org_router.get("", response_model=list[OrgResponse])
async def list_organizations(user: dict = Depends(get_current_user)):
    """List organizations based on user role."""
    user_id = user.get('sub')
    logger.debug(f"Listing organizations for user: {user_id}")
    try:
        result = OrgService.list_organizations(user)
        logger.debug(f"Listed {len(result)} organizations for user: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"action": "list_organizations", "user_id": user_id})
        raise


@org_router.post("")
async def create_organization(org: OrgCreate, user: dict = Depends(check_super_admin)):
    """Create a new organization (super-admin only)."""
    admin_id = user.get('sub')
    logger.info(f"Creating organization - name: {org.name}, admin: {admin_id}")
    try:
        result = OrgService.create_organization(org.dict())
        logger.info(f"Organization created successfully - name: {org.name}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "create_organization",
            "admin_id": admin_id,
            "org_name": org.name
        })
        raise


@org_router.delete("/{org_name}")
async def delete_organization(org_name: str, user: dict = Depends(check_super_admin)):
    """Delete an organization by name (super-admin only)."""
    admin_id = user.get('sub')
    logger.warning(f"Deleting organization - name: {org_name}, admin: {admin_id}")
    try:
        result = OrgService.delete_organization(org_name)
        logger.warning(f"Organization deleted successfully - name: {org_name}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "delete_organization",
            "admin_id": admin_id,
            "org_name": org_name
        })
        raise


@org_router.post("/{org_name}/admins")
async def add_org_admin(
    org_data: AddUserRole,
    org_name: str,
    user: dict = Depends(check_super_admin)
):
    """Add a user as admin to an organization (super-admin only)."""
    admin_id = user.get('sub')
    logger.info(f"Adding org admin - org: {org_name}, username: {org_data.username}, actor: {admin_id}")
    try:
        result = OrgService.add_org_admin(org_name, org_data.username)
        logger.info(f"Org admin added successfully - org: {org_name}, username: {org_data.username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "add_org_admin",
            "actor_id": admin_id,
            "org_name": org_name,
            "username": org_data.username
        })
        raise


@org_router.delete("/{org_name}/admins/{username}")
async def remove_org_admin(
    username: str,
    org_name: str,
    user: dict = Depends(check_super_admin)
):
    """Remove a user from admin role in an organization (super-admin only)."""
    admin_id = user.get('sub')
    logger.info(f"Removing org admin - org: {org_name}, username: {username}, actor: {admin_id}")
    try:
        result = OrgService.remove_org_admin(org_name, username)
        logger.info(f"Org admin removed successfully - org: {org_name}, username: {username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "remove_org_admin",
            "actor_id": admin_id,
            "org_name": org_name,
            "username": username
        })
        raise


@org_router.post("/{org_name}/users")
async def add_org_user(
    data: AddUserRole,
    org_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Add a user to an organization's user group."""
    admin_id = user.get('sub')
    logger.info(f"Adding org user - org: {org_name}, username: {data.username}, actor: {admin_id}")
    try:
        result = OrgService.add_org_user(org_name, data.username)
        logger.info(f"Org user added successfully - org: {org_name}, username: {data.username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "add_org_user",
            "actor_id": admin_id,
            "org_name": org_name,
            "username": data.username
        })
        raise
