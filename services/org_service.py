from typing import List, Dict, Any
from fastapi import HTTPException
from keycloak.exceptions import KeycloakError
from core.config import get_admin_client
from core.logger import get_logger, log_error
from utils.helpers import (
    validate_group_name_not_reserved,
    normalize_kc_name,
    get_group_id_by_path,
    get_user_id_by_username,
    parse_user_orgs,
)

logger = get_logger(__name__)


class OrgService:
    """Service for organization management operations."""

    @staticmethod
    def list_organizations(user: dict) -> List[Dict[str, Any]]:
        """
        List organizations:
        - Super-admin: lists all root org groups (excluding 'super-admin')
        - Others: lists orgs the user belongs to (based on token groups)
        """
        user_id = user.get('sub', 'unknown')
        logger.debug(f"Listing organizations for user: {user_id}")
        try:
            kc = get_admin_client()
            groups = user.get("groups", []) or []

            if "/super-admin" in groups:
                all_groups = kc.get_groups()
                result = [g for g in all_groups if (g.get('name') or '').lower() != 'super-admin']
                logger.debug(f"Listed {len(result)} organizations for super-admin")
                return result

            orgs = sorted(list(parse_user_orgs(groups)))
            result: List[Dict[str, Any]] = []
            for org in orgs:
                gid = get_group_id_by_path(kc, f"/{org}")
                if gid:
                    g = kc.get_group(gid)
                    result.append(
                        {"id": g["id"], "name": g["name"], "path": g["path"]})
            logger.debug(f"Listed {len(result)} organizations for user: {user_id}")
            return result
        except Exception as e:
            log_error(logger, e, {"user_id": user_id, "action": "list_organizations"})
            raise

    @staticmethod
    def create_organization(org_data: dict) -> dict:
        """Create a new organization (super-admin only)."""
        org_name = org_data.get('name')
        logger.info(f"Creating organization: {org_name}")
        try:
            kc = get_admin_client()

            org_name = validate_group_name_not_reserved(
                org_data.get('name'), kind="Organization")
            admin_username = normalize_kc_name(
                org_data.get('admin_username')) if org_data.get('admin_username') else None

            # 1. Create Org Group
            try:
                org_id = kc.create_group({"name": org_name})
            except KeycloakError:
                log_error(logger, Exception("Organization already exists"), {
                    "org_name": org_name,
                    "action": "create_organization"
                })
                raise HTTPException(
                    status_code=409, detail="Organization already exists")

            # 2. Create Structure: /Org/admin and /Org/user
            kc.create_group({"name": "admin"}, parent=org_id)
            kc.create_group({"name": "user"}, parent=org_id)

            # 3. Add Admin User if provided
            if admin_username:
                user_id = get_user_id_by_username(kc, admin_username)

                # Fetch org again to get children IDs
                org_details = kc.get_group(org_id)
                admin_group_id = next((g['id'] for g in org_details.get(
                    'subGroups', []) if g['name'] == 'admin'), None)

                if admin_group_id:
                    kc.group_user_add(user_id, admin_group_id)
                    logger.info(f"Organization created: {org_name} with admin: {admin_username}")
                    return {"message": f"Org '{org_name}' created, user '{admin_username}' assigned as Admin."}

            logger.info(f"Organization created: {org_name} (no admin assigned)")
            return {"message": f"Org '{org_name}' created (No admin assigned)."}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "action": "create_organization"})
            raise

    @staticmethod
    def delete_organization(org_name: str) -> dict:
        """Delete an organization by name (super-admin only)."""
        logger.warning(f"Deleting organization: {org_name}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            group_id = get_group_id_by_path(kc, f"/{org_name}")
            if not group_id:
                log_error(logger, Exception("Organization not found"), {
                    "org_name": org_name,
                    "action": "delete_organization"
                })
                raise HTTPException(
                    status_code=404, detail="Organization not found")

            kc.delete_group(group_id)
            logger.warning(f"Organization deleted successfully: {org_name}")
            return {"message": f"Organization '{org_name}' deleted"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "action": "delete_organization"})
            raise

    @staticmethod
    def add_org_admin(org_name: str, username: str) -> dict:
        """Add a user as admin to an organization (super-admin only)."""
        logger.info(f"Adding org admin - org: {org_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)

            group_id = get_group_id_by_path(kc, f"/{org_name}/admin")
            if not group_id:
                log_error(logger, Exception("Org Admin group not found"), {
                    "org_name": org_name,
                    "username": username,
                    "action": "add_org_admin"
                })
                raise HTTPException(
                    status_code=404, detail="Org Admin group not found")

            kc.group_user_add(user_id, group_id)
            logger.info(f"Org admin added successfully - org: {org_name}, username: {username}")
            return {"message": f"User '{username}' is now Admin of '{org_name}'"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "username": username, "action": "add_org_admin"})
            raise

    @staticmethod
    def remove_org_admin(org_name: str, username: str) -> dict:
        """Remove a user from admin role in an organization (super-admin only)."""
        logger.info(f"Removing org admin - org: {org_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)
            group_id = get_group_id_by_path(kc, f"/{org_name}/admin")

            try:
                kc.group_user_remove(user_id, group_id)
                logger.info(f"Org admin removed successfully - org: {org_name}, username: {username}")
                return {"message": f"User '{username}' removed from '{org_name}' admins"}
            except KeycloakError as e:
                log_error(logger, e, {"org_name": org_name, "username": username, "action": "remove_org_admin"})
                raise HTTPException(
                    status_code=400, detail="Failed to remove user")
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "username": username, "action": "remove_org_admin"})
            raise

    @staticmethod
    def add_org_user(org_name: str, username: str) -> dict:
        """Add a user to an organization's user group."""
        logger.info(f"Adding org user - org: {org_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)

            group_id = get_group_id_by_path(kc, f"/{org_name}/user")
            if not group_id:
                log_error(logger, Exception("Org User group not found"), {
                    "org_name": org_name,
                    "username": username,
                    "action": "add_org_user"
                })
                raise HTTPException(
                    status_code=404, detail="Org User group not found")

            kc.group_user_add(user_id, group_id)
            logger.info(f"Org user added successfully - org: {org_name}, username: {username}")
            return {"message": f"User '{username}' added to '{org_name}' users"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "username": username, "action": "add_org_user"})
            raise
