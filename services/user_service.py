from typing import List, Optional, Dict, Any
from fastapi import HTTPException
from keycloak.exceptions import KeycloakError
from core.config import get_admin_client
from core.logger import get_logger, log_error
from utils.helpers import (
    normalize_kc_list,
    ensure_orgs_exist,
    get_group_id_by_path,
    parse_admin_orgs,
    parse_managed_teams,
    is_user_in_scope,
)

logger = get_logger(__name__)


class UserService:
    """Service for user management operations."""

    @staticmethod
    def enrich_user_with_groups(kc, user: Dict[str, Any]) -> Dict[str, Any]:
        """Add groups to user data by fetching from Keycloak."""
        try:
            user_groups = kc.get_user_groups(user.get("id"))
            # Extract group paths
            user["groups"] = [g.get("path", "") for g in user_groups if g.get("path")]
        except KeycloakError as e:
            logger.warning(f"Failed to fetch groups for user {user.get('id')}: {e}")
            user["groups"] = []
        return user

    @staticmethod
    def list_users(
        org_name: Optional[str],
        team_name: Optional[str],
        user: dict
    ) -> List[Dict[str, Any]]:
        """
        List users based on role and scope:
        - Super-admin: list all users (optionally filtered by org/team)
        - Org-admin: list users under their org(s). If org_name specified, must be one they admin.
        - Team-manager: list users under their team(s). If org_name+team_name specified, must be one they manage.
        """
        from utils.helpers import list_members_recursive, unique_users

        actor_id = user.get('sub', 'unknown')
        logger.debug(f"Listing users - org: {org_name}, team: {team_name}, actor: {actor_id}")
        try:
            kc = get_admin_client()
            groups = [g.lower() for g in (user.get('groups', []) or [])]

            is_super = "/super-admin" in groups
            admin_orgs = parse_admin_orgs(groups)
            managed_teams = parse_managed_teams(groups)

            # Validate requested scope (if any)
            if team_name and not org_name:
                raise HTTPException(
                    status_code=400, detail="team_name requires org_name")

            if org_name and team_name:
                # team scope
                if not is_super and (org_name, team_name) not in managed_teams and org_name not in admin_orgs:
                    raise HTTPException(
                        status_code=403, detail="Not allowed to list users for this team")
                team_group_id = get_group_id_by_path(
                    kc, f"/{org_name}/{team_name}")
                if not team_group_id:
                    raise HTTPException(status_code=404, detail="Team not found")
                users = list_members_recursive(kc, team_group_id)
                return [UserService.enrich_user_with_groups(kc, u) for u in users]

            if org_name:
                # org scope
                if not is_super and org_name not in admin_orgs:
                    raise HTTPException(
                        status_code=403, detail="Not allowed to list users for this org")
                org_group_id = get_group_id_by_path(kc, f"/{org_name}")
                if not org_group_id:
                    raise HTTPException(
                        status_code=404, detail="Organization not found")
                users = list_members_recursive(kc, org_group_id)
                return [UserService.enrich_user_with_groups(kc, u) for u in users]

            # No explicit scope -> infer from role
            if is_super:
                users = kc.get_users()
                return [UserService.enrich_user_with_groups(kc, u) for u in users]

            if admin_orgs:
                all_users: List[Dict[str, Any]] = []
                for org in sorted(admin_orgs):
                    gid = get_group_id_by_path(kc, f"/{org}")
                    if gid:
                        all_users.extend(list_members_recursive(kc, gid))
                users = unique_users(all_users)
                return [UserService.enrich_user_with_groups(kc, u) for u in users]

            if managed_teams:
                all_users = []
                for (org, team) in sorted(managed_teams):
                    gid = get_group_id_by_path(kc, f"/{org}/{team}")
                    if gid:
                        all_users.extend(list_members_recursive(kc, gid))
                users = unique_users(all_users)
                return [UserService.enrich_user_with_groups(kc, u) for u in users]

            raise HTTPException(
                status_code=403, detail="Not allowed to list users")
        except Exception as e:
            log_error(logger, e, {
                "action": "list_users",
                "actor_id": actor_id,
                "org_name": org_name,
                "team_name": team_name
            })
            raise

    @staticmethod
    def create_user(payload: dict, actor: dict) -> dict:
        """
        Create a new user:
        - Org-admin can create user and automatically add them to /Org/user in their org(s).
        - If payload.orgs is provided: it must be subset of orgs the actor admins (unless super-admin).
        - If payload.orgs omitted and actor is org-admin: defaults to all orgs the actor admins.
        - Super-admin can create users and optionally add them to any orgs.
        """
        from utils.helpers import get_user_id_by_username

        actor_id = actor.get('sub', 'unknown')
        email = payload.get('email')
        logger.info(f"Creating user - email: {email}, actor: {actor_id}")
        try:
            kc = get_admin_client()
            groups = [g.lower() for g in (actor.get('groups', []) or [])]
            is_super = "/super-admin" in groups
            admin_orgs = parse_admin_orgs(groups)

            requested_orgs = normalize_kc_list(payload.get('orgs'))
            if not is_super:
                if not admin_orgs:
                    raise HTTPException(
                        status_code=403, detail="Only super-admin or org-admin can create users")
                if requested_orgs is None:
                    requested_orgs = sorted(list(admin_orgs))
                else:
                    bad = [o for o in requested_orgs if o not in admin_orgs]
                    if bad:
                        raise HTTPException(
                            status_code=403, detail=f"Not admin of org(s): {', '.join(bad)}")
            else:
                requested_orgs = requested_orgs or []

            # Validate orgs exist
            if requested_orgs:
                ensure_orgs_exist(kc, requested_orgs)

            try:
                new_user_id = kc.create_user({
                    "email": (payload.get('email') or "").strip().lower(),
                    "enabled": True,
                    "firstName": payload.get('first_name'),
                    "lastName": payload.get('last_name'),
                    "credentials": [{"value": payload.get('password'), "type": "password", "temporary": False}]
                })
            except KeycloakError as e:
                log_error(logger, e, {"email": email, "action": "create_user"})
                raise HTTPException(
                    status_code=409, detail=f"User likely exists: {e}")

            # Add to /Org/user groups
            added_to: List[str] = []
            for org in requested_orgs:
                group_id = get_group_id_by_path(kc, f"/{org}/user")
                if not group_id:
                    # org exists, but expected subgroup missing
                    log_error(logger, Exception(f"Org '{org}' missing '/user' subgroup"), {
                        "new_user_id": new_user_id,
                        "org": org,
                        "action": "create_user_add_to_org"
                    })
                    raise HTTPException(
                        status_code=500, detail=f"Org '{org}' missing '/user' subgroup")
                try:
                    kc.group_user_add(new_user_id, group_id)
                    added_to.append(org)
                except KeycloakError as e:
                    log_error(logger, e, {
                        "new_user_id": new_user_id,
                        "org": org,
                        "action": "create_user_add_to_org"
                    })
                    raise HTTPException(
                        status_code=400, detail=f"Failed to add user to org '{org}': {e}")

            logger.info(f"User created successfully - id: {new_user_id}, email: {email}, orgs: {added_to}")
            return {"message": "User created", "id": new_user_id, "added_to_orgs": added_to}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"email": email, "action": "create_user"})
            raise

    @staticmethod
    def get_user(user_id: str, actor: dict) -> dict:
        """
        Get user by ID:
        - Super-admin can get any user.
        - Org-admin can get users within their org(s).
        - Team-manager can get users within their managed team(s).
        """
        actor_id = actor.get('sub', 'unknown')
        logger.debug(f"Fetching user - user_id: {user_id}, actor: {actor_id}")
        try:
            kc = get_admin_client()
            groups = actor.get("groups", []) or []
            if "/super-admin" in groups:
                try:
                    user = kc.get_user(user_id)
                    logger.debug(f"User retrieved successfully - user_id: {user_id}")
                    return UserService.enrich_user_with_groups(kc, user)
                except KeycloakError:
                    log_error(logger, Exception("User not found"), {
                        "target_user_id": user_id,
                        "actor_id": actor_id,
                        "action": "get_user"
                    })
                    raise HTTPException(status_code=404, detail="User not found")

            scope_orgs = parse_admin_orgs(groups)
            scope_teams = parse_managed_teams(groups)

            if not is_user_in_scope(kc, user_id, scope_orgs, scope_teams):
                logger.warning(f"Access denied - actor: {actor_id}, target_user: {user_id}")
                raise HTTPException(
                    status_code=403, detail="Not allowed to view this user")

            try:
                user = kc.get_user(user_id)
                logger.debug(f"User retrieved successfully - user_id: {user_id}")
                return UserService.enrich_user_with_groups(kc, user)
            except KeycloakError:
                log_error(logger, Exception("User not found"), {
                    "target_user_id": user_id,
                    "actor_id": actor_id,
                    "action": "get_user"
                })
                raise HTTPException(status_code=404, detail="User not found")
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"target_user_id": user_id, "actor_id": actor_id, "action": "get_user"})
            raise

    @staticmethod
    def delete_user(user_id: str) -> dict:
        """Delete user by ID (super-admin only)."""
        logger.warning(f"Deleting user - user_id: {user_id}")
        try:
            kc = get_admin_client()
            try:
                kc.delete_user(user_id)
                logger.warning(f"User deleted successfully - user_id: {user_id}")
                return {"message": "User deleted"}
            except KeycloakError as e:
                log_error(logger, e, {"target_user_id": user_id, "action": "delete_user"})
                raise HTTPException(status_code=404, detail="User not found")
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"target_user_id": user_id, "action": "delete_user"})
            raise
