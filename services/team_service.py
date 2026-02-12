from fastapi import HTTPException
from keycloak.exceptions import KeycloakError
from core.config import get_admin_client
from core.logger import get_logger, log_error
from utils.helpers import (
    validate_group_name_not_reserved,
    normalize_kc_name,
    get_group_id_by_path,
    get_user_id_by_username,
)

logger = get_logger(__name__)


class TeamService:
    """Service for team management operations."""

    @staticmethod
    def create_team(org_name: str, team_data: dict) -> dict:
        """Create a new team within an organization."""
        team_name = team_data.get('name')
        logger.info(f"Creating team - org: {org_name}, team: {team_name}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = validate_group_name_not_reserved(
                team_data.get('name'), kind="Team")
            manager_username = normalize_kc_name(team_data.get('manager_username'))

            org_group_id = get_group_id_by_path(kc, f"/{org_name}")
            if not org_group_id:
                log_error(logger, Exception("Organization not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "action": "create_team"
                })
                raise HTTPException(
                    status_code=404, detail="Organization not found")

            # Create Team Group
            try:
                team_id = kc.create_group({"name": team_name}, parent=org_group_id)
            except KeycloakError:
                log_error(logger, Exception("Team already exists"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "action": "create_team"
                })
                raise HTTPException(status_code=409, detail="Team already exists")

            # Create Subgroups
            kc.create_group({"name": "manager"}, parent=team_id)
            kc.create_group({"name": "member"}, parent=team_id)

            # Assign Manager if provided
            if manager_username:
                user_id = get_user_id_by_username(kc, manager_username)
                team_details = kc.get_group(team_id)
                manager_group_id = next((g['id'] for g in team_details.get(
                    'subGroups', []) if g['name'] == 'manager'), None)

                if manager_group_id:
                    kc.group_user_add(user_id, manager_group_id)

            logger.info(f"Team created successfully - org: {org_name}, team: {team_name}")
            return {"message": f"Team '{team_name}' created."}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "action": "create_team"})
            raise

    @staticmethod
    def delete_team(org_name: str, team_name: str) -> dict:
        """Delete a team from an organization."""
        logger.warning(f"Deleting team - org: {org_name}, team: {team_name}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = normalize_kc_name(team_name) or team_name
            team_group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}")
            if not team_group_id:
                log_error(logger, Exception("Team not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "action": "delete_team"
                })
                raise HTTPException(status_code=404, detail="Team not found")
            kc.delete_group(team_group_id)
            logger.warning(f"Team deleted successfully - org: {org_name}, team: {team_name}")
            return {"message": f"Team '{team_name}' deleted from org '{org_name}'"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "action": "delete_team"})
            raise

    @staticmethod
    def add_team_manager(org_name: str, team_name: str, username: str) -> dict:
        """Add a user as manager to a team."""
        logger.info(f"Adding team manager - org: {org_name}, team: {team_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = normalize_kc_name(team_name) or team_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)
            group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/manager")

            if not group_id:
                log_error(logger, Exception("Group not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "username": username,
                    "action": "add_team_manager"
                })
                raise HTTPException(status_code=404, detail="Group not found")
            kc.group_user_add(user_id, group_id)
            logger.info(f"Team manager added successfully - org: {org_name}, team: {team_name}, username: {username}")
            return {"message": f"User '{username}' added as manager to {team_name}"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "username": username, "action": "add_team_manager"})
            raise

    @staticmethod
    def remove_team_manager(org_name: str, team_name: str, username: str) -> dict:
        """Remove a manager from a team."""
        logger.info(f"Removing team manager - org: {org_name}, team: {team_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = normalize_kc_name(team_name) or team_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)
            group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/manager")

            if not group_id:
                log_error(logger, Exception("Group not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "username": username,
                    "action": "remove_team_manager"
                })
                raise HTTPException(status_code=404, detail="Group not found")
            kc.group_user_remove(user_id, group_id)
            logger.info(f"Team manager removed successfully - org: {org_name}, team: {team_name}, username: {username}")
            return {"message": f"User '{username}' removed as manager from {team_name}"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "username": username, "action": "remove_team_manager"})
            raise

    @staticmethod
    def add_team_member(org_name: str, team_name: str, username: str) -> dict:
        """Add a user as member to a team."""
        logger.info(f"Adding team member - org: {org_name}, team: {team_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = normalize_kc_name(team_name) or team_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)
            group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/member")

            if not group_id:
                log_error(logger, Exception("Group not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "username": username,
                    "action": "add_team_member"
                })
                raise HTTPException(status_code=404, detail="Group not found")
            kc.group_user_add(user_id, group_id)
            logger.info(f"Team member added successfully - org: {org_name}, team: {team_name}, username: {username}")
            return {"message": f"User '{username}' added as member to {team_name}"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "username": username, "action": "add_team_member"})
            raise

    @staticmethod
    def remove_team_member(org_name: str, team_name: str, username: str) -> dict:
        """Remove a user from a team."""
        logger.info(f"Removing team member - org: {org_name}, team: {team_name}, username: {username}")
        try:
            kc = get_admin_client()
            org_name = normalize_kc_name(org_name) or org_name
            team_name = normalize_kc_name(team_name) or team_name
            username = normalize_kc_name(username) or username
            user_id = get_user_id_by_username(kc, username)
            group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/member")

            if not group_id:
                log_error(logger, Exception("Group not found"), {
                    "org_name": org_name,
                    "team_name": team_name,
                    "username": username,
                    "action": "remove_team_member"
                })
                raise HTTPException(status_code=404, detail="Group not found")

            kc.group_user_remove(user_id, group_id)
            logger.info(f"Team member removed successfully - org: {org_name}, team: {team_name}, username: {username}")
            return {"message": f"User removed from {team_name}"}
        except HTTPException:
            raise
        except Exception as e:
            log_error(logger, e, {"org_name": org_name, "team_name": team_name, "username": username, "action": "remove_team_member"})
            raise
