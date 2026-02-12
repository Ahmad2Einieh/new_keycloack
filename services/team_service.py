from fastapi import HTTPException
from keycloak.exceptions import KeycloakError
from core.config import get_admin_client
from utils.helpers import (
    validate_group_name_not_reserved,
    normalize_kc_name,
    get_group_id_by_path,
    get_user_id_by_username,
)


class TeamService:
    """Service for team management operations."""

    @staticmethod
    def create_team(org_name: str, team_data: dict) -> dict:
        """Create a new team within an organization."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = validate_group_name_not_reserved(
            team_data.get('name'), kind="Team")
        manager_username = normalize_kc_name(team_data.get('manager_username'))

        org_group_id = get_group_id_by_path(kc, f"/{org_name}")
        if not org_group_id:
            raise HTTPException(
                status_code=404, detail="Organization not found")

        # Create Team Group
        try:
            team_id = kc.create_group({"name": team_name}, parent=org_group_id)
        except KeycloakError:
            raise HTTPException(status_code=409, detail="Team already exists")

        # Create Subgroups
        kc.create_group({"name": "manager"}, parent=team_id)
        kc.create_group({"name": "member"}, parent=team_id)

        # Assign Manager if provided
        if manager_username:
            user_id = get_user_id_by_username(kc, manager_username)
            team_data = kc.get_group(team_id)
            manager_group_id = next((g['id'] for g in team_data.get(
                'subGroups', []) if g['name'] == 'manager'), None)

            if manager_group_id:
                kc.group_user_add(user_id, manager_group_id)

        return {"message": f"Team '{team_name}' created."}

    @staticmethod
    def delete_team(org_name: str, team_name: str) -> dict:
        """Delete a team from an organization."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        team_group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}")
        if not team_group_id:
            raise HTTPException(status_code=404, detail="Team not found")
        kc.delete_group(team_group_id)
        return {"message": f"Team '{team_name}' deleted from org '{org_name}'"}

    @staticmethod
    def add_team_manager(org_name: str, team_name: str, username: str) -> dict:
        """Add a user as manager to a team."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        username = normalize_kc_name(username) or username
        user_id = get_user_id_by_username(kc, username)
        group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/manager")

        if not group_id:
            raise HTTPException(status_code=404, detail="Group not found")
        kc.group_user_add(user_id, group_id)
        return {"message": f"User '{username}' added as manager to {team_name}"}

    @staticmethod
    def remove_team_manager(org_name: str, team_name: str, username: str) -> dict:
        """Remove a manager from a team."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        username = normalize_kc_name(username) or username
        user_id = get_user_id_by_username(kc, username)
        group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/manager")

        if not group_id:
            raise HTTPException(status_code=404, detail="Group not found")
        kc.group_user_remove(user_id, group_id)
        return {"message": f"User '{username}' removed as manager from {team_name}"}

    @staticmethod
    def add_team_member(org_name: str, team_name: str, username: str) -> dict:
        """Add a user as member to a team."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        username = normalize_kc_name(username) or username
        user_id = get_user_id_by_username(kc, username)
        group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/member")

        if not group_id:
            raise HTTPException(status_code=404, detail="Group not found")
        kc.group_user_add(user_id, group_id)
        return {"message": f"User '{username}' added as member to {team_name}"}

    @staticmethod
    def remove_team_member(org_name: str, team_name: str, username: str) -> dict:
        """Remove a user from a team."""
        kc = get_admin_client()
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        username = normalize_kc_name(username) or username
        user_id = get_user_id_by_username(kc, username)
        group_id = get_group_id_by_path(kc, f"/{org_name}/{team_name}/member")

        kc.group_user_remove(user_id, group_id)
        return {"message": f"User removed from {team_name}"}
