from fastapi import APIRouter, Depends
from services.team_service import TeamService
from models.team import TeamCreate
from models.user import AddUserRole
from core.security import OrgAdminChecker, TeamManagerChecker
from core.logger import get_logger, log_error

team_router = APIRouter(
    prefix="/organizations/{org_name}/teams", tags=["Teams"])
logger = get_logger(__name__)


@team_router.post("")
async def create_team(
    team: TeamCreate,
    org_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Create a new team within an organization."""
    admin_id = user.get('sub')
    logger.info(f"Creating team - org: {org_name}, team: {team.name}, actor: {admin_id}")
    try:
        result = TeamService.create_team(org_name, team.dict())
        logger.info(f"Team created successfully - org: {org_name}, team: {team.name}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "create_team",
            "actor_id": admin_id,
            "org_name": org_name,
            "team_name": team.name
        })
        raise


@team_router.delete("/{team_name}")
async def delete_team(
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Delete a team from an organization."""
    admin_id = user.get('sub')
    logger.warning(f"Deleting team - org: {org_name}, team: {team_name}, actor: {admin_id}")
    try:
        result = TeamService.delete_team(org_name, team_name)
        logger.warning(f"Team deleted successfully - org: {org_name}, team: {team_name}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "delete_team",
            "actor_id": admin_id,
            "org_name": org_name,
            "team_name": team_name
        })
        raise


@team_router.post("/{team_name}/managers")
async def add_team_manager(
    data: AddUserRole,
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Add a user as manager to a team."""
    admin_id = user.get('sub')
    logger.info(f"Adding team manager - org: {org_name}, team: {team_name}, username: {data.username}, actor: {admin_id}")
    try:
        result = TeamService.add_team_manager(org_name, team_name, data.username)
        logger.info(f"Team manager added successfully - org: {org_name}, team: {team_name}, username: {data.username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "add_team_manager",
            "actor_id": admin_id,
            "org_name": org_name,
            "team_name": team_name,
            "username": data.username
        })
        raise


@team_router.delete("/{team_name}/managers/{username}")
async def remove_team_manager(
    username: str,
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Remove a manager from a team."""
    admin_id = user.get('sub')
    logger.info(f"Removing team manager - org: {org_name}, team: {team_name}, username: {username}, actor: {admin_id}")
    try:
        result = TeamService.remove_team_manager(org_name, team_name, username)
        logger.info(f"Team manager removed successfully - org: {org_name}, team: {team_name}, username: {username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "remove_team_manager",
            "actor_id": admin_id,
            "org_name": org_name,
            "team_name": team_name,
            "username": username
        })
        raise


@team_router.post("/{team_name}/members")
async def add_team_member(
    data: AddUserRole,
    org_name: str,
    team_name: str,
    user: dict = Depends(TeamManagerChecker())
):
    """Add a user as member to a team."""
    manager_id = user.get('sub')
    logger.info(f"Adding team member - org: {org_name}, team: {team_name}, username: {data.username}, actor: {manager_id}")
    try:
        result = TeamService.add_team_member(org_name, team_name, data.username)
        logger.info(f"Team member added successfully - org: {org_name}, team: {team_name}, username: {data.username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "add_team_member",
            "actor_id": manager_id,
            "org_name": org_name,
            "team_name": team_name,
            "username": data.username
        })
        raise


@team_router.delete("/{team_name}/members/{username}")
async def remove_team_member(
    username: str,
    org_name: str,
    team_name: str,
    user: dict = Depends(TeamManagerChecker())
):
    """Remove a user from a team."""
    manager_id = user.get('sub')
    logger.info(f"Removing team member - org: {org_name}, team: {team_name}, username: {username}, actor: {manager_id}")
    try:
        result = TeamService.remove_team_member(org_name, team_name, username)
        logger.info(f"Team member removed successfully - org: {org_name}, team: {team_name}, username: {username}")
        return result
    except Exception as e:
        log_error(logger, e, {
            "action": "remove_team_member",
            "actor_id": manager_id,
            "org_name": org_name,
            "team_name": team_name,
            "username": username
        })
        raise
