from fastapi import APIRouter, Depends
from services.team_service import TeamService
from models.team import TeamCreate
from models.user import AddUserRole
from core.security import OrgAdminChecker, TeamManagerChecker

team_router = APIRouter(
    prefix="/organizations/{org_name}/teams", tags=["Teams"])


@team_router.post("")
async def create_team(
    team: TeamCreate,
    org_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Create a new team within an organization."""
    return TeamService.create_team(org_name, team.dict())


@team_router.delete("/{team_name}")
async def delete_team(
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Delete a team from an organization."""
    return TeamService.delete_team(org_name, team_name)


@team_router.post("/{team_name}/managers")
async def add_team_manager(
    data: AddUserRole,
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Add a user as manager to a team."""
    return TeamService.add_team_manager(org_name, team_name, data.username)


@team_router.delete("/{team_name}/managers/{username}")
async def remove_team_manager(
    username: str,
    org_name: str,
    team_name: str,
    user: dict = Depends(OrgAdminChecker())
):
    """Remove a manager from a team."""
    return TeamService.remove_team_manager(org_name, team_name, username)


@team_router.post("/{team_name}/members")
async def add_team_member(
    data: AddUserRole,
    org_name: str,
    team_name: str,
    user: dict = Depends(TeamManagerChecker())
):
    """Add a user as member to a team."""
    return TeamService.add_team_member(org_name, team_name, data.username)


@team_router.delete("/{team_name}/members/{username}")
async def remove_team_member(
    username: str,
    org_name: str,
    team_name: str,
    user: dict = Depends(TeamManagerChecker())
):
    """Remove a user from a team."""
    return TeamService.remove_team_member(org_name, team_name, username)
