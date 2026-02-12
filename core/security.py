from fastapi import Depends, HTTPException, status, Path, Request
from utils.helpers import normalize_kc_name
from core.config import keycloak_openid
from core.logger import get_logger, log_error
import jwt

logger = get_logger(__name__)


async def get_current_user(request: Request):
    """
    Validates token from cookie and returns payload.
    MUST have 'groups' mapper enabled in Keycloak Client Mappers.
    """
    token = request.cookies.get("access_token")

    if not token:
        logger.warning("Authentication attempt with no token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Decode JWT manually with proper options
        # Format the public key with PEM headers
        public_key = keycloak_openid.public_key()
        if not public_key.startswith("-----BEGIN"):
            public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

        user_info = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={"verify_signature": True,
                     "verify_aud": False, "verify_exp": True}
        )
        user_id = user_info.get('sub', 'unknown')
        logger.debug(f"Authentication successful for user: {user_id}")
        return user_info
    except Exception as e:
        log_error(logger, e, {"action": "authenticate"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def check_super_admin(user: dict = Depends(get_current_user)):
    """Strictly checks for /super-admin group membership (case-insensitive)."""
    user_id = user.get('sub', 'unknown')
    groups = [g.lower() for g in (user.get('groups', []) or [])]
    if "/super-admin" not in groups:
        logger.warning(f"Super admin check failed for user: {user_id}")
        raise HTTPException(
            status_code=403, detail="Super Admin privileges required")
    logger.debug(f"Super admin check passed for user: {user_id}")
    return user


class OrgAdminChecker:
    """Checks if user is Admin of the specific Org OR is Super Admin (case-insensitive)."""

    def __call__(self, org_name: str = Path(...), user: dict = Depends(get_current_user)):
        user_id = user.get('sub', 'unknown')
        org_name = normalize_kc_name(org_name) or org_name
        groups = [g.lower() for g in (user.get('groups', []) or [])]
        if "/super-admin" in groups:
            logger.debug(f"Super admin bypass for org: {org_name}, user: {user_id}")
            return user
        if f"/{org_name}/admin" not in groups:
            logger.warning(f"Org admin check failed - org: {org_name}, user: {user_id}")
            raise HTTPException(
                status_code=403, detail=f"Not an admin of organization '{org_name}'")
        logger.debug(f"Org admin check passed - org: {org_name}, user: {user_id}")
        return user


class TeamManagerChecker:
    """Checks if user is Manager of Team OR Org Admin OR Super Admin (case-insensitive)."""

    def __call__(self, org_name: str = Path(...), team_name: str = Path(...), user: dict = Depends(get_current_user)):
        user_id = user.get('sub', 'unknown')
        org_name = normalize_kc_name(org_name) or org_name
        team_name = normalize_kc_name(team_name) or team_name
        groups = [g.lower() for g in (user.get("groups", []) or [])]
        if "/super-admin" in groups or f"/{org_name}/admin" in groups:
            logger.debug(f"Admin bypass for team: {team_name}, org: {org_name}, user: {user_id}")
            return user
        if f"/{org_name}/{team_name}/manager" not in groups:
            logger.warning(f"Team manager check failed - team: {team_name}, org: {org_name}, user: {user_id}")
            raise HTTPException(
                status_code=403, detail=f"Not a manager of team '{team_name}'")
        logger.debug(f"Team manager check passed - team: {team_name}, org: {org_name}, user: {user_id}")
        return user
