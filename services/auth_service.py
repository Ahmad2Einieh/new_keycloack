from fastapi import HTTPException, status, Body
from keycloak.exceptions import KeycloakError
from ..core.config import keycloak_openid


class AuthService:
    """Service for authentication operations."""

    @staticmethod
    def login(username: str, password: str) -> dict:
        """Authenticate user and return token."""
        try:
            return keycloak_openid.token(username, password)
        except KeycloakError:
            raise HTTPException(status_code=401, detail="Invalid Credentials")

    @staticmethod
    def refresh_token(refresh_token: str) -> dict:
        """Refresh access token using refresh token."""
        try:
            return keycloak_openid.refresh_token(refresh_token)
        except KeycloakError:
            raise HTTPException(status_code=400, detail="Invalid Refresh Token")

    @staticmethod
    def logout(refresh_token: str) -> dict:
        """Logout user using refresh token."""
        try:
            keycloak_openid.logout(refresh_token)
            return {"message": "Logged out"}
        except KeycloakError:
            raise HTTPException(status_code=400, detail="Logout failed")

    @staticmethod
    def get_my_profile(user_id: str) -> dict:
        """Get current user profile."""
        from ..core.config import get_admin_client
        kc = get_admin_client()
        return kc.get_user(user_id)

    @staticmethod
    def update_my_profile(user_id: str, update_data: dict) -> dict:
        """Update current user profile."""
        from ..core.config import get_admin_client
        kc = get_admin_client()
        payload = {k: v for k, v in update_data.items() if v is not None}
        try:
            kc.update_user(user_id, payload)
            return {"message": "Profile updated successfully"}
        except KeycloakError as e:
            raise HTTPException(status_code=400, detail=f"Update failed: {e}")

    @staticmethod
    def update_my_password(user_id: str, new_password: str) -> dict:
        """Update current user password."""
        from ..core.config import get_admin_client
        kc = get_admin_client()
        try:
            kc.set_user_password(user_id, new_password, temporary=False)
            return {"message": "Password updated successfully"}
        except KeycloakError as e:
            raise HTTPException(
                status_code=400, detail=f"Password update failed: {e}")

    @staticmethod
    def send_verification_email(user_id: str) -> dict:
        """Send verification email to current user."""
        from ..core.config import get_admin_client
        kc = get_admin_client()
        try:
            kc.send_verify_email(user_id=user_id)
            return {"message": "Verification email sent"}
        except KeycloakError as e:
            raise HTTPException(
                status_code=400, detail=f"Failed to send email: {e}")

    @staticmethod
    def get_my_memberships(user: dict) -> dict:
        """Get current user's memberships (orgs, teams, roles)."""
        from ..utils.helpers import parse_user_orgs, parse_admin_orgs, parse_managed_teams, parse_member_teams

        groups = [g.lower() for g in (user.get('groups', []) or [])]
        orgs = sorted(list(parse_user_orgs(groups)))
        admin_orgs = sorted(list(parse_admin_orgs(groups)))
        managed_teams = sorted([{"org": o, "team": t} for (
            o, t) in parse_managed_teams(groups)], key=lambda x: (x["org"], x["team"]))
        member_teams = sorted([{"org": o, "team": t} for (
            o, t) in parse_member_teams(groups)], key=lambda x: (x["org"], x["team"]))
        return {
            "is_super_admin": "/super-admin" in groups,
            "orgs": orgs,
            "admin_orgs": admin_orgs,
            "managed_teams": managed_teams,
            "member_teams": member_teams,
            "raw_groups": groups,
        }
