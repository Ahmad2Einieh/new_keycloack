from fastapi import HTTPException
from keycloak.exceptions import KeycloakError
from core.config import keycloak_openid
from core.logger import get_logger, log_error

logger = get_logger(__name__)


class AuthService:
    """Service for authentication operations."""

    @staticmethod
    def login(email: str, password: str) -> dict:
        """Authenticate user and return token."""
        logger.debug(f"Login attempt for email: {email}")
        try:
            result = keycloak_openid.token(email, password)
            logger.info(f"Login successful for email: {email}")
            return result
        except KeycloakError as e:
            log_error(logger, e, {"email": email, "action": "login"})
            raise HTTPException(status_code=401, detail="Invalid Credentials")

    @staticmethod
    def refresh_token(refresh_token: str) -> dict:
        """Refresh access token using refresh token."""
        logger.debug("Token refresh attempt")
        try:
            result = keycloak_openid.refresh_token(refresh_token)
            logger.info("Token refreshed successfully")
            return result
        except KeycloakError as e:
            log_error(logger, e, {"action": "refresh_token"})
            raise HTTPException(
                status_code=400, detail="Invalid Refresh Token")

    @staticmethod
    def logout(refresh_token: str) -> dict:
        """Logout user using refresh token."""
        logger.debug("Logout attempt")
        try:
            keycloak_openid.logout(refresh_token)
            logger.info("User logged out successfully")
            return {"message": "Logged out"}
        except KeycloakError as e:
            log_error(logger, e, {"action": "logout"})
            raise HTTPException(status_code=400, detail="Logout failed")

    @staticmethod
    def get_my_profile(user_id: str) -> dict:
        """Get current user profile."""
        logger.debug(f"Fetching profile for user_id: {user_id}")
        try:
            from core.config import get_admin_client
            kc = get_admin_client()
            result = kc.get_user(user_id)
            logger.debug(f"Profile retrieved for user_id: {user_id}")
            return result
        except KeycloakError as e:
            log_error(logger, e, {"user_id": user_id, "action": "get_profile"})
            raise HTTPException(status_code=404, detail="User not found")

    @staticmethod
    def update_my_profile(user_id: str, update_data: dict) -> dict:
        """Update current user profile."""
        logger.info(f"Updating profile for user_id: {user_id}, data: {list(update_data.keys())}")
        try:
            from core.config import get_admin_client
            kc = get_admin_client()

            # Map snake_case field names to Keycloak's camelCase
            field_mapping = {
                "first_name": "firstName",
                "last_name": "lastName",
                "email": "email",
            }

            payload = {
                field_mapping.get(k, k): v
                for k, v in update_data.items()
                if v is not None
            }

            kc.update_user(user_id, payload)
            logger.info(f"Profile updated successfully for user_id: {user_id}")
            return {"message": "Profile updated successfully"}
        except KeycloakError as e:
            log_error(logger, e, {"user_id": user_id, "action": "update_profile"})
            raise HTTPException(status_code=400, detail=f"Update failed: {e}")

    @staticmethod
    def update_my_password(user_id: str, new_password: str) -> dict:
        """Update current user password."""
        logger.info(f"Updating password for user_id: {user_id}")
        try:
            from core.config import get_admin_client
            kc = get_admin_client()
            kc.set_user_password(user_id, new_password, temporary=False)
            logger.info(f"Password updated successfully for user_id: {user_id}")
            return {"message": "Password updated successfully"}
        except KeycloakError as e:
            log_error(logger, e, {"user_id": user_id, "action": "update_password"})
            raise HTTPException(
                status_code=400, detail=f"Password update failed: {e}")

    @staticmethod
    def send_verification_email(user_id: str) -> dict:
        """Send verification email to current user."""
        logger.info(f"Sending verification email for user_id: {user_id}")
        try:
            from core.config import get_admin_client
            kc = get_admin_client()
            kc.send_verify_email(user_id=user_id)
            logger.info(f"Verification email sent successfully for user_id: {user_id}")
            return {"message": "Verification email sent"}
        except KeycloakError as e:
            log_error(logger, e, {"user_id": user_id, "action": "send_verification_email"})
            raise HTTPException(
                status_code=400, detail=f"Failed to send email: {e}")

    @staticmethod
    def get_my_memberships(user: dict) -> dict:
        """Get current user's memberships (orgs, teams, roles)."""
        user_id = user.get('sub', 'unknown')
        logger.debug(f"Fetching memberships for user_id: {user_id}")
        try:
            from utils.helpers import parse_user_orgs, parse_admin_orgs, parse_managed_teams, parse_member_teams

            groups = [g.lower() for g in (user.get('groups', []) or [])]
            orgs = sorted(list(parse_user_orgs(groups)))
            admin_orgs = sorted(list(parse_admin_orgs(groups)))
            managed_teams = sorted([{"org": o, "team": t} for (
                o, t) in parse_managed_teams(groups)], key=lambda x: (x["org"], x["team"]))
            member_teams = sorted([{"org": o, "team": t} for (
                o, t) in parse_member_teams(groups)], key=lambda x: (x["org"], x["team"]))
            result = {
                "is_super_admin": "/super-admin" in groups,
                "orgs": orgs,
                "admin_orgs": admin_orgs,
                "managed_teams": managed_teams,
                "member_teams": member_teams,
                "raw_groups": groups,
            }
            logger.debug(f"Memberships retrieved for user_id: {user_id}")
            return result
        except Exception as e:
            log_error(logger, e, {"user_id": user_id, "action": "get_memberships"})
            raise
