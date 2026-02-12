from fastapi import APIRouter, Depends, Response, Request, HTTPException
from services.auth_service import AuthService
from models.user import LoginRequest, UserUpdate, PasswordUpdate, UserResponse, VerifyEmailAndPasswordUpdate
from core.security import get_current_user
from core.logger import get_logger, log_error

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger(__name__)


@auth_router.post("/login")
async def login(response: Response, form_data: LoginRequest = Depends()):
    """Authenticate user and set tokens in HTTP-only cookies."""
    logger.info(f"Login attempt for email: {form_data.email}")
    try:
        tokens = AuthService.login(form_data.email, form_data.password)
        logger.info(f"Login successful for email: {form_data.email}")
    except Exception as e:
        log_error(logger, e, {"email": form_data.email, "action": "login"})
        raise

    # Set access token cookie (short-lived)
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=tokens.get("expires_in", 3600)
    )

    # Set refresh token cookie (long-lived)
    response.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        secure=False,  # Set to True in production with HT  TPS
        samesite="lax",
        max_age=tokens.get("refresh_expires_in", 86400)
    )

    return {"message": "Login successful", "token_type": "bearer"}


@auth_router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    """Refresh access token using refresh token from cookie."""
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        logger.warning("Refresh token attempt with no token in cookies")
        raise HTTPException(
            status_code=401, detail="Refresh token not found in cookies")

    try:
        tokens = AuthService.refresh_token(refresh_token)
        logger.info("Token refreshed successfully")
    except Exception as e:
        log_error(logger, e, {"action": "refresh_token"})
        raise

    # Update access token cookie
    response.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=tokens.get("expires_in", 3600)
    )

    # Update refresh token cookie if a new one is provided
    if "refresh_token" in tokens:
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
            max_age=tokens.get("refresh_expires_in", 86400)
        )

    return {"message": "Token refreshed successfully"}


@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout user and clear authentication cookies."""
    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        # Logout from Keycloak
        try:
            AuthService.logout(refresh_token)
            logger.info("User logged out successfully")
        except Exception as e:
            log_error(logger, e, {"action": "logout"})

    # Clear cookies
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    return {"message": "Logged out successfully"}


@auth_router.get("/me/profile", response_model=UserResponse)
async def get_my_profile(user: dict = Depends(get_current_user)):
    """Get current user profile."""
    user_id = user.get('sub')
    logger.debug(f"Fetching profile for user_id: {user_id}")
    try:
        result = AuthService.get_my_profile(user_id)
        logger.debug(f"Profile retrieved successfully for user_id: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"user_id": user_id, "action": "get_profile"})
        raise


@auth_router.put("/me/profile")
async def update_my_profile(update_data: UserUpdate, user: dict = Depends(get_current_user)):
    """Update current user profile."""
    user_id = user.get('sub')
    logger.info(f"Updating profile for user_id: {user_id}")
    try:
        result = AuthService.update_my_profile(
            user_id, update_data.model_dump())
        logger.info(f"Profile updated successfully for user_id: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"user_id": user_id, "action": "update_profile"})
        raise


@auth_router.put("/me/password")
async def update_my_password(pwd: PasswordUpdate, user: dict = Depends(get_current_user)):
    """Update current user password."""
    user_id = user.get('sub')
    logger.info(f"Updating password for user_id: {user_id}")
    try:
        result = AuthService.update_my_password(user_id, pwd.new_password)
        logger.info(f"Password updated successfully for user_id: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"user_id": user_id, "action": "update_password"})
        raise


@auth_router.get("/me/memberships")
async def my_memberships(user: dict = Depends(get_current_user)):
    """Get current user's memberships (orgs, teams, roles)."""
    user_id = user.get('sub')
    logger.debug(f"Fetching memberships for user_id: {user_id}")
    try:
        result = AuthService.get_my_memberships(user)
        logger.debug(
            f"Memberships retrieved successfully for user_id: {user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"user_id": user_id, "action": "get_memberships"})
        raise


@auth_router.post("/verify-email-password")
async def verify_email_and_update_password(data: VerifyEmailAndPasswordUpdate):
    """Verify email and update password (no authentication required)."""
    logger.info(f"Verifying email and updating password for user_id: {data.user_id}")
    try:
        result = AuthService.verify_email_and_update_password(
            data.user_id, data.new_password
        )
        logger.info(f"Email verified and password updated for user_id: {data.user_id}")
        return result
    except Exception as e:
        log_error(logger, e, {"user_id": data.user_id, "action": "verify_email_and_update_password"})
        raise
