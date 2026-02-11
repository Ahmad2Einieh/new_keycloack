from fastapi import APIRouter, Depends, Response, Request, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from services.auth_service import AuthService
from models.user import UserUpdate, PasswordUpdate, UserResponse
from core.security import get_current_user

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and set tokens in HTTP-only cookies."""
    tokens = AuthService.login(form_data.username, form_data.password)

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
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=tokens.get("refresh_expires_in", 86400)
    )

    return {"message": "Login successful", "token_type": "bearer"}


@auth_router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    """Refresh access token using refresh token from cookie."""
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(
            status_code=401, detail="Refresh token not found in cookies")

    tokens = AuthService.refresh_token(refresh_token)

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
        AuthService.logout(refresh_token)

    # Clear cookies
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    return {"message": "Logged out successfully"}


@auth_router.get("/me/profile", response_model=UserResponse)
async def get_my_profile(user: dict = Depends(get_current_user)):
    """Get current user profile."""
    return AuthService.get_my_profile(user['sub'])


@auth_router.put("/me/profile")
async def update_my_profile(update_data: UserUpdate, user: dict = Depends(get_current_user)):
    """Update current user profile."""
    return AuthService.update_my_profile(user['sub'], update_data.dict())


@auth_router.put("/me/password")
async def update_my_password(pwd: PasswordUpdate, user: dict = Depends(get_current_user)):
    """Update current user password."""
    return AuthService.update_my_password(user['sub'], pwd.new_password)


@auth_router.post("/me/verify-email")
async def send_verification_email(user: dict = Depends(get_current_user)):
    """Send verification email to current user."""
    return AuthService.send_verification_email(user['sub'])


@auth_router.get("/me/memberships")
async def my_memberships(user: dict = Depends(get_current_user)):
    """Get current user's memberships (orgs, teams, roles)."""
    return AuthService.get_my_memberships(user)
