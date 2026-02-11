from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    # If provided, the new user will be added to each /OrgName/user group.
    # - Super-admin can pass any org names
    # - Org-admin can only pass orgs they admin; if omitted, defaults to all orgs they admin
    orgs: Optional[List[str]] = Field(
        default=None, description="Optional list of organization names")


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None


class PasswordUpdate(BaseModel):
    new_password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    enabled: bool


class AddUserRole(BaseModel):
    username: str
