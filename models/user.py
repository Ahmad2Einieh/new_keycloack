from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    # If provided, the new user will be added to each /OrgName/user group.
    # - Super-admin can pass any org names
    # - Org-admin can only pass orgs they admin; if omitted, defaults to all orgs they admin
    orgs: Optional[List[str]] = Field(
        default=None, description="Optional list of organization names")

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError(
                'Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError(
                'Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', v):
            raise ValueError(
                'Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class PasswordUpdate(BaseModel):
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_new_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError(
                'Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError(
                'Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', v):
            raise ValueError(
                'Password must contain at least one special character')
        return v


class UserResponse(BaseModel):
    id: str
    email: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    enabled: bool
    groups: Optional[List[str]] = None


class AddUserRole(BaseModel):
    username: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VerifyEmailAndPasswordUpdate(BaseModel):
    user_id: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_new_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError(
                'Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError(
                'Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', v):
            raise ValueError(
                'Password must contain at least one special character')
        return v
