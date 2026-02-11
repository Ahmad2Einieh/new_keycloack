from typing import Optional
from pydantic import BaseModel


class OrgCreate(BaseModel):
    name: str
    admin_username: Optional[str] = None  # Now Optional


class OrgResponse(BaseModel):
    id: str
    name: str
    path: str
