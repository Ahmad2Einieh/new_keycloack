from typing import Optional
from pydantic import BaseModel


class TeamCreate(BaseModel):
    name: str
    manager_username: Optional[str] = None
