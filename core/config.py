from keycloak import KeycloakOpenID, KeycloakAdmin
from fastapi.security import OAuth2PasswordBearer
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    KEYCLOAK_URL: str
    REALM_NAME: str
    CLIENT_ID: str
    CLIENT_SECRET: str


# --- Configuration (Load from ENV) ---
settings = Settings()
KEYCLOAK_URL = settings.KEYCLOAK_URL
REALM_NAME = settings.REALM_NAME
CLIENT_ID = settings.CLIENT_ID
CLIENT_SECRET = settings.CLIENT_SECRET

# --- Keycloak Clients ---
# 1. OpenID Client (For Login/Token validation)
keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_URL,
    client_id=CLIENT_ID,
    realm_name=REALM_NAME,
    client_secret_key=CLIENT_SECRET
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# 2. Admin Client (For Management Actions)
# Helper to get a fresh admin token/client for every request to avoid expiration issues
def get_admin_client():
    """Get a fresh Keycloak admin client instance."""
    return KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        client_id=CLIENT_ID,
        realm_name=REALM_NAME,
        client_secret_key=CLIENT_SECRET,
        verify=True
    )
