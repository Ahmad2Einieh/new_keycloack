from keycloak import KeycloakOpenID, KeycloakAdmin
from fastapi.security import OAuth2PasswordBearer

# --- Configuration (Load from ENV in production) ---
KEYCLOAK_URL = "http://localhost:8099/"
REALM_NAME = "yameen_realm"
CLIENT_ID = "yameen_backend_client"
CLIENT_SECRET = "i3M9IhiFN5cViff64gRp32ndYKygFzBd"

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
