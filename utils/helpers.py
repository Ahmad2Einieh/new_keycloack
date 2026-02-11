from typing import List, Optional, Dict, Any, Set, Tuple
from fastapi import HTTPException
from keycloak.exceptions import KeycloakError


# --- Normalization & Validation ---


def normalize_kc_name(value: Optional[str]) -> Optional[str]:
    """Normalize a name to lowercase and trim whitespace."""
    if value is None:
        return None
    return value.strip().lower()


def normalize_kc_list(values: Optional[List[str]]) -> Optional[List[str]]:
    """Normalize a list of names to lowercase and trim whitespace."""
    if values is None:
        return None
    return [v.strip().lower() for v in values if v is not None]


# Names that must never be used for org/team group names (to avoid collisions with role subgroups)
RESERVED_GROUP_NAMES: Set[str] = {
    "admin", "super-admin", "user", "manager", "member",
    # common variants / future-proofing
    "admins", "users", "managers", "members", "role", "roles",
}


def validate_group_name_not_reserved(name: str, kind: str) -> str:
    """
    Ensures org/team names are safe:
    - Lowercase & trimmed
    - Not in RESERVED_GROUP_NAMES
    """
    n = normalize_kc_name(name) or ""
    if not n:
        raise HTTPException(status_code=400, detail=f"{kind} name is required")
    if n in RESERVED_GROUP_NAMES:
        raise HTTPException(
            status_code=400,
            detail=f"{kind} name '{name}' is reserved and cannot be used"
        )
    return n


def get_group_id_by_path(kc_admin, path: str) -> Optional[str]:
    """Get group ID by path from Keycloak. All group paths are stored/queried in lowercase."""
    path = (path or '').strip().lower()
    try:
        group = kc_admin.get_group_by_path(path)
        return group['id'] if group else None
    except KeycloakError:
        return None


def get_user_id_by_username(kc_admin, username: str) -> str:
    """Get user ID by username from Keycloak."""
    user_id = kc_admin.get_user_id(username)
    if not user_id:
        raise HTTPException(
            status_code=404, detail=f"User '{username}' not found")
    return user_id


# --- Group Parsing Functions ---


def parse_admin_orgs(groups: List[str]) -> Set[str]:
    """Parse admin groups to extract org names. e.g. "/acme/admin" -> "acme"."""
    out: Set[str] = set()
    for g in groups or []:
        g = (g or '').lower()
        parts = [p for p in g.split("/") if p]
        if len(parts) == 2 and parts[1] == "admin":
            out.add(parts[0])
    return out


def parse_managed_teams(groups: List[str]) -> Set[Tuple[str, str]]:
    """Parse manager groups to extract team names. e.g. "/acme/payments/manager" -> ("acme","payments")."""
    out: Set[Tuple[str, str]] = set()
    for g in groups or []:
        g = (g or '').lower()
        parts = [p for p in g.split("/") if p]
        if len(parts) == 3 and parts[2] == "manager":
            out.add((parts[0], parts[1]))
    return out


def parse_member_teams(groups: List[str]) -> Set[Tuple[str, str]]:
    """Parse member groups to extract team names. e.g. "/acme/payments/member" -> ("acme","payments")."""
    out: Set[Tuple[str, str]] = set()
    for g in groups or []:
        g = (g or '').lower()
        parts = [p for p in g.split("/") if p]
        if len(parts) == 3 and parts[2] == "member":
            out.add((parts[0], parts[1]))
    return out


def parse_user_orgs(groups: List[str]) -> Set[str]:
    """Parse all groups to extract orgs user belongs to (admin or user or team member/manager)."""
    out: Set[str] = set()
    for g in groups or []:
        g = (g or '').lower()
        parts = [p for p in g.split("/") if p]
        if len(parts) >= 2:
            out.add(parts[0])
    out.discard("super-admin")  # normalized to lowercase
    return out


# --- User & Member Functions ---


def unique_users(users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate users from a list based on user ID."""
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for u in users:
        uid = u.get("id")
        if uid and uid not in seen:
            seen.add(uid)
            out.append(u)
    return out


def list_members_recursive(kc, group_id: str) -> List[Dict[str, Any]]:
    """Returns unique users in group and all its subgroups."""
    collected: List[Dict[str, Any]] = []
    try:
        collected.extend(kc.get_group_members(group_id))
    except KeycloakError:
        # If the group exists but members fetch fails, treat as empty
        pass

    try:
        group = kc.get_group(group_id)
        for sg in group.get("subGroups", []) or []:
            collected.extend(list_members_recursive(kc, sg["id"]))
    except KeycloakError:
        pass

    return unique_users(collected)


def ensure_orgs_exist(kc, org_names: List[str]) -> None:
    """Verify that all specified organizations exist in Keycloak."""
    for org in org_names:
        if not get_group_id_by_path(kc, f"/{org}"):
            raise HTTPException(
                status_code=404, detail=f"Organization '{org}' not found")


def is_user_in_scope(kc, target_user_id: str, scope_orgs: Set[str], scope_teams: Set[Tuple[str, str]]) -> bool:
    """Checks whether a target user belongs to any allowed org/team scope."""
    if not scope_orgs and not scope_teams:
        return False
    try:
        t_groups = kc.get_user_groups(target_user_id) or []
    except KeycloakError:
        return False
    for g in t_groups:
        p = g.get("path", "")
        parts = [x for x in p.split("/") if x]
        if not parts:
            continue
        org = parts[0]
        if org in scope_orgs:
            return True
        if len(parts) >= 2 and (org, parts[1]) in scope_teams:
            return True
    return False
