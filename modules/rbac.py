ROLE_PERMISSIONS = {
    "admin": ["autopwn", "scan", "report"],
    "viewer": ["scan", "report"]
}

def is_allowed(role, action):
    return action in ROLE_PERMISSIONS.get(role, [])
