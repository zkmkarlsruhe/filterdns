"""Authentication middleware for the API."""

import hmac
import secrets
import time
from functools import wraps
from typing import Any, Callable
from uuid import UUID

import bcrypt
from quart import Response, jsonify, request, session

from filterdns.config import settings
from filterdns.db import queries

# Cache for admin password hash (computed once at startup)
_admin_password_hash: bytes | None = None

# Token store: {token: {"profile_id": UUID, "expires_at": float}}
# In production, use Redis or similar for distributed deployments
_profile_tokens: dict[str, dict[str, Any]] = {}

# Token settings
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
TOKEN_CLEANUP_INTERVAL = 300  # Clean expired tokens every 5 minutes
_last_cleanup = 0.0


def _cleanup_expired_tokens() -> None:
    """Remove expired tokens from the store."""
    global _last_cleanup
    now = time.time()

    # Only cleanup periodically to avoid overhead
    if now - _last_cleanup < TOKEN_CLEANUP_INTERVAL:
        return

    _last_cleanup = now
    expired = [token for token, data in _profile_tokens.items() if data["expires_at"] < now]
    for token in expired:
        del _profile_tokens[token]


def generate_profile_token(profile_id: UUID) -> str:
    """Generate a secure token for profile authentication.

    Returns a cryptographically secure token that can be used
    for subsequent API requests.
    """
    _cleanup_expired_tokens()

    # Generate a secure random token (32 bytes = 256 bits)
    token = secrets.token_urlsafe(32)

    # Store with expiry
    _profile_tokens[token] = {
        "profile_id": str(profile_id),
        "expires_at": time.time() + TOKEN_EXPIRY_SECONDS
    }

    return token


def validate_profile_token(token: str) -> str | None:
    """Validate a profile token and return the profile_id if valid.

    Returns None if token is invalid or expired.
    """
    _cleanup_expired_tokens()

    if not token:
        return None

    token_data = _profile_tokens.get(token)
    if not token_data:
        return None

    # Check expiry
    if token_data["expires_at"] < time.time():
        del _profile_tokens[token]
        return None

    return token_data["profile_id"]


def revoke_profile_token(token: str) -> None:
    """Revoke a profile token (logout)."""
    _profile_tokens.pop(token, None)


def _get_admin_password_hash() -> bytes:
    """Get or compute the bcrypt hash of the admin password."""
    global _admin_password_hash
    if _admin_password_hash is None:
        _admin_password_hash = bcrypt.hashpw(
            settings.admin_password.encode(), bcrypt.gensalt()
        )
    return _admin_password_hash


def admin_required(f: Callable) -> Callable:
    """Decorator requiring admin authentication."""

    @wraps(f)
    async def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check session first (already authenticated)
        if session.get("is_admin"):
            return await f(*args, **kwargs)

        # Check Authorization header with Bearer token
        # Token must be the admin password, verified securely
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            if await verify_admin_password(token):
                return await f(*args, **kwargs)

        return jsonify({"error": "Admin authentication required"}), 401

    return decorated_function


def profile_auth_optional(f: Callable) -> Callable:
    """Decorator for optional profile password authentication.

    If the profile has a password set, validates the Authorization header.
    Accepts secure tokens (not plaintext passwords).
    """

    @wraps(f)
    async def decorated_function(*args: Any, **kwargs: Any) -> Any:
        profile_name = kwargs.get("profile_name")
        if not profile_name:
            return await f(*args, **kwargs)

        profile = await queries.get_profile_by_name(profile_name)
        if not profile:
            return jsonify({"error": "Profile not found"}), 404

        # If profile has no password, allow access
        if not profile.password_hash:
            kwargs["profile"] = profile
            return await f(*args, **kwargs)

        # Check Authorization header for token
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            # Validate token and check it belongs to this profile
            token_profile_id = validate_profile_token(token)
            if token_profile_id and token_profile_id == str(profile.id):
                kwargs["profile"] = profile
                return await f(*args, **kwargs)

        # Check session (cookie-based auth)
        if session.get(f"profile_{profile.id}"):
            kwargs["profile"] = profile
            return await f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401

    return decorated_function


async def verify_admin_password(password: str) -> bool:
    """Verify admin password using constant-time comparison.

    Uses bcrypt to prevent timing attacks on password verification.
    """
    if not password:
        return False

    try:
        # Use bcrypt checkpw for constant-time comparison
        return bcrypt.checkpw(password.encode(), _get_admin_password_hash())
    except Exception:
        return False


async def verify_profile_password(profile_id: UUID, password: str) -> bool:
    """Verify profile password."""
    return await queries.verify_profile_password(profile_id, password)
