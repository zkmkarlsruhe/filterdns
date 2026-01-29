"""Authentication middleware for the API."""

from functools import wraps
from typing import Any, Callable
from uuid import UUID

import bcrypt
from quart import Response, jsonify, request, session

from filterdns.config import settings
from filterdns.db import queries


def admin_required(f: Callable) -> Callable:
    """Decorator requiring admin authentication."""

    @wraps(f)
    async def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check session
        if session.get("is_admin"):
            return await f(*args, **kwargs)

        # Check Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            if token == settings.admin_password:
                return await f(*args, **kwargs)

        return jsonify({"error": "Admin authentication required"}), 401

    return decorated_function


def profile_auth_optional(f: Callable) -> Callable:
    """Decorator for optional profile password authentication.

    If the profile has a password set, validates the Authorization header.
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

        # Check Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            password = auth[7:]
            if bcrypt.checkpw(password.encode(), profile.password_hash.encode()):
                kwargs["profile"] = profile
                return await f(*args, **kwargs)

        # Check session
        if session.get(f"profile_{profile.id}"):
            kwargs["profile"] = profile
            return await f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401

    return decorated_function


async def verify_admin_password(password: str) -> bool:
    """Verify admin password."""
    return password == settings.admin_password


async def verify_profile_password(profile_id: UUID, password: str) -> bool:
    """Verify profile password."""
    return await queries.verify_profile_password(profile_id, password)
