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


def client_auth_optional(f: Callable) -> Callable:
    """Decorator for optional client password authentication.

    If the client has a password set, validates the Authorization header.
    """

    @wraps(f)
    async def decorated_function(*args: Any, **kwargs: Any) -> Any:
        client_name = kwargs.get("client_name")
        if not client_name:
            return await f(*args, **kwargs)

        client = await queries.get_client_by_name(client_name)
        if not client:
            return jsonify({"error": "Client not found"}), 404

        # If client has no password, allow access
        if not client.password_hash:
            kwargs["client"] = client
            return await f(*args, **kwargs)

        # Check Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            password = auth[7:]
            if bcrypt.checkpw(password.encode(), client.password_hash.encode()):
                kwargs["client"] = client
                return await f(*args, **kwargs)

        # Check session
        if session.get(f"client_{client.id}"):
            kwargs["client"] = client
            return await f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401

    return decorated_function


async def verify_admin_password(password: str) -> bool:
    """Verify admin password."""
    return password == settings.admin_password


async def verify_client_password(client_id: UUID, password: str) -> bool:
    """Verify client password."""
    return await queries.verify_client_password(client_id, password)
