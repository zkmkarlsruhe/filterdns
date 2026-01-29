"""Quart application factory for FilterDNS."""

import asyncio
import os
from collections import defaultdict
from pathlib import Path
from time import time

import structlog
from quart import Quart, request, send_from_directory
from quart_cors import cors

from filterdns.api import create_api_blueprint
from filterdns.blocklist.engine import get_engine
from filterdns.blocklist.fetcher import load_default_blocklists, update_all_blocklists
from filterdns.cache import get_config_cache
from filterdns.config import settings
from filterdns.db.database import close_db, init_db
from filterdns.gateway.doh import create_doh_blueprint
from filterdns.profiles.loader import load_all_presets_into_engine, load_builtin_presets

logger = structlog.get_logger()


def create_app() -> Quart:
    """Create and configure the Quart application."""
    app = Quart(
        __name__,
        static_folder="static",
        static_url_path="/static",
    )

    # Enable CORS for API routes
    app = cors(app, allow_origin="*")

    # Secret key for sessions
    app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

    # Configure session
    app.config["SESSION_TYPE"] = "secure_cookie"
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400  # 24 hours

    # Rate limiting state
    rate_limit_store: dict[str, list[float]] = defaultdict(list)
    RATE_LIMIT_WINDOW = 60  # seconds
    RATE_LIMIT_MAX_REQUESTS = 30  # max requests per window for sensitive endpoints

    @app.before_request
    async def check_rate_limit():
        """Basic rate limiting for sensitive endpoints."""
        # Only rate limit profile creation
        if request.path == "/api/profiles" and request.method == "POST":
            client_ip = request.remote_addr or "unknown"
            now = time()

            # Clean old entries
            rate_limit_store[client_ip] = [
                t for t in rate_limit_store[client_ip]
                if now - t < RATE_LIMIT_WINDOW
            ]

            # Check limit
            if len(rate_limit_store[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
                return {"error": "Rate limit exceeded. Please try again later."}, 429

            # Record request
            rate_limit_store[client_ip].append(now)

    @app.after_request
    async def add_security_headers(response):
        """Add security headers to all responses."""
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # XSS protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # HSTS - only in production (when not localhost)
        if request.host and not request.host.startswith(("localhost", "127.0.0.1")):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response

    # Register blueprints
    app.register_blueprint(create_api_blueprint())
    app.register_blueprint(create_doh_blueprint())

    # Serve static files for the SPA
    @app.route("/")
    @app.route("/<path:path>")
    async def serve_spa(path: str = "index.html"):
        """Serve the SPA frontend."""
        static_dir = Path(app.static_folder or "static")

        # Try to serve the requested file
        file_path = static_dir / path
        if file_path.is_file():
            return await send_from_directory(static_dir, path)

        # For SPA routing, serve index.html for non-file paths
        # but exclude API and DNS routes
        if not path.startswith(("api/", "dns-query", "resolve")):
            index_path = static_dir / "index.html"
            if index_path.is_file():
                return await send_from_directory(static_dir, "index.html")

        return "Not found", 404

    # Lifecycle hooks
    @app.before_serving
    async def startup():
        """Initialize resources on startup."""
        logger.info("Starting FilterDNS server")

        # Initialize database
        await init_db()

        # Load default blocklists into database (skip if SKIP_BLOCKLISTS is set)
        if not os.environ.get("SKIP_BLOCKLISTS"):
            await load_default_blocklists()

            # Update blocklists
            engine = get_engine()
            await update_all_blocklists(engine)
        else:
            logger.info("Skipping blocklist loading (SKIP_BLOCKLISTS=1)")
            engine = get_engine()

        # Load built-in presets (seeds DB on first startup)
        await load_builtin_presets(engine)

        # Load all presets from DB into engine (includes any custom presets)
        await load_all_presets_into_engine(engine)

        # Initialize config cache
        cache = get_config_cache()
        logger.info("Config cache initialized", ttl_seconds=30)

        # Start background blocklist update task
        app.blocklist_update_task = asyncio.create_task(_blocklist_update_loop(engine))

        # Count preset blocklists vs regular blocklists
        all_ids = engine.get_blocklist_ids()
        preset_count = sum(1 for bid in all_ids if bid.startswith("preset_"))
        blocklist_count = len(all_ids) - preset_count

        logger.info(
            "FilterDNS ready",
            blocklists=blocklist_count,
            presets=preset_count,
            total_domains=engine.get_total_domains(),
        )

    @app.after_serving
    async def shutdown():
        """Cleanup resources on shutdown."""
        logger.info("Shutting down FilterDNS server")

        # Cancel background task
        if hasattr(app, "blocklist_update_task"):
            app.blocklist_update_task.cancel()
            try:
                await app.blocklist_update_task
            except asyncio.CancelledError:
                pass

        # Close database
        await close_db()

    return app


async def _blocklist_update_loop(engine) -> None:
    """Background task to periodically update blocklists."""
    while True:
        try:
            await asyncio.sleep(settings.blocklist_update_interval)
            logger.info("Updating blocklists")
            await update_all_blocklists(engine)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Blocklist update error", error=str(e))
            await asyncio.sleep(300)  # Wait 5 minutes on error
