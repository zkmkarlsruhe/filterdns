"""Quart application factory for FilterDNS."""

import asyncio
import os
from pathlib import Path

import structlog
from quart import Quart, send_from_directory
from quart_cors import cors

from filterdns.api import create_api_blueprint
from filterdns.blocklist.engine import get_engine
from filterdns.blocklist.fetcher import load_default_blocklists, update_all_blocklists
from filterdns.config import settings
from filterdns.db.database import close_db, init_db
from filterdns.gateway.doh import create_doh_blueprint

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

        # Load default blocklists into database
        await load_default_blocklists()

        # Update blocklists
        engine = get_engine()
        await update_all_blocklists(engine)

        # Start background blocklist update task
        app.blocklist_update_task = asyncio.create_task(_blocklist_update_loop(engine))

        logger.info(
            "FilterDNS ready",
            blocklists=len(engine.get_blocklist_ids()),
            domains=engine.get_total_domains(),
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
