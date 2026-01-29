"""Entry point for FilterDNS."""

import asyncio
import signal
import sys

import structlog
from hypercorn.asyncio import serve
from hypercorn.config import Config

from filterdns.app import create_app
from filterdns.config import settings
from filterdns.gateway.dns53 import DNS53Server
from filterdns.gateway.dot import DoTServer

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer() if settings.debug else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


async def run_servers() -> None:
    """Run all DNS servers concurrently."""
    # Create Quart app
    app = create_app()

    # Configure Hypercorn
    config = Config()
    config.bind = [f"0.0.0.0:{settings.admin_port}"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.startup_timeout = 300  # 5 minutes for blocklist loading

    # TLS for DoH (if configured)
    if settings.has_tls:
        doh_config = Config()
        doh_config.bind = [f"0.0.0.0:{settings.doh_port}"]
        doh_config.certfile = str(settings.tls_cert)
        doh_config.keyfile = str(settings.tls_key)
        doh_config.alpn_protocols = ["h2", "http/1.1"]

    # Create shutdown event
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Start servers
    servers = []

    # DNS53 server (UDP/TCP on port 53)
    dns53 = DNS53Server()
    await dns53.start()
    servers.append(dns53)

    # DoT server (TLS on port 853)
    dot = DoTServer()
    await dot.start()
    servers.append(dot)

    logger.info(
        "FilterDNS servers started",
        admin_port=settings.admin_port,
        dns_port=settings.dns_port,
        doh_port=settings.doh_port if settings.has_tls else None,
        dot_port=settings.dot_port if settings.has_tls else None,
    )

    try:
        # Run Hypercorn (Admin UI + API + DoH if no separate TLS)
        if settings.has_tls:
            # Run admin on HTTP and DoH on HTTPS
            await asyncio.gather(
                serve(app, config, shutdown_trigger=shutdown_event.wait),
                serve(app, doh_config, shutdown_trigger=shutdown_event.wait),
            )
        else:
            # Run everything on HTTP (development mode)
            await serve(app, config, shutdown_trigger=shutdown_event.wait)

    finally:
        # Stop DNS servers
        for server in servers:
            await server.stop()


def main() -> None:
    """Main entry point."""
    print(
        """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███████╗██╗██╗  ████████╗███████╗██████╗ ██████╗ ███╗   ██╗ ║
    ║   ██╔════╝██║██║  ╚══██╔══╝██╔════╝██╔══██╗██╔══██╗████╗  ██║ ║
    ║   █████╗  ██║██║     ██║   █████╗  ██████╔╝██║  ██║██╔██╗ ██║ ║
    ║   ██╔══╝  ██║██║     ██║   ██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║ ║
    ║   ██║     ██║███████╗██║   ███████╗██║  ██║██████╔╝██║ ╚████║ ║
    ║   ╚═╝     ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝ ║
    ║                                                               ║
    ║           Self-Hosted DNS Filtering for ZKM                   ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    )

    logger.info(
        "Starting FilterDNS",
        domain=settings.domain,
        admin_port=settings.admin_port,
        dns_port=settings.dns_port,
        doh_port=settings.doh_port,
        dot_port=settings.dot_port,
        debug=settings.debug,
    )

    try:
        asyncio.run(run_servers())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Fatal error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
