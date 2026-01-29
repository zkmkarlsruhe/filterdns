"""DNS-over-HTTPS (DoH) endpoint (RFC 8484)."""

import base64
from typing import Any

import dns.message
import structlog
from quart import Blueprint, Response, request

from filterdns.dns.filter import DNSFilter, get_filter
from filterdns.gateway.client_resolver import ClientResolver, get_client_resolver

logger = structlog.get_logger()

# DNS message content type
DNS_MESSAGE_TYPE = "application/dns-message"


def create_doh_blueprint(
    dns_filter: DNSFilter | None = None,
    client_resolver: ClientResolver | None = None,
) -> Blueprint:
    """Create the DoH Blueprint.

    Args:
        dns_filter: DNS filter instance
        client_resolver: Client resolver instance

    Returns:
        Quart Blueprint with DoH routes
    """
    bp = Blueprint("doh", __name__)
    _dns_filter = dns_filter or get_filter()
    _client_resolver = client_resolver or get_client_resolver()

    @bp.route("/dns-query", methods=["GET", "POST"])
    async def dns_query() -> Response:
        """Handle DoH requests (RFC 8484).

        GET: DNS query in ?dns= parameter (base64url encoded)
        POST: DNS query in request body (application/dns-message)
        """
        try:
            # Get DNS message from request
            if request.method == "GET":
                # Base64url encoded query in 'dns' parameter
                dns_param = request.args.get("dns")
                if not dns_param:
                    return Response("Missing dns parameter", status=400)

                # Decode base64url (may need padding)
                padding = 4 - (len(dns_param) % 4)
                if padding != 4:
                    dns_param += "=" * padding
                dns_data = base64.urlsafe_b64decode(dns_param)

            else:  # POST
                # Raw DNS message in body
                content_type = request.content_type or ""
                if DNS_MESSAGE_TYPE not in content_type:
                    return Response(
                        f"Expected {DNS_MESSAGE_TYPE}",
                        status=415,
                    )
                dns_data = await request.get_data()

            # Parse DNS query
            query = dns.message.from_wire(dns_data)

            # Get client from subdomain
            host = request.host
            client = await _client_resolver.resolve_from_subdomain(host)

            # Filter the query
            result = await _dns_filter.filter_query(query, client)

            # Log the request
            if query.question:
                domain = str(query.question[0].name).rstrip(".")
                logger.debug(
                    "DoH query processed",
                    domain=domain,
                    host=host,
                    client_name=client.name if client else None,
                    blocked=result.blocked,
                    response_time_ms=result.response_time_ms,
                )

            # Return DNS response
            response_data = result.response.to_wire()
            return Response(
                response_data,
                status=200,
                content_type=DNS_MESSAGE_TYPE,
                headers={
                    "Cache-Control": "max-age=300",
                },
            )

        except Exception as e:
            logger.error("DoH request error", error=str(e))
            return Response("Internal server error", status=500)

    @bp.route("/resolve", methods=["GET"])
    async def json_resolve() -> dict[str, Any]:
        """JSON API for DNS resolution (Google-style).

        Query parameters:
        - name: Domain name to resolve
        - type: Record type (default: A)
        """
        name = request.args.get("name")
        if not name:
            return {"Status": 400, "Comment": "Missing name parameter"}

        rdtype = request.args.get("type", "A")

        try:
            # Create a DNS query
            query = dns.message.make_query(name, rdtype)

            # Get client from subdomain
            host = request.host
            client = await _client_resolver.resolve_from_subdomain(host)

            # Filter the query
            result = await _dns_filter.filter_query(query, client)

            # Convert response to JSON format
            response = result.response
            answer_section = []

            if response.answer:
                for rrset in response.answer:
                    for rdata in rrset:
                        answer_section.append(
                            {
                                "name": str(rrset.name),
                                "type": rrset.rdtype,
                                "TTL": rrset.ttl,
                                "data": rdata.to_text(),
                            }
                        )

            return {
                "Status": response.rcode().value,
                "TC": response.flags & dns.flags.TC != 0,
                "RD": response.flags & dns.flags.RD != 0,
                "RA": response.flags & dns.flags.RA != 0,
                "AD": response.flags & dns.flags.AD != 0,
                "CD": response.flags & dns.flags.CD != 0,
                "Question": [
                    {
                        "name": str(q.name),
                        "type": q.rdtype,
                    }
                    for q in response.question
                ],
                "Answer": answer_section if answer_section else None,
                "Comment": f"Blocked by {result.blocklist_id}" if result.blocked else None,
            }

        except Exception as e:
            logger.error("JSON resolve error", error=str(e))
            return {"Status": 2, "Comment": str(e)}

    return bp
