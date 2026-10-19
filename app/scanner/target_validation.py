from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetRejected(ValueError):
    """Raised when a target fails configured authorization/safety checks."""


_METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}
_METADATA_IPS = {
    ipaddress.ip_address(value)
    for value in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254")
}


def validate_target(url: str, allowlist: list[str], *, allow_private: bool = False) -> str:
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise TargetRejected("Malformed target URL") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise TargetRejected("Target must be an absolute HTTP(S) URL")
    if parts.username or parts.password or parts.fragment:
        raise TargetRejected("Credentials and URL fragments are not permitted")
    host = parts.hostname.rstrip(".").lower()
    if host in _METADATA_HOSTS:
        raise TargetRejected("Cloud metadata targets are blocked")
    if not any(
        host == item.lower().lstrip(".") or host.endswith("." + item.lower().lstrip("."))
        for item in allowlist
    ):
        raise TargetRejected("Target host is not explicitly allowlisted")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            answers = socket.getaddrinfo(
                host, port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM
            )
            addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
        except OSError as exc:
            raise TargetRejected("Target hostname did not resolve") from exc
    if addresses & _METADATA_IPS:
        raise TargetRejected("Cloud metadata IP targets are blocked")
    if not allow_private and any(not addr.is_global for addr in addresses):
        raise TargetRejected("Private, loopback, link-local, and reserved IP targets are blocked")
    netloc = host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), parts.query, ""))


def validate_redirect(
    base_url: str, location: str, allowlist: list[str], *, allow_private: bool = False
) -> str:
    from urllib.parse import urljoin

    return validate_target(
        urljoin(base_url.rstrip("/") + "/", location), allowlist, allow_private=allow_private
    )
