"""Bounded server-side probes for product protocols missed by Android Wi-Fi scans.

The mobile scanner remains the source of the normal scan.  This module is an
additional LAN observation path for the Raspberry Pi API host: it probes only
the documented Family Hub/Spotify ZeroConf endpoint on the scan subnet and
returns the manufacturer's own response as private evidence.  It never turns
an IP address or a port number into a resident-facing product name.
"""

from __future__ import annotations

import concurrent.futures
import errno
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import time
import uuid
from collections import defaultdict
from collections.abc import Container, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..scan_validation import strip_untrusted_self_claims
from .identity_enrichment import (
    bind_authenticated_self_android_claim,
    strip_untrusted_authenticated_self_android,
)


PROBE_PORT = 17654
PROBE_CONNECT_TIMEOUT_SECONDS = 0.35
PROBE_READ_TIMEOUT_SECONDS = 1.5
PROBE_MAX_HOSTS = 512
PROBE_WORKERS = 64
MAX_RESPONSE_BYTES = 8_192
_ENABLED_VALUES = {"1", "true", "yes", "on"}
NEIGHBOR_PING_TIMEOUT_SECONDS = 1.0
NEIGHBOR_PING_WORKERS = 64

# The phone's scan is intentionally quick and can be blocked by Android Wi-Fi
# isolation or by a device that does not answer multicast.  The API host is on
# the same LAN, so it gets a second, bounded evidence pass.  These are
# discovery ports only: a port is never converted into a product name.
LAN_DISCOVERY_PORTS = (
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1400, 1443, 1900, 3702,
    5000, 5001, 7000, 7001, 7547, 7676, 8001, 8002, 8008, 8009, 8060,
    8080, 8081, 8443, 8888, 8899, 9000, 9001, 9100, 9761, PROBE_PORT,
    49152, 49153, 49154, 49155, 49156, 49157,
)
LAN_PORT_TIMEOUT_SECONDS = 0.28
LAN_PORT_WORKERS = 96
HTTP_EVIDENCE_PORTS = {
    80, 1400, 5000, 7000, 7001, 7676, 8001, 8002, 8008, 8009, 8060,
    8080, 8081, 8888, 8899, 9000, 9001, 9761,
}
HTTP_EVIDENCE_BYTES = 8_192
UPNP_EVIDENCE_BYTES = 12_288
# These are response fields used by common embedded-device HTTP APIs.  The
# parser below only accepts the device's own structured JSON/XML fields; an
# HTML title or arbitrary banner remains a weaker private hint.
_HTTP_IDENTITY_KEY_ALIASES = {
    "manufacturer": frozenset(
        {
            "manufacturer",
            "manufacturername",
            "vendor",
            "vendorname",
            "brand",
            "brandname",
            "oem",
        }
    ),
    "model": frozenset(
        {
            "model",
            "modelname",
            "modelnumber",
            "modelid",
            "devicemodel",
            "devicemodelname",
            "productmodel",
        }
    ),
    "product": frozenset(
        {
            "product",
            "productname",
            "productid",
            "deviceproduct",
            "deviceproductname",
        }
    ),
    "device_type": frozenset(
        {
            "devicetype",
            "devicetypeid",
            "category",
            "producttype",
        }
    ),
    "name": frozenset(
        {
            "friendlyname",
            "displayname",
            "devicename",
            "name",
        }
    ),
}
_HTTP_IDENTITY_FIELD_PREFIXES = {
    "manufacturer": "http-manufacturer",
    "model": "http-model",
    "product": "http-product",
    "device_type": "http-device-type",
    "name": "http-name",
}
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
MDNS_LISTEN_SECONDS = 1.8
MDNS_SERVICE_TYPES = (
    "_http._tcp.local",
    "_https._tcp.local",
    "_rtsp._tcp.local",
    "_onvif._tcp.local",
    "_axis-video._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_hap._tcp.local",
    "_homekit._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_smb._tcp.local",
    "_workstation._tcp.local",
    "_smartthings._tcp.local",
    "_smarthome._tcp.local",
    "_samsungmsf._tcp.local",
    "_androidtvremote2._tcp.local",
    "_hue._tcp.local",
    "_amzn-wplay._tcp.local",
    "_sonos._tcp.local",
    "_roku-rcp._tcp.local",
    "_viziocast._tcp.local",
    "_miio._udp.local",
    "_nanoleafapi._tcp.local",
    "_spotify-connect._tcp.local",
    # LG ThinQ appliances and media devices advertise this service.  The
    # service alone never decides the product kind; TXT/UPnP evidence does.
    "_lg-smart-device._tcp.local",
)
# Match Android raw discovery: query the shared product/service allowlist plus
# DNS-SD's type-enumeration meta record on multicast.  Direct recovery uses
# only the bounded product/service list because it already targets one host.
MDNS_QUERY_TYPES = MDNS_SERVICE_TYPES + ("_services._dns-sd._udp.local",)
# Some access points suppress multicast while still allowing an appliance to
# answer a direct mDNS query. Use the same central bounded service set for
# multicast and direct recovery so isolation cannot selectively hide Matter,
# camera, appliance, media, or smart-home advertisements. Service names remain
# private evidence and never create a product identity by themselves.
MDNS_UNICAST_QUERY_TYPES = MDNS_SERVICE_TYPES
MDNS_UNICAST_WORKERS = 64
MDNS_UNICAST_TIMEOUT_SECONDS = 0.45
SSDP_UNICAST_WORKERS = 64
SSDP_UNICAST_TIMEOUT_SECONDS = 0.85
WS_DISCOVERY_GROUP = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
WS_DISCOVERY_LISTEN_SECONDS = 1.8
DHCP_LEASE_PATHS = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/var/lib/NetworkManager/dnsmasq-dhcp.leases",
)
PROC_NET_ARP_PATH = "/proc/net/arp"
PROC_NET_ROUTE_PATH = "/proc/net/route"
SIOCGIFADDR = 0x8915
# CPython does not expose IP_PKTINFO on every build even though Linux assigns
# it the stable value 8.  The server probe is deployed on Linux; unsupported
# platforms fail closed when socket setup is attempted.
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
# Linux's stable socket option for pinning all traffic to one interface.  An
# unsupported platform or a service account without permission must fail
# closed; falling back to the process-default route can cross a VPN or another
# private NIC that happens to use the same CIDR.
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
_MODEL_TOKEN_RE = re.compile(
    r"\b(?:RF|RB|QN|UN|RT-|ROG|TUF-|ARCHER|DECO|TL-|ER|DS-|IPC-|Mac|"
    r"(?:A|AX|N|T|C|G|BE|X)\d[0-9A-Z-]{2,})[0-9A-Z,._-]*\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _RouteInterfaceBinding:
    """Authoritative Linux interface coordinates for one scan subnet."""

    name: str
    ipv4: str
    ifindex: int


@dataclass(frozen=True)
class _SubnetHostScope:
    """Usable hosts on the one private subnet declared by the Android scan."""

    network: ipaddress.IPv4Network
    local_ip: ipaddress.IPv4Address

    def __contains__(self, value: object) -> bool:
        try:
            host = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        return (
            isinstance(host, ipaddress.IPv4Address)
            and host in self.network
            and host != self.network.network_address
            and host != self.network.broadcast_address
            and host != self.local_ip
        )

    @property
    def remote_host_count(self) -> int:
        # /31 and /32 are rejected when this scope is constructed.
        return max(0, self.network.num_addresses - 3)


class _InterfaceBindingError(OSError):
    """Raised before any unicast traffic when exact interface binding fails."""


_EXPECTED_TCP_PEER_NEGATIVE_ERRNOS = frozenset(
    value
    for name in (
        "ECONNABORTED",
        "ECONNREFUSED",
        "ECONNRESET",
        "EHOSTDOWN",
        "EHOSTUNREACH",
        "EPIPE",
        "ETIMEDOUT",
    )
    if (value := getattr(errno, name, None)) is not None
)


def _tcp_os_error_is_expected_peer_negative(exc: OSError) -> bool:
    """Return whether one TCP failure is a completed negative observation.

    A refused, reset, unreachable, or timed-out peer is an ordinary closed or
    non-responsive endpoint, so the bounded pass still covered that pair.
    Unknown errors and local interface/resource failures must fail closed: for
    example ENETDOWN, ENODEV, EADDRNOTAVAIL, EMFILE, and ENOBUFS mean the pass
    did not reliably observe the selected LAN and therefore must become
    ``scan_partial`` at the caller.
    """

    if isinstance(
        exc,
        (
            socket.timeout,
            ConnectionAbortedError,
            ConnectionRefusedError,
            ConnectionResetError,
            BrokenPipeError,
        ),
    ):
        return True
    return exc.errno in _EXPECTED_TCP_PEER_NEGATIVE_ERRNOS


def _enabled() -> bool:
    return os.getenv("HG_SERVER_PROTOCOL_PROBE", "").strip().lower() in _ENABLED_VALUES


def _neighbor_ping_enabled() -> bool:
    """Whether the Pi may warm its neighbour table before reading ARP.

    This is a separate production switch because a unit test or a developer
    running the protocol augmenter must never start a LAN sweep implicitly.
    The deployed Raspberry Pi unit enables it explicitly.
    """
    return os.getenv("HG_SERVER_NEIGHBOR_PING_SWEEP", "").strip().lower() in _ENABLED_VALUES


def _run_interface_ping(
    host: str,
    binding: _RouteInterfaceBinding,
    ping: str,
) -> tuple[bool, bool]:
    """Run one bounded ICMP probe on exactly the selected interface.

    The first value reports reachability.  The second reports whether the ping
    process itself ran to completion.  A normal non-zero exit is a complete
    unreachable result; inability to execute the command is an incomplete
    server pass and must never be silently treated as an offline host.
    """
    try:
        completed = subprocess.run(
            [
                ping,
                "-I",
                binding.name,
                "-c",
                "1",
                "-W",
                str(int(NEIGHBOR_PING_TIMEOUT_SECONDS)),
                "-n",
                host,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=NEIGHBOR_PING_TIMEOUT_SECONDS + 0.5,
            check=False,
        )
        return_code = getattr(completed, "returncode", 2)
        if return_code == 0:
            return True, True
        if return_code == 1:
            return False, True
        # iputils reserves exit code 2 for local/command errors (including an
        # invalid or unusable interface).  Such a result says nothing about
        # host reachability and makes the server pass incomplete.
        return False, False
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False, False


def _refresh_gateway_neighbor(
    gateway: str,
    binding: _RouteInterfaceBinding,
) -> tuple[set[str], bool]:
    """Refresh only the declared gateway before authorizing a subnet sweep.

    This one-host safety probe is always attempted when Pi augmentation is
    enabled; the optional full-neighbour sweep remains gated by
    ``HG_SERVER_NEIGHBOR_PING_SWEEP`` and runs only after same-L2 proof.
    """
    try:
        parsed = ipaddress.ip_address(str(gateway).strip())
    except ValueError:
        return set(), False
    if parsed.version != 4 or not parsed.is_private:
        return set(), False
    ping = shutil.which("ping") or shutil.which("ping4")
    if not ping:
        return set(), False
    canonical = str(parsed)
    responsive, complete = _run_interface_ping(canonical, binding, ping)
    return ({canonical} if responsive else set()), complete


def _refresh_exact_neighbor(
    host: str,
    binding: _RouteInterfaceBinding,
) -> tuple[set[str], bool]:
    """Refresh one exact same-LAN host on the selected interface.

    Unlike the optional subnet sweep, current-self attestation cannot use a
    cached row or another host's activity.  Reuse the always-on, one-address
    gateway primitive only after the gateway has already proved this L2.
    """

    return _refresh_gateway_neighbor(host, binding)


def _refresh_local_neighbors(
    hosts: Sequence[str],
    binding: _RouteInterfaceBinding,
) -> tuple[set[str], bool]:
    """Warm the Pi's ARP/neighbour table with a bounded ICMP pass.

    A device with every TCP port closed and no multicast advertisement is
    still a real LAN device.  Linux learns its MAC when it answers one bounded
    ping, after which ``_local_neighbor_entries`` can carry that observation
    into the normal identity/catalog pipeline.  We discard ping output and
    never turn reachability into a product name.
    """
    if not _neighbor_ping_enabled() or not hosts:
        return set(), True
    ping = shutil.which("ping") or shutil.which("ping4")
    if not ping:
        return set(), False

    def probe(host: str) -> tuple[str | None, bool]:
        responsive, complete = _run_interface_ping(host, binding, ping)
        return (host if responsive else None), complete

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=NEIGHBOR_PING_WORKERS
        ) as executor:
            results = list(executor.map(probe, hosts))
    except (OSError, RuntimeError, ValueError):
        return set(), False
    return (
        {host for host, _complete in results if host is not None},
        all(complete for _host, complete in results),
    )


def _subnet_host_scope(
    network_context: Mapping[str, Any] | None,
) -> _SubnetHostScope | None:
    if not isinstance(network_context, Mapping):
        return None
    raw_subnet = str(network_context.get("subnet_cidr") or "").strip()
    try:
        network = ipaddress.ip_network(raw_subnet, strict=False)
        local_ip = ipaddress.ip_address(
            str(network_context.get("local_ip") or "").strip()
        )
    except ValueError:
        return None
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not network.is_private
        or network.num_addresses < 4
        or not isinstance(local_ip, ipaddress.IPv4Address)
        or local_ip not in network
        or local_ip in (network.network_address, network.broadcast_address)
    ):
        return None
    return _SubnetHostScope(network=network, local_ip=local_ip)


def _probe_hosts(network_context: Mapping[str, Any] | None) -> list[str]:
    """Return a bounded, rank-proportional sample of remote usable hosts.

    A /24 is covered completely.  Larger CIDRs retain both usable ends and an
    even distribution through the middle rather than silently skipping the Pi
    pass or clustering probes at the low end of the address range.
    """
    scope = _subnet_host_scope(network_context)
    if scope is None or scope.remote_host_count <= 0:
        return []

    sample_count = min(scope.remote_host_count, PROBE_MAX_HOSTS)
    first = int(scope.network.network_address) + 1
    local_offset = int(scope.local_ip) - first
    remote_count = scope.remote_host_count
    hosts: list[str] = []
    for rank in range(sample_count):
        remote_rank = (
            0
            if sample_count == 1
            else rank * (remote_count - 1) // (sample_count - 1)
        )
        address_offset = remote_rank + (1 if remote_rank >= local_offset else 0)
        hosts.append(str(ipaddress.IPv4Address(first + address_offset)))
    return hosts


def _probe_coverage_complete(scope: _SubnetHostScope) -> bool:
    return scope.remote_host_count <= PROBE_MAX_HOSTS


def _prioritized_probe_hosts(
    sampled_hosts: Sequence[str],
    scope: _SubnetHostScope,
    discovered_devices: Sequence[Mapping[str, Any]],
    current_interface_neighbors: Mapping[str, Any],
    gateway: str,
) -> list[str]:
    """Merge known in-scope hosts ahead of the uniform sample, by IP once.

    Android observations and the selected interface's neighbour entries are
    only probe priorities here.  They do not refresh a MAC or establish a
    product identity without fresh response evidence later in the pass.
    """
    ordered: dict[str, None] = {}

    def add(value: Any) -> None:
        canonical = _canonical_allowed_host(value, scope)
        if canonical is not None:
            ordered.setdefault(canonical, None)

    add(gateway)
    for device in discovered_devices:
        add(device.get("ip_address"))
    for host in sorted(current_interface_neighbors):
        add(host)
    for host in sampled_hosts:
        add(host)
    # Structural evidence stays ahead of the uniform sample, but adding those
    # priorities must never expand the actual Pi sweep beyond the API's one
    # bounded observation budget.
    return list(ordered)[:PROBE_MAX_HOSTS]


def _canonical_allowed_host(
    host: Any,
    allowed_hosts: Container[str],
) -> str | None:
    """Return a canonical IPv4 address only when this request may observe it.

    ``is_private`` is deliberately insufficient here: the Raspberry Pi can
    have several private interfaces (for example Ethernet, Wi-Fi, Docker or a
    VPN).  Server-side discovery evidence belongs to the scan only when its
    source address is one of the exact hosts derived from the request's
    validated ``subnet_cidr``.
    """
    try:
        parsed = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return None
    canonical = str(parsed)
    if parsed.version != 4 or canonical not in allowed_hosts:
        return None
    return canonical


def _filter_allowed_host_mapping(
    entries: Mapping[str, Any] | None,
    allowed_hosts: Container[str],
) -> dict[str, Any]:
    """Apply the request-scoped host allowlist to one discovery result map."""
    filtered: dict[str, Any] = {}
    for host, value in (entries or {}).items():
        canonical = _canonical_allowed_host(host, allowed_hosts)
        if canonical is not None:
            filtered[canonical] = value
    return filtered


def _safe_response_text(value: Any) -> str:
    text = " ".join(str(value or "").split())
    if not text or any(ord(char) < 32 for char in text):
        return ""
    return text[:160]


def _get_info(
    host: str,
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, str] | None, bool]:
    """Read the endpoint's own product fields without exposing the response."""
    request_paths = ("/zc/0?action=getInfo&version=2.10.0", "/?action=getInfo&version=2.10.0")
    for path in request_paths:
        try:
            with _new_interface_tcp_connection(
                host,
                PROBE_PORT,
                binding,
                timeout=PROBE_CONNECT_TIMEOUT_SECONDS,
            ) as conn:
                conn.settimeout(PROBE_READ_TIMEOUT_SECONDS)
                conn.sendall(
                    (
                        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                        "Accept: application/json\r\nConnection: close\r\n\r\n"
                    ).encode("ascii")
                )
                chunks: list[bytes] = []
                size = 0
                while size < MAX_RESPONSE_BYTES:
                    block = conn.recv(min(2048, MAX_RESPONSE_BYTES - size))
                    if not block:
                        break
                    chunks.append(block)
                    size += len(block)
                response = b"".join(chunks).decode("utf-8", errors="ignore")
            header_end = response.find("\r\n\r\n")
            if header_end < 0:
                header_end = response.find("\n\n")
            if header_end < 0 or not response.startswith("HTTP/"):
                continue
            status_line = response.splitlines()[0] if response.splitlines() else ""
            status = status_line.split(" ", 2)[1] if len(status_line.split(" ", 2)) > 1 else ""
            if not status.startswith("2"):
                continue
            body = response[header_end + (4 if response[header_end:header_end + 4] == "\r\n\r\n" else 2) :]
            payload = json.loads(body)
            if not isinstance(payload, Mapping):
                continue
            result = {
                "brand": _safe_response_text(payload.get("brandDisplayName")),
                "model": _safe_response_text(payload.get("modelDisplayName")),
                "name": _safe_response_text(payload.get("remoteName")),
                "type": _safe_response_text(payload.get("deviceType")),
            }
            if any(result.values()):
                return result, True
        except _InterfaceBindingError:
            return None, False
        except OSError as exc:
            if not _tcp_os_error_is_expected_peer_negative(exc):
                return None, False
            continue
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return None, True


def _linux_route_address(value: str) -> ipaddress.IPv4Address | None:
    """Decode one little-endian IPv4 value from ``/proc/net/route``."""
    try:
        raw = int(str(value).strip(), 16).to_bytes(4, byteorder="little", signed=False)
        return ipaddress.IPv4Address(raw)
    except (ValueError, OverflowError):
        return None


def _routing_interface(network_context: Mapping[str, Any] | None) -> str | None:
    """Resolve the direct Linux interface that currently owns this scan LAN.

    The route must be up, directly connected, and cover the complete declared
    subnet.  Longest prefix and then lowest metric mirror the normal main-table
    choice when two interfaces expose the same private CIDR.  If that cannot
    be established from the read-only route table, ARP evidence fails closed.
    """
    if not isinstance(network_context, Mapping):
        return None
    try:
        declared = ipaddress.ip_network(
            str(network_context.get("subnet_cidr") or "").strip(), strict=False
        )
    except ValueError:
        return None
    if declared.version != 4 or not declared.is_private:
        return None

    raw_gateway = str(network_context.get("gateway_ip") or "").strip()
    if raw_gateway:
        try:
            gateway = ipaddress.ip_address(raw_gateway)
        except ValueError:
            return None
        if gateway.version != 4 or gateway not in declared:
            return None

    try:
        lines = Path(PROC_NET_ROUTE_PATH).read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines()[1:]
    except OSError:
        return None

    candidates: list[tuple[int, int, int, str]] = []
    for order, line in enumerate(lines):
        parts = line.split()
        if len(parts) < 8:
            continue
        interface, raw_destination, raw_gateway_route = parts[0], parts[1], parts[2]
        raw_flags, raw_metric, raw_mask = parts[3], parts[6], parts[7]
        if not interface or len(interface) > 64 or any(ord(char) < 33 for char in interface):
            continue
        destination = _linux_route_address(raw_destination)
        route_gateway = _linux_route_address(raw_gateway_route)
        mask = _linux_route_address(raw_mask)
        if destination is None or route_gateway is None or mask is None:
            continue
        try:
            flags = int(raw_flags, 16)
            metric = int(raw_metric, 10)
            route = ipaddress.IPv4Network(
                (str(destination), str(mask)), strict=False
            )
        except (ValueError, TypeError):
            continue
        if not flags & 0x1 or int(route_gateway) != 0:
            continue
        if not declared.subnet_of(route):
            continue
        candidates.append((route.prefixlen, -metric, -order, interface))
    if not candidates:
        return None
    return max(candidates)[3]


def _interface_ipv4_address(interface: str) -> str | None:
    """Read the primary IPv4 address assigned to one Linux interface.

    There is deliberately no hostname/default-route fallback here.  Either
    the selected route interface itself proves an address, or multicast and
    direct UDP discovery are skipped for this scan.
    """
    encoded = str(interface or "").encode("utf-8", errors="strict")
    if not encoded or len(encoded) > 15 or b"\x00" in encoded:
        return None
    try:
        import fcntl  # Linux-only; the production protocol probe runs on Pi.

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            response = fcntl.ioctl(
                control.fileno(),
                SIOCGIFADDR,
                struct.pack("256s", encoded),
            )
        return socket.inet_ntoa(response[20:24])
    except (ImportError, OSError, ValueError, struct.error, UnicodeError):
        return None


def _resolve_route_interface_binding(
    interface: str | None,
    network_context: Mapping[str, Any] | None,
) -> _RouteInterfaceBinding | None:
    """Resolve and validate the selected route interface's IPv4 and ifindex."""
    if not interface or not isinstance(network_context, Mapping):
        return None
    try:
        declared = ipaddress.ip_network(
            str(network_context.get("subnet_cidr") or "").strip(), strict=False
        )
        interface_address = ipaddress.ip_address(
            str(_interface_ipv4_address(interface) or "").strip()
        )
        ifindex = socket.if_nametoindex(interface)
    except (OSError, ValueError):
        return None
    if (
        declared.version != 4
        or not declared.is_private
        or interface_address.version != 4
        or interface_address not in declared
        or interface_address in {declared.network_address, declared.broadcast_address}
        or ifindex <= 0
    ):
        return None
    return _RouteInterfaceBinding(
        name=interface,
        ipv4=str(interface_address),
        ifindex=ifindex,
    )


def _mark_server_probe_partial(
    network_context: Mapping[str, Any] | None,
) -> None:
    """Surface an interface-scoped discovery failure without identifiers."""
    if not isinstance(network_context, MutableMapping):
        return
    raw_diagnostics = network_context.get("scan_diagnostics")
    diagnostics = (
        dict(raw_diagnostics) if isinstance(raw_diagnostics, Mapping) else {}
    )
    diagnostics["scan_partial"] = True
    network_context["scan_diagnostics"] = diagnostics


def _mark_server_probe_l2_unverified(
    network_context: Mapping[str, Any] | None,
) -> None:
    """Record an optional Pi-pass limitation without invalidating native coverage.

    Android 11 may expose no gateway MAC to the app even when the Wi-Fi scan
    itself completed every declared IPv4 candidate. In that case the Pi
    enrichment pass must not run, but the authoritative native coverage is
    still usable for scoring and device presentation.
    """
    if not isinstance(network_context, MutableMapping):
        return
    raw_diagnostics = network_context.get("scan_diagnostics")
    diagnostics = (
        dict(raw_diagnostics) if isinstance(raw_diagnostics, Mapping) else {}
    )
    diagnostics["server_probe_l2_unverified"] = True
    network_context["scan_diagnostics"] = diagnostics


def _bind_socket_to_interface(
    sock: socket.socket,
    binding: _RouteInterfaceBinding,
) -> None:
    """Pin a socket to the selected Linux interface before any network I/O."""
    interface_bytes = binding.name.encode("utf-8", errors="strict")
    if (
        not interface_bytes
        or len(interface_bytes) > 15
        or b"\x00" in interface_bytes
    ):
        raise _InterfaceBindingError("invalid interface name")
    try:
        sock.setsockopt(
            socket.SOL_SOCKET,
            SO_BINDTODEVICE,
            interface_bytes + b"\x00",
        )
    except (OSError, ValueError, UnicodeError) as exc:
        raise _InterfaceBindingError("exact interface binding failed") from exc


def _new_interface_tcp_socket(
    binding: _RouteInterfaceBinding,
    *,
    timeout: float,
) -> socket.socket:
    """Create an unconnected TCP socket pinned to interface and local IPv4."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        _bind_socket_to_interface(sock, binding)
        sock.bind((binding.ipv4, 0))
        sock.settimeout(timeout)
        return sock
    except _InterfaceBindingError:
        sock.close()
        raise
    except (OSError, ValueError) as exc:
        sock.close()
        raise _InterfaceBindingError("exact local IPv4 binding failed") from exc


def _new_interface_tcp_connection(
    host: str,
    port: int,
    binding: _RouteInterfaceBinding,
    *,
    timeout: float,
) -> socket.socket:
    """Connect without ever consulting the process-default interface."""
    sock = _new_interface_tcp_socket(binding, timeout=timeout)
    try:
        sock.connect((host, port))
        return sock
    except OSError:
        sock.close()
        raise


def _preflight_interface_unicast_binding(
    binding: _RouteInterfaceBinding,
) -> bool:
    """Prove the service can pin unicast sockets before probing the LAN."""
    try:
        with _new_interface_tcp_socket(
            binding,
            timeout=LAN_PORT_TIMEOUT_SECONDS,
        ):
            return True
    except _InterfaceBindingError:
        return False


def _new_interface_udp_socket(
    binding: _RouteInterfaceBinding,
    *,
    bind_port: int = 0,
    multicast_group: str | None = None,
    reuse: bool = False,
) -> socket.socket:
    """Create a UDP socket whose sends and receives can prove one ifindex.

    mDNS multicast is bound to the group address because a wildcard receive
    bind would be too broad by itself.  IP_PKTINFO is still mandatory and each
    received datagram is checked below, so another interface that happens to
    use the same CIDR cannot contribute evidence.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        _bind_socket_to_interface(sock, binding)
        if not callable(getattr(sock, "sendmsg", None)) or not callable(
            getattr(sock, "recvmsg", None)
        ):
            raise OSError("interface packet metadata is unavailable")
        if reuse:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
        sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
        if multicast_group:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(binding.ipv4),
            )
            sock.bind((multicast_group, bind_port))
            membership = socket.inet_aton(multicast_group) + socket.inet_aton(
                binding.ipv4
            )
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                membership,
            )
        else:
            # An exact local address prevents the kernel from selecting a
            # different private interface as the receive endpoint.
            sock.bind((binding.ipv4, bind_port))
        return sock
    except (OSError, ValueError):
        sock.close()
        raise


def _send_udp_on_interface(
    sock: socket.socket,
    payload: bytes,
    destination: tuple[str, int],
    binding: _RouteInterfaceBinding,
) -> None:
    """Send one datagram with an explicit Linux in_pktinfo ifindex/source."""
    packet_info = struct.pack(
        "=I4s4s",
        binding.ifindex,
        socket.inet_aton(binding.ipv4),
        b"\x00" * 4,
    )
    sock.sendmsg(
        [payload],
        [(socket.IPPROTO_IP, IP_PKTINFO, packet_info)],
        0,
        destination,
    )


def _recv_udp_on_interface(
    sock: socket.socket,
    max_bytes: int,
    binding: _RouteInterfaceBinding,
) -> tuple[bytes, tuple[Any, ...]] | None:
    """Receive only datagrams carrying the selected route interface ifindex."""
    payload, ancillary, flags, address = sock.recvmsg(max_bytes, 128)
    if flags & getattr(socket, "MSG_CTRUNC", 0):
        return None
    for level, message_type, data in ancillary:
        if (
            level == socket.IPPROTO_IP
            and message_type == IP_PKTINFO
            and len(data) >= 12
        ):
            received_ifindex = struct.unpack("=I", data[:4])[0]
            if received_ifindex == binding.ifindex:
                return payload, address
            return None
    return None


def _coerce_discovery_pass(
    value: Any,
) -> tuple[dict[str, list[str]], bool]:
    """Normalize a discovery pass and retain compatibility with test doubles."""
    complete = True
    evidence: Any = value
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[1], bool)
    ):
        evidence, complete = value
    return (
        dict(evidence) if isinstance(evidence, Mapping) else {},
        complete,
    )


def _coerce_tcp_discovery_pass(
    value: Any,
) -> tuple[dict[str, list[int]], set[str], bool]:
    """Normalize TCP output while preserving negative replies as telemetry.

    Older deterministic tests and rollout doubles return ``(ports, complete)``.
    Treat their open-port keys as responsive for compatibility. Production
    returns ``(ports, responsive_hosts, complete)`` so transport completion can
    still be diagnosed.  The responsive set is not independent device-presence
    evidence: routers and access points can proxy a reset for unused addresses.
    """
    if isinstance(value, tuple) and len(value) == 3 and isinstance(value[2], bool):
        raw_ports, raw_responsive, complete = value
        ports = dict(raw_ports) if isinstance(raw_ports, Mapping) else {}
        responsive = {
            str(host)
            for host in (raw_responsive or [])
            if str(host).strip()
        }
        return ports, responsive, complete
    ports, complete = _coerce_discovery_pass(value)
    return ports, set(ports), complete


def _local_neighbor_entries(interface: str | None) -> dict[str, str]:
    """Read the Pi's current ARP table as private evidence.

    Android often cannot read its own neighbour table.  The API host can, and
    an ARP entry is a real LAN observation even when every TCP port is closed.
    Only complete rows belonging to the request's current routing interface
    are returned.  Freshness is decided by the caller using pre/post snapshots;
    the MAC never leaves the private repository/presentation boundary.
    """
    entries: dict[str, str] = {}
    conflicted_hosts: set[str] = set()
    if not interface:
        return entries
    try:
        lines = Path(PROC_NET_ARP_PATH).read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines()[1:]
    except OSError:
        return entries
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        host, raw_flags, mac, device = parts[0], parts[2], parts[3], parts[5]
        if device != interface:
            continue
        try:
            parsed = ipaddress.ip_address(host)
            flags = int(raw_flags, 0)
        except ValueError:
            continue
        if parsed.version != 4 or not parsed.is_private:
            continue
        if not flags & 0x2 or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
            continue
        if mac.upper() in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            continue
        canonical_host = str(parsed)
        canonical_mac = mac.upper()
        if canonical_host in conflicted_hosts:
            continue
        previous = entries.get(canonical_host)
        if previous is not None and previous != canonical_mac:
            # Two complete rows assigning different MACs to one IPv4 address
            # are ambiguous.  Drop the address rather than letting file order
            # decide which physical endpoint receives an identity proof.
            entries.pop(canonical_host, None)
            conflicted_hosts.add(canonical_host)
            continue
        entries[canonical_host] = canonical_mac
    return entries


def _safe_mdns_text(value: Any) -> str:
    """Bound mDNS labels/TXT values before they become private evidence."""
    text = " ".join(str(value or "").split())
    if not text or any(ord(char) < 32 for char in text):
        return ""
    return text[:160]


def _encode_dns_name(name: str) -> bytes:
    labels = [label for label in str(name).strip(".").split(".") if label]
    encoded = bytearray()
    for label in labels:
        raw = label.encode("utf-8", errors="ignore")[:63]
        if raw:
            encoded.extend((len(raw),))
            encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _build_mdns_query(name: str, *, unicast_response: bool = False) -> bytes:
    # A zero transaction ID is valid for multicast DNS and lets us issue all
    # bounded queries without keeping request state.  We only trust the
    # response source IP and the device's own advertisement fields.
    question_class = 0x8001 if unicast_response else 1
    return struct.pack("!6H", 0, 0, 1, 0, 0, 0) + _encode_dns_name(name) + struct.pack("!2H", 12, question_class)


def _read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read one DNS name, including compression pointers, with hard bounds."""
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    jumps = 0
    while 0 <= cursor < len(data) and jumps < 12:
        length = data[cursor]
        if length == 0:
            return ".".join(labels), next_offset if next_offset is not None else cursor + 1
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                return "", len(data)
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data):
                return "", len(data)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            jumps += 1
            continue
        if length > 63 or cursor + 1 + length > len(data):
            return "", len(data)
        label = data[cursor + 1 : cursor + 1 + length].decode("utf-8", errors="ignore")
        if label:
            labels.append(label[:80])
        cursor += 1 + length
    return "", len(data)


def _parse_mdns_packet(
    data: bytes,
    *,
    source_host: str | None = None,
) -> dict[str, list[str]]:
    """Attribute one mDNS packet's evidence to its advertised endpoints.

    A multicast response can contain records for several devices.  The UDP
    source therefore is not an identity boundary.  Follow the DNS-SD graph
    from PTR service -> SRV instance/target -> target A/AAAA records and keep
    each instance's TXT and port only on the endpoint(s) reached through that
    instance.  The UDP source is used only for the common compact-response
    case where the whole packet names exactly one SRV target but omits its
    address record.
    """
    if len(data) < 12:
        return {}
    try:
        _transaction, _flags, question_count, answer_count, authority_count, additional_count = struct.unpack(
            "!6H", data[:12]
        )
    except struct.error:
        return {}
    offset = 12
    for _ in range(question_count):
        _name, offset = _read_dns_name(data, offset)
        if offset + 4 > len(data):
            return {}
        offset += 4

    # DNS names are case-insensitive.  Preserve the first safe spelling for
    # evidence while all graph joins use the normalized key.
    original_names: dict[str, str] = {}
    ptr_instances: dict[str, list[str]] = defaultdict(list)
    srv_records: dict[str, list[tuple[str, int]]] = defaultdict(list)
    txt_records: dict[str, list[str]] = defaultdict(list)
    address_records: dict[str, list[str]] = defaultdict(list)

    def name_key(value: str) -> str:
        safe = _safe_mdns_text(value).strip(".")
        if not safe:
            return ""
        key = safe.casefold()
        original_names.setdefault(key, safe)
        return key

    for _ in range(answer_count + authority_count + additional_count):
        name, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        record_type, _record_class, _ttl, record_length = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        end = offset + record_length
        if end > len(data):
            break
        owner_key = name_key(name)
        if record_type == 12:  # PTR: service type and instance name
            target, _ = _read_dns_name(data, offset)
            target_key = name_key(target)
            if owner_key and target_key and target_key not in ptr_instances[owner_key]:
                ptr_instances[owner_key].append(target_key)
        elif record_type == 33 and record_length >= 6:  # SRV
            port = struct.unpack("!H", data[offset + 4 : offset + 6])[0]
            target, _ = _read_dns_name(data, offset + 6)
            target_key = name_key(target)
            if owner_key and target_key and 1 <= port <= 65535:
                record = (target_key, port)
                if record not in srv_records[owner_key]:
                    srv_records[owner_key].append(record)
        elif record_type == 16:  # TXT
            cursor = offset
            while cursor < end:
                length = data[cursor]
                cursor += 1
                if cursor + length > end:
                    break
                value = _safe_mdns_text(data[cursor : cursor + length].decode("utf-8", errors="ignore"))
                if owner_key and value and value not in txt_records[owner_key]:
                    txt_records[owner_key].append(value)
                cursor += length
        elif record_type == 1 and record_length == 4:  # A
            try:
                address = str(ipaddress.IPv4Address(data[offset:end]))
            except ipaddress.AddressValueError:
                address = ""
            if owner_key and address and address not in address_records[owner_key]:
                address_records[owner_key].append(address)
        elif record_type == 28 and record_length == 16:  # AAAA
            try:
                address = str(ipaddress.IPv6Address(data[offset:end]))
            except ipaddress.AddressValueError:
                address = ""
            if owner_key and address and address not in address_records[owner_key]:
                address_records[owner_key].append(address)
        offset = end

    services_by_instance: dict[str, list[str]] = defaultdict(list)
    for service_key, instance_keys in ptr_instances.items():
        for instance_key in instance_keys:
            if service_key not in services_by_instance[instance_key]:
                services_by_instance[instance_key].append(service_key)

    distinct_targets = {
        target_key
        for records in srv_records.values()
        for target_key, _port in records
    }
    fallback_host = ""
    if len(distinct_targets) == 1 and source_host is not None:
        try:
            fallback_host = str(ipaddress.ip_address(str(source_host).strip()))
        except ValueError:
            fallback_host = ""

    attributed: dict[str, list[str]] = {}
    for instance_key, records in srv_records.items():
        base_evidence: list[str] = []
        for service_key in services_by_instance.get(instance_key, []):
            service_name = original_names.get(service_key, "")
            if service_name.startswith("_"):
                base_evidence.append(f"mdns-type:{service_name}")
        instance_name = original_names.get(instance_key, "")
        if instance_name:
            base_evidence.append(f"mdns-name:{instance_name}")
        instance_txt_evidence = [
            f"mdns-txt:{value}" for value in txt_records.get(instance_key, [])
        ]

        for target_key, port in records:
            endpoint_hosts = list(address_records.get(target_key, []))
            if not endpoint_hosts and fallback_host:
                endpoint_hosts = [fallback_host]
            for endpoint_host in endpoint_hosts:
                endpoint_evidence = [
                    *base_evidence,
                    f"mdns-host:{endpoint_host}",
                    f"mdns-port:{port}",
                    *instance_txt_evidence,
                ]
                attributed[endpoint_host] = _merge_unique(
                    attributed.get(endpoint_host), endpoint_evidence
                )[:48]

    return attributed


def _discover_mdns(
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[str]], bool]:
    """Collect bounded mDNS evidence from the Pi LAN.

    Android's NSD/multicast path can be blocked by Wi-Fi isolation.  The Pi is
    already on the household LAN, so a second raw mDNS listener recovers the
    same product advertisements without converting a protocol name or port
    into a product label.  Failure is deliberately non-fatal.
    """
    result: dict[str, list[str]] = defaultdict(list)
    complete = True
    try:
        with _new_interface_udp_socket(
            binding,
            bind_port=MDNS_PORT,
            multicast_group=MDNS_GROUP,
            reuse=True,
        ) as sock:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            except OSError:
                return {}, False
            for query_name in MDNS_QUERY_TYPES:
                try:
                    _send_udp_on_interface(
                        sock,
                        _build_mdns_query(query_name),
                        (MDNS_GROUP, MDNS_PORT),
                        binding,
                    )
                except OSError:
                    complete = False
                    continue
            deadline = time.monotonic() + MDNS_LISTEN_SECONDS
            while time.monotonic() < deadline:
                wait = min(0.25, max(0.01, deadline - time.monotonic()))
                try:
                    readable, _writable, _errors = select.select([sock], [], [], wait)
                except (OSError, ValueError):
                    complete = False
                    break
                if not readable:
                    continue
                try:
                    received = _recv_udp_on_interface(sock, 9_000, binding)
                    if received is None:
                        continue
                    payload, address = received
                    host = str(address[0])
                    parsed_host = ipaddress.ip_address(host)
                except (OSError, ValueError):
                    complete = False
                    continue
                if parsed_host.version != 4 or not parsed_host.is_private:
                    continue
                for endpoint_host, evidence in _parse_mdns_packet(
                    payload, source_host=host
                ).items():
                    result[endpoint_host] = _merge_unique(
                        result.get(endpoint_host), evidence
                    )
    except OSError:
        return {}, False
    return {host: values for host, values in result.items() if values}, complete


def _discover_mdns_unicast(
    hosts: Sequence[str],
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[str]], bool]:
    """Ask likely hosts directly when multicast is filtered by the AP.

    This is a bounded supplement to the multicast listener, not a way to
    manufacture identity.  Only private target hosts from the active scan
    subnet are queried, and only the device's own mDNS response fields are
    retained as private evidence.
    """
    targets: list[str] = []
    for raw_host in list(hosts)[:PROBE_MAX_HOSTS]:
        try:
            parsed = ipaddress.ip_address(str(raw_host))
        except ValueError:
            continue
        if parsed.version == 4 and parsed.is_private:
            targets.append(str(parsed))

    def probe(host: str) -> tuple[dict[str, list[str]], bool]:
        attributed: dict[str, list[str]] = {}
        complete = True
        try:
            with _new_interface_udp_socket(binding) as sock:
                sock.settimeout(MDNS_UNICAST_TIMEOUT_SECONDS)
                for query_name in MDNS_UNICAST_QUERY_TYPES:
                    try:
                        _send_udp_on_interface(
                            sock,
                            _build_mdns_query(query_name, unicast_response=True),
                            (host, MDNS_PORT),
                            binding,
                        )
                    except OSError:
                        complete = False
                deadline = time.monotonic() + MDNS_UNICAST_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    try:
                        received = _recv_udp_on_interface(sock, 9_000, binding)
                    except socket.timeout:
                        break
                    except OSError:
                        complete = False
                        break
                    if received is None:
                        continue
                    payload, address = received
                    if str(address[0]) != host:
                        continue
                    for endpoint_host, evidence in _parse_mdns_packet(
                        payload, source_host=host
                    ).items():
                        attributed[endpoint_host] = _merge_unique(
                            attributed.get(endpoint_host), evidence
                        )[:48]
        except OSError:
            return {}, False
        return attributed, complete

    result: dict[str, list[str]] = {}
    complete = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=MDNS_UNICAST_WORKERS) as executor:
        for attributed, host_complete in executor.map(probe, targets):
            complete = complete and host_complete
            for endpoint_host, evidence in attributed.items():
                result[endpoint_host] = _merge_unique(
                    result.get(endpoint_host), evidence
                )[:48]
    return result, complete


def _dhcp_lease_entries() -> dict[str, dict[str, str]]:
    """Read unexpired leases as conditional private hostname evidence.

    A lease is not presence proof and its MAC is never a replacement for the
    current-interface ARP result.  The caller may use the hostname only after
    the host is proven current and both MAC values match.
    """
    entries: dict[str, dict[str, str]] = {}
    expiry_by_host: dict[str, int] = {}
    now = int(time.time())
    for raw_path in DHCP_LEASE_PATHS:
        path = Path(raw_path)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            raw_expiry, mac, host, hostname = parts[:4]
            try:
                expiry = int(raw_expiry, 10)
            except ValueError:
                continue
            # dnsmasq uses zero for an infinite/static lease.  Any positive
            # timestamp at or before now is expired and cannot describe the
            # current occupant of a reused address.
            if expiry < 0 or (expiry > 0 and expiry <= now):
                continue
            try:
                parsed = ipaddress.ip_address(host)
            except ValueError:
                continue
            if parsed.version != 4 or not parsed.is_private:
                continue
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac):
                continue
            if mac.upper() in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
                continue
            safe_hostname = _safe_mdns_text(hostname)
            if safe_hostname in {"", "*", "-"}:
                safe_hostname = ""
            canonical = str(parsed)
            expiry_rank = (1 << 63) - 1 if expiry == 0 else expiry
            if canonical in expiry_by_host and expiry_rank <= expiry_by_host[canonical]:
                continue
            expiry_by_host[canonical] = expiry_rank
            entry = {"mac": mac.upper(), "hostname": ""}
            if safe_hostname:
                entry["hostname"] = safe_hostname
            entries[canonical] = entry
    return entries


_TCP_OPEN = "open"
_TCP_REFUSED = "refused"
_TCP_NO_RESPONSE = "no-response"


def _probe_tcp_observation(
    host: str,
    port: int,
    binding: _RouteInterfaceBinding,
) -> tuple[str, bool]:
    try:
        with _new_interface_tcp_connection(
            host,
            port,
            binding,
            timeout=LAN_PORT_TIMEOUT_SECONDS,
        ):
            return _TCP_OPEN, True
    except _InterfaceBindingError:
        return _TCP_NO_RESPONSE, False
    except OSError as exc:
        complete = _tcp_os_error_is_expected_peer_negative(exc)
        refused = isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED
        return (_TCP_REFUSED if refused else _TCP_NO_RESPONSE), complete


def _probe_tcp(
    host: str,
    port: int,
    binding: _RouteInterfaceBinding,
) -> tuple[bool, bool]:
    """Compatibility projection used by focused transport tests."""
    state, complete = _probe_tcp_observation(host, port, binding)
    return state == _TCP_OPEN, complete


def _scan_tcp_ports(
    hosts: Sequence[str],
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[int]], set[str], bool]:
    """Probe all bounded host/port pairs concurrently.

    The previous server path only checked the Family Hub endpoint.  That
    missed routers, PCs, printers, and IoT devices that were already reachable
    on ordinary services.  Pair-level concurrency keeps this bounded pass
    below the mobile scan's several-minute worst case without guessing names.
    """
    pairs = [(host, port) for host in hosts for port in LAN_DISCOVERY_PORTS]
    found: dict[str, list[int]] = defaultdict(list)
    responsive_hosts: set[str] = set()
    complete = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=LAN_PORT_WORKERS) as executor:
        outcomes = executor.map(
            lambda item: _probe_tcp_observation(item[0], item[1], binding),
            pairs,
        )
        for (host, port), (state, probe_complete) in zip(pairs, outcomes):
            complete = complete and probe_complete
            if state in {_TCP_OPEN, _TCP_REFUSED}:
                responsive_hosts.add(host)
            if state == _TCP_OPEN:
                found[host].append(port)
    return (
        {host: sorted(ports) for host, ports in found.items()},
        responsive_hosts,
        complete,
    )


def _parse_http_response(response: bytes) -> tuple[dict[str, str], str] | None:
    text = response.decode("utf-8", errors="ignore")
    separator = "\r\n\r\n"
    header_end = text.find(separator)
    if header_end < 0:
        separator = "\n\n"
        header_end = text.find(separator)
    if header_end < 0 or not text.startswith("HTTP/"):
        return None
    status_line = text.splitlines()[0] if text.splitlines() else ""
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].startswith("2"):
        return None
    headers: dict[str, str] = {}
    for line in text[:header_end].splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip() and value.strip():
            headers[key.strip().lower()] = value.strip()[:240]
    return headers, text[header_end + len(separator) : HTTP_EVIDENCE_BYTES]


def _http_identity_field(key: object) -> str | None:
    """Map a JSON/XML field name to one bounded identity field.

    This deliberately ignores arbitrary keys such as ``version`` or
    ``description``.  A model is accepted only when the endpoint labels it as
    a model/product field, so a web-server version can never become a product
    number by accident.
    """
    normalized = re.sub(r"[^a-z0-9]", "", str(key or "").casefold())
    for field, aliases in _HTTP_IDENTITY_KEY_ALIASES.items():
        if normalized in aliases:
            return field
    return None


def _structured_http_fingerprints(
    body: str,
    headers: Mapping[str, str] | None = None,
) -> list[str]:
    """Extract manufacturer/model fields from a device-owned HTTP payload.

    Embedded products expose these values in several shapes: a small JSON
    object, a nested JSON status response, or a UPnP-like XML document served
    outside SSDP.  This parser keeps only a short allowlist of field names and
    stores the result as private fingerprints.  It never treats a hostname,
    IP address, port, HTTP ``Server`` banner, or arbitrary page text as a
    model.
    """
    values: dict[str, list[str]] = {field: [] for field in _HTTP_IDENTITY_KEY_ALIASES}

    def add(field: str | None, raw: object) -> None:
        if field is None:
            return
        value = _safe_response_text(raw)
        if not value or len(value) > 160 or value in values[field]:
            return
        values[field].append(value)

    for raw_key, raw_value in (headers or {}).items():
        key = re.sub(r"[^a-z0-9]", "", str(raw_key).casefold())
        header_aliases = {
            "xdevicemanufacturer": "manufacturer",
            "xmanufacturer": "manufacturer",
            "xdevicemodel": "model",
            "xmodel": "model",
            "xproductname": "product",
            "xdevicetype": "device_type",
            "xfriendlyname": "name",
        }
        add(header_aliases.get(key), raw_value)

    def walk_json(value: object, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, Mapping):
            for key, item in value.items():
                field = _http_identity_field(key)
                if isinstance(item, (str, int, float)) and not isinstance(item, bool):
                    add(field, item)
                elif isinstance(item, (Mapping, list)):
                    walk_json(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:32]:
                if isinstance(item, (Mapping, list)):
                    walk_json(item, depth + 1)

    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            walk_json(json.loads(stripped[:HTTP_EVIDENCE_BYTES]))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    # The same fields are common in XML device descriptions.  _xml_text is a
    # bounded tag reader and safely ignores malformed/HTML responses.
    xml_tags = {
        "manufacturer": ("manufacturer", "manufacturerName", "vendor", "brand"),
        "model": ("model", "modelName", "modelNumber", "modelId", "deviceModel"),
        "product": ("product", "productName", "productId", "deviceProduct"),
        "device_type": ("deviceType", "category", "productType"),
        "name": ("friendlyName", "displayName", "deviceName", "name"),
    }
    if "<" in body:
        for field, tags in xml_tags.items():
            for tag in tags:
                add(field, _xml_text(body, tag))

    evidence: list[str] = []
    for field in ("manufacturer", "model", "product", "device_type", "name"):
        prefix = _HTTP_IDENTITY_FIELD_PREFIXES[field]
        for value in values[field][:4]:
            item = f"{prefix}:{value}"
            if item not in evidence:
                evidence.append(item)
    return evidence[:16]


def _http_evidence(
    host: str,
    port: int,
    binding: _RouteInterfaceBinding,
) -> tuple[list[str], bool]:
    if port not in HTTP_EVIDENCE_PORTS:
        return [], True
    try:
        with _new_interface_tcp_connection(
            host,
            port,
            binding,
            timeout=0.45,
        ) as conn:
            conn.settimeout(0.8)
            conn.sendall(
                f"GET / HTTP/1.0\r\nHost: {host}\r\nAccept: text/html, */*\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            chunks: list[bytes] = []
            size = 0
            while size < HTTP_EVIDENCE_BYTES:
                block = conn.recv(min(2048, HTTP_EVIDENCE_BYTES - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
        parsed = _parse_http_response(b"".join(chunks))
    except _InterfaceBindingError:
        return [], False
    except OSError as exc:
        return [], _tcp_os_error_is_expected_peer_negative(exc)
    if parsed is None:
        return [], True
    headers, body = parsed
    evidence: list[str] = []
    if headers.get("server"):
        evidence.append(f"http-server:{headers['server']}")
    evidence.extend(_structured_http_fingerprints(body, headers))
    title = re.search(r"<title[^>]*>\s*([^<]{1,120})\s*</title>", body, re.IGNORECASE)
    if title:
        evidence.append(f"http-title:{' '.join(title.group(1).split())[:120]}")
    # Only promote strict, catalog-shaped model tokens. Arbitrary page text
    # remains private HTTP evidence and cannot become a product label.
    for match in _MODEL_TOKEN_RE.finditer(body[:6000]):
        token = match.group(0).strip(" .,:;()[]{}")[:80]
        if token and f"http-model:{token}" not in evidence:
            evidence.append(f"http-model:{token}")
    return evidence[:12], True


def _xml_text(body: str, tag: str) -> str:
    """Read one short UPnP description field as private evidence."""
    match = re.search(
        rf"<(?:(?:[A-Za-z][A-Za-z0-9_-]*):)?{re.escape(tag)}(?:\s[^>]*)?>"
        rf"\s*([^<]{{1,160}})\s*</(?:(?:[A-Za-z][A-Za-z0-9_-]*):)?{re.escape(tag)}\s*>",
        body,
        flags=re.IGNORECASE,
    )
    return _safe_response_text(match.group(1)) if match else ""


def _upnp_evidence(
    host: str,
    location: str,
    binding: _RouteInterfaceBinding,
) -> tuple[list[str], bool]:
    """Fetch a device's own UPnP description, without trusting its label.

    SSDP only gives us a location.  The description is useful for Samsung hubs,
    Sonos, TVs and set-top boxes, but arbitrary friendly names must remain
    private evidence until the catalog/identity resolver verifies them.
    """
    try:
        parsed = urlsplit(str(location).strip())
        if parsed.scheme.lower() != "http" or parsed.hostname != host:
            return [], True
        port = parsed.port or 80
        if not 1 <= port <= 65535:
            return [], True
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query[:240]
        with _new_interface_tcp_connection(
            host,
            port,
            binding,
            timeout=0.45,
        ) as conn:
            conn.settimeout(0.9)
            conn.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/xml,text/xml,*/*\r\n"
                "Connection: close\r\n\r\n".encode("ascii", errors="ignore")
            )
            chunks: list[bytes] = []
            size = 0
            while size < UPNP_EVIDENCE_BYTES:
                block = conn.recv(min(2048, UPNP_EVIDENCE_BYTES - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
        parsed_response = _parse_http_response(b"".join(chunks))
        if parsed_response is None:
            return [], True
        _headers, body = parsed_response
    except _InterfaceBindingError:
        return [], False
    except OSError as exc:
        return [], _tcp_os_error_is_expected_peer_negative(exc)
    except ValueError:
        return [], True
    evidence: list[str] = []
    for tag, prefix in (
        ("UDN", "upnp-udn"),
        ("manufacturer", "upnp-manufacturer"),
        ("modelName", "upnp-model"),
        ("modelNumber", "upnp-model"),
        ("friendlyName", "upnp-name"),
        ("deviceType", "upnp-type"),
    ):
        value = _xml_text(body, tag)
        if value:
            item = f"{prefix}:{value}"
            if item not in evidence:
                evidence.append(item)
    return evidence[:10], True


def _netbios_name(
    host: str,
    binding: _RouteInterfaceBinding,
) -> tuple[str | None, bool]:
    """Best-effort NetBIOS node-status name for SMB hosts."""
    request = bytes.fromhex("133700000001000000000000") + bytes.fromhex(
        "20434b414141414141414141414141414141414141414141414141414141414141410000210001"
    )
    try:
        with _new_interface_udp_socket(binding) as sock:
            sock.settimeout(0.55)
            _send_udp_on_interface(sock, request, (host, 137), binding)
            received = _recv_udp_on_interface(sock, 2048, binding)
            if received is None:
                return None, True
            payload, address = received
            if str(address[0]) != host:
                return None, True
    except socket.timeout:
        return None, True
    except OSError:
        return None, False
    # NBSTAT names are fixed 15-byte ASCII entries followed by a suffix byte.
    # Restrict to readable workstation/server names and reject workgroup noise.
    for match in re.finditer(rb"([A-Za-z0-9][A-Za-z0-9 _.-]{2,14})\x00", payload):
        value = match.group(1).decode("ascii", errors="ignore").strip()
        if value and value.upper() not in {"WORKGROUP", "__MSBROWSE__", "IS"}:
            return value[:80], True
    return None, True


def _discover_ssdp(
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[str]], bool]:
    """Collect one bounded SSDP response window on the server LAN."""
    request = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    ).encode("ascii")
    result: dict[str, list[str]] = defaultdict(list)
    complete = True
    try:
        with _new_interface_udp_socket(binding) as sock:
            sock.settimeout(0.35)
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(binding.ipv4),
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                _send_udp_on_interface(
                    sock,
                    request,
                    ("239.255.255.250", 1900),
                    binding,
                )
            except OSError:
                return {}, False
            deadline = time.monotonic() + 1.8
            while time.monotonic() < deadline:
                try:
                    received = _recv_udp_on_interface(sock, 4096, binding)
                except socket.timeout:
                    continue
                except OSError:
                    complete = False
                    break
                if received is None:
                    continue
                payload, address = received
                host = str(address[0])
                try:
                    if not ipaddress.ip_address(host).is_private:
                        continue
                except ValueError:
                    continue
                if host not in result and len(result) >= PROBE_MAX_HOSTS:
                    continue
                result[host] = _merge_unique(
                    result.get(host),
                    _parse_ssdp_response(payload, source_host=host),
                )[:24]
    except OSError:
        return {}, False
    return (
        {host: list(dict.fromkeys(values)) for host, values in result.items()},
        complete,
    )


def _safe_ssdp_location(source_host: str, value: str) -> str | None:
    """Keep an SSDP location only when it points back to its responder.

    SSDP devices occasionally advertise a hostname, a stale address, or a
    location on another interface.  Passing that URL through would make the
    final subnet boundary quarantine an otherwise valid observation and could
    send the UPnP follow-up request to the wrong host.  The responder's
    source address is the only endpoint authority accepted here; product
    identity still comes from the fetched structured UPnP fields.
    """
    try:
        source = ipaddress.ip_address(str(source_host).strip())
        parsed = urlsplit(str(value).strip())
        hostname = parsed.hostname
        if (
            source.version != 4
            or parsed.scheme.lower() not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or not hostname
        ):
            return None
        advertised = ipaddress.ip_address(hostname)
    except (ValueError, TypeError):
        return None
    return str(value).strip() if advertised == source else None


def _parse_ssdp_response(
    payload: bytes,
    *,
    source_host: str | None = None,
) -> list[str]:
    """Parse one SSDP response into bounded private evidence fields."""
    text = payload.decode("utf-8", errors="ignore")
    headers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep and value.strip():
            headers[key.strip().lower()] = value.strip()[:240]
    evidence: list[str] = []
    for key in ("server", "st", "usn"):
        if headers.get(key):
            evidence.append(f"ssdp-{key}:{headers[key]}")
    location = headers.get("location")
    if location:
        safe_location = (
            _safe_ssdp_location(source_host, location)
            if source_host is not None
            else location
        )
        if safe_location:
            evidence.append(f"ssdp-location:{safe_location}")
    return evidence


def _discover_ssdp_unicast(
    hosts: Sequence[str],
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[str]], bool]:
    """Ask each private host directly when multicast SSDP is filtered.

    A number of consumer routers and appliances answer M-SEARCH only on the
    receiving interface.  Directing the same bounded query to each candidate
    host recovers those responses without turning an open port or a hostname
    into a product identity.  Responses are accepted only from the target
    address and are kept as private evidence for the resolver.
    """
    targets: list[str] = []
    for raw_host in list(hosts)[:PROBE_MAX_HOSTS]:
        try:
            parsed = ipaddress.ip_address(str(raw_host))
        except ValueError:
            continue
        if parsed.version == 4 and parsed.is_private:
            targets.append(str(parsed))

    search_targets = (
        "ssdp:all",
        "upnp:rootdevice",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:Basic:1",
    )

    def probe(host: str) -> tuple[str, list[str], bool]:
        evidence: list[str] = []
        complete = True
        request_template = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: {host}:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: {target}\r\n\r\n"
        )
        try:
            with _new_interface_udp_socket(binding) as sock:
                sock.settimeout(SSDP_UNICAST_TIMEOUT_SECONDS)
                for target in search_targets:
                    try:
                        _send_udp_on_interface(
                            sock,
                            request_template.format(
                                host=host, target=target
                            ).encode("ascii"),
                            (host, 1900),
                            binding,
                        )
                    except OSError:
                        complete = False
                deadline = time.monotonic() + SSDP_UNICAST_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    try:
                        received = _recv_udp_on_interface(sock, 8_192, binding)
                    except socket.timeout:
                        break
                    except OSError:
                        complete = False
                        break
                    if received is None:
                        continue
                    payload, address = received
                    if str(address[0]) != host:
                        continue
                    evidence = _merge_unique(
                        evidence,
                        _parse_ssdp_response(payload, source_host=host),
                    )
        except OSError:
            return host, [], False
        return host, evidence[:24], complete

    result: dict[str, list[str]] = {}
    complete = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=SSDP_UNICAST_WORKERS) as executor:
        for host, evidence, host_complete in executor.map(probe, targets):
            complete = complete and host_complete
            if evidence:
                result[host] = evidence
    return result, complete


def _parse_onvif_probe_match(payload: bytes) -> list[str]:
    """Keep bounded WS-Discovery evidence from an ONVIF ProbeMatch."""
    text = payload[:12_288].decode("utf-8", errors="ignore")
    lowered = text.lower()
    if "probematch" not in lowered or not (
        "onvif" in lowered or "networkvideotransmitter" in lowered
    ):
        return []
    evidence = ["onvif-ws-discovery"]
    for tag, prefix in (("Scopes", "onvif-scope"), ("Types", "onvif-type")):
        pattern = (
            rf"<(?:(?:[A-Za-z][A-Za-z0-9_-]*):)?{tag}(?:\s[^>]*)?>"
            rf"\s*([^<]{{1,4096}})\s*</(?:(?:[A-Za-z][A-Za-z0-9_-]*):)?{tag}\s*>"
        )
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            for raw_value in match.group(1).split():
                value = _safe_response_text(raw_value)
                item = f"{prefix}:{value}" if value else ""
                if item and item not in evidence:
                    evidence.append(item)
                if len(evidence) >= 24:
                    return evidence
    return evidence


def _discover_onvif(
    binding: _RouteInterfaceBinding,
) -> tuple[dict[str, list[str]], bool]:
    """Collect ONVIF WS-Discovery replies on the selected same-L2 interface."""
    message_id = uuid.uuid4()
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<e:Header>'
        f'<w:MessageID>uuid:{message_id}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe><d:Types>'
        'dn:NetworkVideoTransmitter'
        '</d:Types></d:Probe></e:Body></e:Envelope>'
    ).encode("utf-8")
    result: dict[str, list[str]] = {}
    complete = True
    try:
        with _new_interface_udp_socket(binding) as sock:
            sock.settimeout(0.35)
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(binding.ipv4),
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                _send_udp_on_interface(
                    sock,
                    probe,
                    (WS_DISCOVERY_GROUP, WS_DISCOVERY_PORT),
                    binding,
                )
            except OSError:
                return {}, False
            deadline = time.monotonic() + WS_DISCOVERY_LISTEN_SECONDS
            while time.monotonic() < deadline:
                try:
                    received = _recv_udp_on_interface(sock, 12_288, binding)
                except socket.timeout:
                    continue
                except OSError:
                    complete = False
                    break
                if received is None:
                    continue
                payload, address = received
                host = str(address[0])
                try:
                    parsed = ipaddress.ip_address(host)
                except ValueError:
                    continue
                if parsed.version != 4 or not parsed.is_private:
                    continue
                evidence = _parse_onvif_probe_match(payload)
                if evidence:
                    result[str(parsed)] = _merge_unique(result.get(str(parsed)), evidence)
    except OSError:
        return {}, False
    return result, complete


def _probe_one(
    host: str,
    binding: _RouteInterfaceBinding,
) -> tuple[tuple[str, dict[str, str]] | None, bool]:
    info, complete = _get_info(host, binding)
    return ((host, info) if info else None), complete


def _merge_unique(left: Sequence[Any] | None, right: Sequence[Any] | None) -> list[Any]:
    result: list[Any] = []
    for value in list(left or []) + list(right or []):
        if value not in result:
            result.append(value)
    return result


def _normalized_physical_mac(value: Any) -> str | None:
    """Return a canonical unicast MAC, rejecting scanner placeholders."""
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", compact):
        return None
    if compact in {"000000000000", "020000000000", "FFFFFFFFFFFF"}:
        return None
    if int(compact[:2], 16) & 1:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _normalized_upnp_uuid_root(value: Any) -> str | None:
    """Return the canonical RFC UUID at the root of one USN/UDN value.

    SSDP appends a service suffix after ``::`` while UPnP UDN contains only the
    root.  Arbitrary labels that merely start with ``uuid:`` are not a strong
    cross-observer gateway identifier and therefore fail closed here.
    """
    raw = str(value or "").strip()
    root = raw.split("::", 1)[0].strip()
    if not root.lower().startswith("uuid:"):
        return None
    try:
        parsed = uuid.UUID(root[5:].strip())
    except (ValueError, AttributeError):
        return None
    if parsed.int == 0:
        return None
    return str(parsed)


def _upnp_uuid_roots_from_fingerprints(
    fingerprints: Sequence[Any] | None,
    *,
    require_android_source: bool = False,
    discovery_sources: Sequence[Any] | None = None,
) -> set[str]:
    """Extract strong gateway UUID roots from bounded private evidence."""
    sources = {str(value or "").strip().lower() for value in discovery_sources or []}
    roots: set[str] = set()
    for raw_fingerprint in fingerprints or []:
        fingerprint = str(raw_fingerprint or "").strip()
        prefix, separator, value = fingerprint.partition(":")
        normalized_prefix = prefix.lower()
        if not separator or normalized_prefix not in {"ssdp-usn", "upnp-udn"}:
            continue
        if require_android_source:
            if normalized_prefix == "ssdp-usn" and "ssdp" not in sources:
                continue
            if normalized_prefix == "upnp-udn" and not sources.intersection(
                {"ssdp", "upnp"}
            ):
                continue
        normalized = _normalized_upnp_uuid_root(value)
        if normalized is not None:
            roots.add(normalized)
    return roots


def _android_gateway_uuids(
    discovered_devices: Sequence[Mapping[str, Any]],
    network_context: Mapping[str, Any] | None,
) -> set[str]:
    """Read source-attributed SSDP/UPnP UUIDs from the Android gateway row."""
    if not isinstance(network_context, Mapping):
        return set()
    try:
        gateway = ipaddress.ip_address(
            str(network_context.get("gateway_ip") or "").strip()
        )
    except ValueError:
        return set()
    if gateway.version != 4 or not gateway.is_private:
        return set()

    roots: set[str] = set()
    for device in discovered_devices:
        if not isinstance(device, Mapping):
            continue
        try:
            observed_ip = ipaddress.ip_address(
                str(device.get("ip_address") or "").strip()
            )
        except ValueError:
            continue
        if observed_ip != gateway:
            continue
        raw_fingerprints = device.get("fingerprints")
        raw_sources = device.get("discovery_sources")
        fingerprints = (
            raw_fingerprints
            if isinstance(raw_fingerprints, Sequence)
            and not isinstance(raw_fingerprints, (str, bytes, bytearray))
            else []
        )
        sources = (
            raw_sources
            if isinstance(raw_sources, Sequence)
            and not isinstance(raw_sources, (str, bytes, bytearray))
            else []
        )
        roots.update(
            _upnp_uuid_roots_from_fingerprints(
                fingerprints,
                require_android_source=True,
                discovery_sources=sources,
            )
        )
    return roots


def _android_gateway_mac(
    discovered_devices: Sequence[Mapping[str, Any]],
    network_context: Mapping[str, Any] | None,
) -> str | None:
    """Read one non-conflicting physical gateway MAC from Android evidence."""
    if not isinstance(network_context, Mapping):
        return None
    try:
        gateway = ipaddress.ip_address(
            str(network_context.get("gateway_ip") or "").strip()
        )
    except ValueError:
        return None
    if gateway.version != 4 or not gateway.is_private:
        return None

    values: set[str] = set()
    for device in discovered_devices:
        if not isinstance(device, Mapping):
            continue
        try:
            observed_ip = ipaddress.ip_address(
                str(device.get("ip_address") or "").strip()
            )
        except ValueError:
            continue
        if observed_ip != gateway:
            continue
        mac = _normalized_physical_mac(device.get("mac_address"))
        if mac is not None:
            values.add(mac)
    return next(iter(values)) if len(values) == 1 else None


def _same_current_gateway_uuid(
    android_gateway_uuids: set[str],
    gateway: str,
    binding: _RouteInterfaceBinding,
) -> bool:
    """Reconfirm Android's gateway UUID on the Pi's bound current interface.

    This is deliberately a one-host gate.  Only replies whose UDP source is
    the declared gateway survive ``_discover_ssdp_unicast``.  A UPnP
    description is fetched only from a responder-owned safe location, and no
    non-gateway address is touched until an exact normalized UUID intersects.
    """
    if not android_gateway_uuids:
        return False
    raw_discovery, complete = _coerce_discovery_pass(
        _discover_ssdp_unicast([gateway], binding)
    )
    if not complete:
        return False
    gateway_evidence = _filter_allowed_host_mapping(raw_discovery, {gateway}).get(
        gateway,
        [],
    )
    if not isinstance(gateway_evidence, Sequence) or isinstance(
        gateway_evidence, (str, bytes, bytearray)
    ):
        return False

    current_roots = _upnp_uuid_roots_from_fingerprints(gateway_evidence)
    if android_gateway_uuids.intersection(current_roots):
        return True

    locations: list[str] = []
    for raw_fingerprint in gateway_evidence:
        fingerprint = str(raw_fingerprint or "").strip()
        if not fingerprint.lower().startswith("ssdp-location:"):
            continue
        safe_location = _safe_ssdp_location(
            gateway,
            fingerprint.split(":", 1)[1],
        )
        if safe_location and safe_location not in locations:
            locations.append(safe_location)
    for location in locations[:2]:
        description_evidence, description_complete = _upnp_evidence(
            gateway,
            location,
            binding,
        )
        if not description_complete:
            return False
        current_roots.update(
            _upnp_uuid_roots_from_fingerprints(description_evidence)
        )
        if android_gateway_uuids.intersection(current_roots):
            return True
    return False


def _same_current_gateway_l2(
    discovered_devices: Sequence[Mapping[str, Any]],
    network_context: Mapping[str, Any] | None,
    pre_probe_neighbors: Mapping[str, str],
    post_probe_neighbors: Mapping[str, str],
    active_unicast_hosts: set[str],
) -> bool:
    """Prove Android and Pi observed the same current gateway on one L2."""
    if not isinstance(network_context, Mapping):
        return False
    try:
        gateway = str(
            ipaddress.ip_address(
                str(network_context.get("gateway_ip") or "").strip()
            )
        )
    except ValueError:
        return False

    android_mac = _android_gateway_mac(discovered_devices, network_context)
    pi_mac = _normalized_physical_mac(post_probe_neighbors.get(gateway))
    if not android_mac or not pi_mac or android_mac != pi_mac:
        return False
    # A new/changed neighbor is fresh by itself.  An unchanged cache entry is
    # accepted only if an interface-bound unicast probe reached the gateway
    # during this pass.
    fresh_neighbor = _normalized_physical_mac(
        pre_probe_neighbors.get(gateway)
    ) != pi_mac
    return fresh_neighbor or gateway in active_unicast_hosts


def _attest_current_android_self(
    result: list[dict[str, Any]],
    network_context: Mapping[str, Any] | None,
    *,
    trusted_client_ip: str | None,
    route_interface: str,
    interface_binding: _RouteInterfaceBinding,
    pre_refresh_neighbors: Mapping[str, str],
    claimed_observations: Sequence[Mapping[str, Any]] | None = None,
) -> None:
    """Bind current Android Build evidence to one freshly observed MAC.

    This function is intentionally prospective.  It never consults history,
    an earlier occupant of the IP address, DHCP leases, or a client-provided
    authenticated marker.  The caller invokes it only after the gateway has
    proved that Android and this server are on the same current L2.
    """

    # Preserve client self metadata only as an untrusted claim for this one
    # verifier invocation.  Strip it from the working observations first so
    # every early return leaves the rows as ordinary household endpoints.
    claims = [
        strip_untrusted_authenticated_self_android(observation)
        for observation in (
            claimed_observations if claimed_observations is not None else result
        )
    ]
    result[:] = [strip_untrusted_self_claims(observation) for observation in result]

    scope = _subnet_host_scope(network_context)
    try:
        peer = ipaddress.ip_address(str(trusted_client_ip or "").strip())
        gateway_peer = ipaddress.ip_address(
            str((network_context or {}).get("gateway_ip") or "").strip()
        )
    except ValueError:
        return
    # A local HTTPS request can hairpin through the household gateway before
    # nginx forwards it to this service.  In that topology the trusted proxy
    # address is the *verified gateway*, not Android's local address.  The
    # caller has already proved that Android and this server see the same
    # gateway MAC; accepting that one exact gateway address still requires the
    # declared local IP, an exact neighbour refresh and a unique physical MAC
    # below.  Any other peer remains fail-closed.
    if (
        scope is None
        or not isinstance(peer, ipaddress.IPv4Address)
        or not isinstance(gateway_peer, ipaddress.IPv4Address)
        or gateway_peer not in scope.network
        or gateway_peer in {scope.network.network_address, scope.network.broadcast_address}
        or peer not in {scope.local_ip, gateway_peer}
    ):
        return

    self_indexes: list[int] = []
    for index, observation in enumerate(result):
        try:
            observed_ip = ipaddress.ip_address(
                str(observation.get("ip_address") or "").strip()
            )
        except ValueError:
            continue
        if observed_ip == scope.local_ip:
            self_indexes.append(index)
    if len(self_indexes) != 1:
        return

    index = self_indexes[0]
    if index >= len(claims):
        return
    observation = claims[index]
    try:
        claimed_ip = ipaddress.ip_address(
            str(observation.get("ip_address") or "").strip()
        )
    except ValueError:
        return
    if claimed_ip != scope.local_ip:
        return
    raw_risks = observation.get("risk_signals")
    risks = (
        {
            str(value or "").strip().casefold().replace("_", "-")
            for value in raw_risks
        }
        if isinstance(raw_risks, Sequence)
        and not isinstance(raw_risks, (str, bytes, bytearray))
        else set()
    )
    if risks != {"self-device"} or observation.get("online") is not True:
        return

    refreshed_hosts, refresh_complete = _refresh_exact_neighbor(
        str(scope.local_ip),
        interface_binding,
    )
    canonical_refreshed_hosts: set[str] = set()
    for value in refreshed_hosts:
        try:
            parsed = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if parsed == scope.local_ip:
            canonical_refreshed_hosts.add(str(parsed))
    post_refresh_neighbors = _local_neighbor_entries(route_interface)
    current_mac = _normalized_physical_mac(
        post_refresh_neighbors.get(str(scope.local_ip))
    )
    if (
        not refresh_complete
        or str(scope.local_ip) not in canonical_refreshed_hosts
        or current_mac is None
    ):
        return

    # A client-supplied physical MAC is not authority.  If it is present and
    # conflicts with the exact post-refresh ARP row, however, the observation
    # is ambiguous and must not be silently rebound.
    supplied_mac = _normalized_physical_mac(observation.get("mac_address"))
    if supplied_mac is not None and supplied_mac != current_mac:
        return
    previous_mac = _normalized_physical_mac(
        pre_refresh_neighbors.get(str(scope.local_ip))
    )
    neighbor_is_current = (
        previous_mac != current_mac
        or str(scope.local_ip) in canonical_refreshed_hosts
    )
    if not neighbor_is_current:
        return

    candidate = dict(observation)
    candidate["mac_address"] = current_mac
    bound = bind_authenticated_self_android_claim(candidate)
    if bound is not None:
        result[index] = bound


def augment_android_observations(
    discovered_devices: Sequence[Mapping[str, Any]],
    network_context: Mapping[str, Any] | None,
    *,
    trusted_client_ip: str | None = None,
) -> list[dict[str, Any]]:
    """Merge verified server protocol responses into an Android scan.

    The feature is explicitly opt-in through the production systemd unit so
    local tests and development do not perform a LAN scan.  The returned
    values are still private observations; the existing identity resolver and
    public DevicePresentation boundary decide whether a product is displayable.
    """
    bounded_devices = discovered_devices[:PROBE_MAX_HOSTS]
    # A JSON client can spell reserved evidence tokens, but it cannot mint the
    # in-process proof object consumed by storage.  Strip every serializable
    # imitation before any enablement, L2 or identity decision.
    claimed_observations = [
        strip_untrusted_authenticated_self_android(device)
        for device in bounded_devices
    ]
    result = [strip_untrusted_self_claims(device) for device in bounded_devices]
    if len(discovered_devices) > PROBE_MAX_HOSTS:
        _mark_server_probe_partial(network_context)
    if not _enabled():
        return result

    # A centrally hosted Pi cannot prove that a remote Android client is on
    # the same layer-2 network from a private CIDR alone.  Common home routers
    # reuse ranges such as 192.168.0.0/24, so falling back to the Pi's own
    # gateway neighbour when Android has no gateway MAC can scan the Pi's LAN
    # and attach those observations to an unrelated household.  Treat the Pi
    # pass as optional and skip it before any Pi-side LAN I/O unless Android
    # supplied an independently observed physical gateway MAC or a strong
    # gateway UUID that this Pi can reconfirm from that one gateway only.
    android_gateway_mac = _android_gateway_mac(bounded_devices, network_context)
    android_gateway_uuids = _android_gateway_uuids(
        bounded_devices,
        network_context,
    )
    if android_gateway_mac is None and not android_gateway_uuids:
        _mark_server_probe_l2_unverified(network_context)
        return result

    subnet_scope = _subnet_host_scope(network_context)
    hosts = _probe_hosts(network_context)
    if subnet_scope is None or not hosts:
        # An invalid subnet is not a completed server enrichment pass.  The
        # Android observations remain intact, but the caller must hold the
        # score instead of treating a silently skipped pass as complete.
        _mark_server_probe_partial(network_context)
        return result
    probe_coverage_complete = _probe_coverage_complete(subnet_scope)

    # Every server-side discovery source shares this exact request boundary.
    # A generic private-address check would admit observations from another
    # Raspberry Pi NIC, container bridge or VPN and make the household scan
    # inaccurate.
    allowed_hosts: Container[str] = subnet_scope
    local_ip = str((network_context or {}).get("local_ip") or "").strip()
    route_interface = _routing_interface(network_context)
    interface_binding = _resolve_route_interface_binding(
        route_interface,
        network_context,
    )
    if interface_binding is None or not _preflight_interface_unicast_binding(
        interface_binding
    ):
        # The Pi is commonly hosted on a different LAN from the phone.  Failure
        # to bind a Pi interface therefore says nothing about the completeness
        # of the already-finished native Android scan.
        _mark_server_probe_l2_unverified(network_context)
        return result
    gateway = _canonical_allowed_host(
        (network_context or {}).get("gateway_ip"),
        allowed_hosts,
    )
    if gateway is None:
        _mark_server_probe_l2_unverified(network_context)
        return result

    # The gateway is the L2 trust anchor.  Before touching any other host,
    # refresh this one address on the selected interface and compare its
    # current neighbor MAC with Android's independently observed physical MAC,
    # or reconfirm its source-attributed UUID with a gateway-only request. This
    # prevents even a discarded sweep from reaching a different LAN that
    # happens to reuse the same RFC1918 CIDR.
    raw_gateway_pre_neighbors = _local_neighbor_entries(route_interface)
    gateway_pre_neighbors = _filter_allowed_host_mapping(
        raw_gateway_pre_neighbors,
        allowed_hosts,
    )
    raw_gateway_ping_hosts: set[str] = set()
    gateway_ping_complete = True
    if android_gateway_mac is not None:
        raw_gateway_ping_hosts, gateway_ping_complete = _refresh_gateway_neighbor(
            gateway,
            interface_binding,
        )
    gateway_ping_hosts = {
        canonical
        for host in raw_gateway_ping_hosts
        if (canonical := _canonical_allowed_host(host, allowed_hosts)) is not None
    }
    raw_gateway_post_neighbors = _local_neighbor_entries(route_interface)
    gateway_post_neighbors = _filter_allowed_host_mapping(
        raw_gateway_post_neighbors,
        allowed_hosts,
    )
    gateway_mac_match = (
        android_gateway_mac is not None
        and gateway_ping_complete
        and _same_current_gateway_l2(
            bounded_devices,
            network_context,
            gateway_pre_neighbors,
            gateway_post_neighbors,
            gateway_ping_hosts,
        )
    )
    gateway_uuid_match = (
        _same_current_gateway_uuid(
            android_gateway_uuids,
            gateway,
            interface_binding,
        )
        if android_gateway_uuids
        else False
    )
    gateway_l2_match = gateway_mac_match or gateway_uuid_match

    if not gateway_l2_match:
        # Matching RFC1918 addresses are not proof of the same household.  A
        # A mismatched gateway MAC/UUID means this Pi may belong to another L2
        # network; preserve native coverage and do not start a broader Pi sweep.
        _mark_server_probe_l2_unverified(network_context)
        return result

    _attest_current_android_self(
        result,
        network_context,
        trusted_client_ip=trusted_client_ip,
        route_interface=route_interface,
        interface_binding=interface_binding,
        pre_refresh_neighbors=raw_gateway_post_neighbors,
        claimed_observations=claimed_observations,
    )

    if not probe_coverage_complete:
        # Only after same-L2 proof may a bounded Pi pass affect completeness.
        # A remote Pi that merely lacks a route must never hold a valid native
        # score, while a genuinely co-located but sampled Pi pass remains
        # explicitly partial.
        _mark_server_probe_partial(network_context)

    # Same-L2 proof succeeded.  Only now may the optional full ping sweep,
    # TCP port pass and product-protocol workers touch the requested subnet.
    pre_probe_neighbors = gateway_post_neighbors
    hosts = _prioritized_probe_hosts(
        hosts,
        subnet_scope,
        bounded_devices,
        pre_probe_neighbors,
        gateway,
    )
    raw_ping_hosts, ping_sweep_complete = _refresh_local_neighbors(
        hosts,
        interface_binding,
    )
    ping_hosts = {
        canonical
        for host in raw_ping_hosts
        if (canonical := _canonical_allowed_host(host, allowed_hosts)) is not None
    }
    if not ping_sweep_complete:
        _mark_server_probe_partial(network_context)
    dhcp_entries = _filter_allowed_host_mapping(
        _dhcp_lease_entries(), allowed_hosts
    )
    raw_tcp_ports, raw_tcp_responsive_hosts, tcp_probe_complete = _coerce_tcp_discovery_pass(
        _scan_tcp_ports(hosts, interface_binding)
    )
    tcp_ports = _filter_allowed_host_mapping(raw_tcp_ports, allowed_hosts)
    tcp_responsive_hosts = {
        canonical
        for host in raw_tcp_responsive_hosts
        if (canonical := _canonical_allowed_host(host, allowed_hosts)) is not None
    }
    # A newly learned or changed complete ARP row after the bounded active
    # pass is fresh evidence even when all application ports are closed.
    post_probe_neighbors = _filter_allowed_host_mapping(
        _local_neighbor_entries(route_interface),
        allowed_hosts,
    )
    if not tcp_probe_complete:
        _mark_server_probe_partial(network_context)
        return result
    # A successful NBSTAT reply is fresh protocol evidence.  Recheck cached
    # neighbours that exposed no TCP service before deciding they are stale;
    # cache the result so the presentation merge does not send the query twice.
    netbios_names: dict[str, str] = {}
    unicast_probe_complete = True
    for host in set(pre_probe_neighbors) | set(post_probe_neighbors):
        if {139, 445}.intersection(tcp_ports.get(host, [])):
            continue
        name, complete = _netbios_name(host, interface_binding)
        unicast_probe_complete = unicast_probe_complete and complete
        if name:
            netbios_names[host] = name
    mdns_fingerprints: dict[str, Any] = {}
    ssdp_fingerprints: dict[str, Any] = {}
    onvif_fingerprints: dict[str, Any] = {}
    unicast_mdns_hosts: set[str] = set()
    unicast_ssdp_hosts: set[str] = set()
    interface_discovery_complete = True
    if interface_binding is not None:
        multicast_mdns, multicast_mdns_complete = _coerce_discovery_pass(
            _discover_mdns(interface_binding)
        )
        unicast_mdns, unicast_mdns_complete = _coerce_discovery_pass(
            _discover_mdns_unicast(hosts, interface_binding)
        )
        mdns_fingerprints = _filter_allowed_host_mapping(
            multicast_mdns, allowed_hosts
        )
        filtered_unicast_mdns = _filter_allowed_host_mapping(
            unicast_mdns, allowed_hosts
        )
        unicast_mdns_hosts = {
            host for host, fingerprints in filtered_unicast_mdns.items() if fingerprints
        }
        for host, fingerprints in filtered_unicast_mdns.items():
            mdns_fingerprints[host] = _merge_unique(
                mdns_fingerprints.get(host), fingerprints
            )

        multicast_ssdp, multicast_ssdp_complete = _coerce_discovery_pass(
            _discover_ssdp(interface_binding)
        )
        unicast_ssdp, unicast_ssdp_complete = _coerce_discovery_pass(
            _discover_ssdp_unicast(hosts, interface_binding)
        )
        ssdp_fingerprints = _filter_allowed_host_mapping(
            multicast_ssdp, allowed_hosts
        )
        filtered_unicast_ssdp = _filter_allowed_host_mapping(
            unicast_ssdp, allowed_hosts
        )
        unicast_ssdp_hosts = {
            host for host, fingerprints in filtered_unicast_ssdp.items() if fingerprints
        }
        for host, fingerprints in filtered_unicast_ssdp.items():
            ssdp_fingerprints[host] = _merge_unique(
                ssdp_fingerprints.get(host), fingerprints
            )
        multicast_onvif, multicast_onvif_complete = _coerce_discovery_pass(
            _discover_onvif(interface_binding)
        )
        onvif_fingerprints = _filter_allowed_host_mapping(
            multicast_onvif, allowed_hosts
        )
        interface_discovery_complete = all(
            (
                multicast_mdns_complete,
                unicast_mdns_complete,
                multicast_ssdp_complete,
                unicast_ssdp_complete,
                multicast_onvif_complete,
            )
        )
    if not interface_discovery_complete or not unicast_probe_complete:
        # The existing public DTO exposes only a bounded boolean.  Never leak
        # the interface name/address or pretend that the remaining subset is a
        # complete household scan.
        _mark_server_probe_partial(network_context)

    # The Family Hub/Spotify endpoint is intermittent on sleeping appliances.
    # Probe hosts whose 17654 socket was just observed first, while retaining
    # the all-host fallback for compatibility with an Android observation or
    # a test double that did not expose the server port map.
    probe_hosts = [host for host in hosts if PROBE_PORT in tcp_ports.get(host, [])] or hosts
    found: list[tuple[str, dict[str, str]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as executor:
        for item, complete in executor.map(
            lambda host: _probe_one(host, interface_binding),
            probe_hosts,
        ):
            unicast_probe_complete = unicast_probe_complete and complete
            if item is None:
                continue
            canonical = _canonical_allowed_host(item[0], allowed_hosts)
            if canonical is not None:
                found.append((canonical, item[1]))
    if not unicast_probe_complete:
        _mark_server_probe_partial(network_context)

    by_ip: dict[str, dict[str, Any]] = {
        str(device.get("ip_address") or "").strip(): device
        for device in result
        if str(device.get("ip_address") or "").strip()
    }
    # An mDNS/SSDP multicast packet proves an IP source was present, but its
    # Ethernet destination is the multicast MAC: it does not prove that an
    # unchanged ARP cache MAC belongs to that source.  Only traffic that used
    # the current route's unicast path (or a changed/new ARP row below) may
    # refresh physical identity.
    unicast_active_hosts = (
        ping_hosts
        | set(tcp_ports)
        | unicast_mdns_hosts
        | unicast_ssdp_hosts
        | set(netbios_names)
        | {host for host, _info in found}
    )
    fresh_neighbor_hosts = {
        host
        for host, mac in post_probe_neighbors.items()
        if pre_probe_neighbors.get(host) != mac
    }
    # Android input proves that its own observation exists, but it does not
    # prove that an unchanged Pi ARP cache row belongs to the same occupant.
    # Preserve a verified Android MAC as supplied; only Pi unicast evidence or
    # a newly learned/changed ARP row may enrich it from the server snapshot.
    neighbor_evidence_hosts = unicast_active_hosts | fresh_neighbor_hosts
    neighbors: dict[str, str] = {}
    for host in neighbor_evidence_hosts:
        # Never reuse a MAC that exists only in the pre-scan snapshot.  Even
        # when the IP responds to a protocol probe, that cached MAC could
        # belong to the previous occupant of a reused address.
        mac = post_probe_neighbors.get(host)
        if mac and host != local_ip:
            neighbors[host] = mac

    def ensure_observation(host: str) -> dict[str, Any] | None:
        canonical = _canonical_allowed_host(host, allowed_hosts)
        if canonical is None:
            return None
        host = canonical
        observation = by_ip.get(host)
        if observation is None:
            if len(result) >= PROBE_MAX_HOSTS:
                _mark_server_probe_partial(network_context)
                return None
            observation = {
                "device_id": None,
                "name": "",
                "device_type": "",
                "manufacturer": "",
                "model": "",
                "ip_address": host,
                "mac_address": f"UNKNOWN-{host}",
                "online": True,
                "open_ports": [],
                "services": [],
                "default_credentials": False,
                "encryption": "unknown",
                "firmware": "unknown",
                "vulnerabilities": [],
                "discovery_sources": [],
                "fingerprints": [],
                "risk_signals": [],
                "confidence": 0.65,
            }
            result.append(observation)
            by_ip[host] = observation
        if host in neighbors:
            observation["mac_address"] = neighbors[host]
        return observation

    service_names = {
        21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 139: "smb",
        443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 1400: "sonos-http",
        1443: "sonos-https", 1900: "upnp", 3702: "onvif", 5000: "admin",
        5001: "media-alt", 7000: "media", 7001: "media-alt", 7547: "tr-069",
        7676: "smart-home", 8001: "smart-home", 8002: "smart-home",
        8008: "http-alt", 8009: "androidtv", 8060: "roku",
        8080: "http-alt", 8081: "http-alt", 8443: "https-alt", 8888: "admin-alt",
        8899: "iot-http", 9000: "admin-9000", 9001: "admin-9001", 9100: "printer",
        9761: "lg-smart-device",
        PROBE_PORT: "spotify-connect",
    }
    # Only a newly learned/changed neighbour or a host independently proven
    # active during this scan reaches this loop.  An unchanged pre-scan ARP
    # cache row is identity enrichment at most, never presence evidence.
    for host in neighbors:
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["discovery_sources"] = _merge_unique(observation.get("discovery_sources"), ["server-neighbor"])

    for host, ports in tcp_ports.items():
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["open_ports"] = _merge_unique(observation.get("open_ports"), ports)
        observation["services"] = _merge_unique(
            observation.get("services"), [service_names.get(port, f"tcp-{port}") for port in ports]
        )
        observation["discovery_sources"] = _merge_unique(observation.get("discovery_sources"), ["server-tcp-probe"])
        for port in ports:
            http_fingerprints, complete = _http_evidence(
                host,
                port,
                interface_binding,
            )
            if not complete:
                _mark_server_probe_partial(network_context)
            for fingerprint in http_fingerprints:
                observation["fingerprints"] = _merge_unique(observation.get("fingerprints"), [fingerprint])
        if 139 in ports or 445 in ports:
            name, complete = _netbios_name(host, interface_binding)
            if not complete:
                _mark_server_probe_partial(network_context)
            if name:
                observation["discovery_sources"] = _merge_unique(
                    observation.get("discovery_sources"), ["netbios"]
                )
                observation["fingerprints"] = _merge_unique(
                    observation.get("fingerprints"), [f"netbios-name:{name}"]
                )

    # Some computers and gateways answer the NetBIOS node-status query while
    # keeping every TCP service closed.  Query ARP-observed hosts without SMB
    # ports as a bounded hostname-only fallback; a hostname remains private
    # evidence and is never itself treated as a product model.
    for host in neighbors:
        if {139, 445}.intersection(tcp_ports.get(host, [])):
            continue
        name = netbios_names.get(host)
        if not name:
            name, complete = _netbios_name(host, interface_binding)
            if not complete:
                _mark_server_probe_partial(network_context)
        if not name:
            continue
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["discovery_sources"] = _merge_unique(
            observation.get("discovery_sources"), ["netbios"]
        )
        observation["fingerprints"] = _merge_unique(
            observation.get("fingerprints"), [f"netbios-name:{name}"]
        )

    # mDNS is a product's own service advertisement, not a port-derived name.
    # Restrict responses to the requested scan subnet so a second LAN/VPN
    # interface cannot leak unrelated private hosts into the household.
    for host, fingerprints in mdns_fingerprints.items():
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["services"] = _merge_unique(observation.get("services"), ["mdns"])
        observation["discovery_sources"] = _merge_unique(observation.get("discovery_sources"), ["mdns"])
        observation["fingerprints"] = _merge_unique(observation.get("fingerprints"), fingerprints)

    # A current matching router lease can corroborate a proven observation.
    # Its hostname remains private evidence; the identity resolver still
    # requires vendor/model/catalog corroboration before it becomes a
    # resident-facing product name.
    for host, entry in dhcp_entries.items():
        # A lease can be valid long after a device goes offline.  Attach it to
        # an observation already established by this scan, but never create a
        # device from the lease alone.
        observation = by_ip.get(host)
        if observation is None:
            continue
        current_mac = neighbors.get(host, "").upper()
        lease_mac = str(entry.get("mac") or "").strip().upper()
        if not current_mac or current_mac != lease_mac:
            continue
        observation["discovery_sources"] = _merge_unique(
            observation.get("discovery_sources"), ["dhcp-lease"]
        )
        hostname = str(entry.get("hostname") or "").strip()
        if hostname:
            observation["fingerprints"] = _merge_unique(
                observation.get("fingerprints"), [f"dhcp-hostname:{hostname}"]
            )

    for host, fingerprints in ssdp_fingerprints.items():
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["open_ports"] = _merge_unique(observation.get("open_ports"), [1900])
        observation["services"] = _merge_unique(observation.get("services"), ["upnp"])
        observation["discovery_sources"] = _merge_unique(observation.get("discovery_sources"), ["ssdp"])
        observation["fingerprints"] = _merge_unique(observation.get("fingerprints"), fingerprints)
        locations = [
            value.split(":", 1)[1]
            for value in fingerprints
            if value.lower().startswith("ssdp-location:")
        ]
        for location in locations[:2]:
            upnp_fingerprints, complete = _upnp_evidence(
                host,
                location,
                interface_binding,
            )
            if not complete:
                _mark_server_probe_partial(network_context)
            observation["fingerprints"] = _merge_unique(
                observation.get("fingerprints"), upnp_fingerprints
            )

    # WS-Discovery proves only that an ONVIF endpoint answered from this IP.
    # Keep it as private product-protocol evidence; multicast never refreshes
    # a cached ARP MAC and the IP-keyed observation merge prevents duplicates.
    for host, fingerprints in onvif_fingerprints.items():
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["open_ports"] = _merge_unique(
            observation.get("open_ports"), [WS_DISCOVERY_PORT]
        )
        observation["services"] = _merge_unique(
            observation.get("services"), ["onvif"]
        )
        observation["discovery_sources"] = _merge_unique(
            observation.get("discovery_sources"), ["ws-discovery"]
        )
        observation["fingerprints"] = _merge_unique(
            observation.get("fingerprints"), fingerprints
        )

    for host, info in found:
        observation = ensure_observation(host)
        if observation is None:
            continue
        observation["open_ports"] = _merge_unique(observation.get("open_ports"), [PROBE_PORT])
        observation["services"] = _merge_unique(observation.get("services"), ["spotify-connect"])
        observation["discovery_sources"] = _merge_unique(
            observation.get("discovery_sources"), ["server-protocol-probe", "spotify-connect"]
        )
        # ``found`` contains only a successfully parsed HTTP 2xx getInfo
        # response (see ``_get_info``).  Preserve that success boundary so the
        # identity resolver can distinguish the device's structured response
        # from a bare open port or an attempted request.
        fingerprints = ["spotify-probe:17654", "spotify-getinfo-done"]
        if info.get("brand"):
            fingerprints.append(f"spotify-brand:{info['brand']}")
        if info.get("model"):
            fingerprints.append(f"spotify-model:{info['model']}")
        if info.get("name"):
            fingerprints.append(f"spotify-name:{info['name']}")
        if info.get("type"):
            fingerprints.append(f"spotify-type:{info['type']}")
        observation["fingerprints"] = _merge_unique(observation.get("fingerprints"), fingerprints)
    return result


__all__ = ["augment_android_observations"]
