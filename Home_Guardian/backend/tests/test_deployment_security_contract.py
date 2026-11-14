from __future__ import annotations

from pathlib import Path

from starlette.requests import Request

from app.main import guardian_lookup_rate_key, trusted_scan_client_ip


def _request(
    client_host: str,
    forwarded_for: str = "",
    real_ip: str = "",
    forwarded: str = "",
) -> Request:
    headers = []
    if forwarded_for:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    if real_ip:
        headers.append((b"x-real-ip", real_ip.encode("ascii")))
    if forwarded:
        headers.append((b"forwarded", forwarded.encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/guardian-mode/links/lookup",
            "headers": headers,
            "client": (client_host, 12345),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        }
    )


def test_guardian_lookup_rate_key_ignores_spoofed_forwarded_for_by_default(monkeypatch):
    monkeypatch.delenv("HG_TRUSTED_PROXY_HOSTS", raising=False)

    assert guardian_lookup_rate_key(_request("198.51.100.8", "203.0.113.77")) == "198.51.100.8"


def test_guardian_lookup_rate_key_accepts_real_ip_only_from_explicit_proxy(monkeypatch):
    monkeypatch.setenv("HG_TRUSTED_PROXY_HOSTS", "127.0.0.1, ::1")

    assert guardian_lookup_rate_key(_request("127.0.0.1", "198.51.100.200", "203.0.113.77")) == "203.0.113.77"
    assert guardian_lookup_rate_key(_request("198.51.100.8", "203.0.113.77", "203.0.113.88")) == "198.51.100.8"


def test_scan_client_ip_accepts_header_free_direct_ipv4(monkeypatch):
    monkeypatch.delenv("HG_TRUSTED_PROXY_HOSTS", raising=False)

    assert trusted_scan_client_ip(_request("192.168.50.10")) == "192.168.50.10"


def test_scan_client_ip_rejects_spoofed_headers_from_direct_peer(monkeypatch):
    monkeypatch.delenv("HG_TRUSTED_PROXY_HOSTS", raising=False)

    assert trusted_scan_client_ip(
        _request("192.168.50.10", "192.168.50.99", "192.168.50.99")
    ) is None


def test_scan_client_ip_requires_matching_single_headers_from_trusted_proxy(monkeypatch):
    monkeypatch.setenv("HG_TRUSTED_PROXY_HOSTS", "127.0.0.1,::1")

    assert trusted_scan_client_ip(
        _request("127.0.0.1", "192.168.50.10", "192.168.50.10")
    ) == "192.168.50.10"
    assert trusted_scan_client_ip(
        _request("::1", "192.168.50.10", "192.168.50.10")
    ) == "192.168.50.10"
    assert trusted_scan_client_ip(
        _request("127.0.0.1", "192.168.50.10", "192.168.50.11")
    ) is None
    assert trusted_scan_client_ip(
        _request(
            "127.0.0.1",
            "198.51.100.8, 192.168.50.10",
            "192.168.50.10",
        )
    ) is None
    assert trusted_scan_client_ip(
        _request("127.0.0.1", "", "192.168.50.10")
    ) is None
    assert trusted_scan_client_ip(
        _request(
            "127.0.0.1",
            "192.168.50.10",
            "192.168.50.10",
            'for="192.168.50.10"',
        )
    ) is None


def test_deployment_requires_root_only_auth_secret_file_before_service_start():
    server_root = Path(__file__).resolve().parents[3] / "Home_Guardian_Server"
    service = (server_root / "deploy" / "systemd" / "home-guardian-api.service").read_text(encoding="utf-8")
    install_script = (server_root / "deploy" / "scripts" / "remote-install.sh").read_text(encoding="utf-8")
    nginx_config = (server_root / "deploy" / "nginx" / "home-guardian.conf").read_text(encoding="utf-8")
    nginx_snippet = (server_root / "deploy" / "nginx" / "home-guardian.snippet.conf").read_text(encoding="utf-8")

    assert "EnvironmentFile=/etc/home-guardian/auth.env" in service
    assert "HG_ALLOW_EPHEMERAL_AUTH_SECRET" not in service
    assert "Environment=HG_TRUSTED_PROXY_HOSTS=127.0.0.1,::1" in service
    assert "Environment=HG_NVD_CACHE_PATH=/srv/home-guardian/runtime/nvd-cache-v1.json" in service
    assert "AUTH_ENV_FILE=/etc/home-guardian/auth.env" in install_script
    assert "validate_production_auth" in install_script
    assert "critical_env_value GOOGLE_CLIENT_ID" in install_script
    assert "GOOGLE_CLIENT_ID is not a production Google OAuth client id" in install_script
    assert "root:root" in install_script
    assert '[ "${mode}" = \'600\' ]' in install_script
    assert "critical_env_value HG_AUTH_TOKEN_SECRET 32" in install_script
    assert "HG_AUTH_TOKEN_SECRET" in install_script
    assert 'systemctl is-active --quiet "${SERVICE_NAME}.service"' in install_script
    assert "for attempt in $(seq 1 90)" in install_script
    assert "last /health response" in install_script
    assert 'getattr(app, "version", None) != "1.0.0"' in install_script
    assert 'data.get("version") != "1.0.0"' in install_script
    deploy_script = (server_root / "deploy" / "scripts" / "deploy.ps1").read_text(encoding="utf-8")
    assert "$response.data.version -ne '1.0.0'" in deploy_script
    assert "required systemd rollback unit is missing" in deploy_script
    assert 'sudo install -o root -g root -m 0644 "${unit_backup}" "${unit_path}"' in deploy_script
    assert 'sudo cmp -s -- "${unit_backup}" "${unit_path}"' in deploy_script
    assert 'sudo diff -qr -- "${dropin_backup}" "${dropin_path}"' in deploy_script
    assert "$env:HOME_GUARDIAN_PUBLIC_BASE_URL" in deploy_script
    assert 'if ($LASTEXITCODE -ne 0)' in deploy_script
    assert "$proxy_add_x_forwarded_for" not in nginx_config
    assert "$proxy_add_x_forwarded_for" not in nginx_snippet
    assert nginx_config.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
    assert nginx_snippet.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
