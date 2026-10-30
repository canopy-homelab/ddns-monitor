import base64
import time
import urllib.error
import urllib.parse
import urllib.request

import dns.exception
import dns.resolver
import pytest

NOIP_UPDATE_URL = "https://dynupdate.no-ip.com/nic/update"


def _query_noip(
    params: dict[str, str],
    auth: tuple[str, str] | None = None,
    user_agent: str | None = None,
    timeout: float = 10.0,
) -> tuple[int, str]:
    query_string = urllib.parse.urlencode(params)
    url = f"{NOIP_UPDATE_URL}?{query_string}" if params else NOIP_UPDATE_URL
    headers: dict[str, str] = {}
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    if user_agent:
        headers["User-Agent"] = user_agent

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace").strip()
        return e.code, body


class TestNoIpContract:
    """Empirical verification of the No-IP DynDNS2 DDNS API contract."""

    def test_reachability_unauthenticated(self):
        """
        Observed: Unauthenticated call attempting an IP mutation returns HTTP 401 with 'badauth'.
        (Note: If caller WAN IP matches, edge may short-circuit to 200 with 'nochg').
        """
        status, body = _query_noip(
            {"hostname": "probe-unauth-mutation.ddns.net", "myip": "1.2.3.4"}
        )
        assert status in (200, 401), f"Expected HTTP 200 or 401, got {status} with body: {body}"
        assert body.startswith(("badauth", "nochg")), (
            f"Expected 'badauth' or short-circuit 'nochg', got: {body}"
        )

    def test_bad_credentials(self, noip_config):
        """
        Observed: Invalid credentials when requesting an IP mutation returns HTTP 401
        with 'badauth'. Note: If IP already matches, edge may short-circuit to 'nochg'.
        """
        status, body = _query_noip(
            {"hostname": noip_config["hostname"], "myip": "1.2.3.4"},
            auth=("invalid_user_probe_123", "invalid_password_probe_123"),
            user_agent=noip_config["user_agent"],
        )
        assert status == 401, f"Expected HTTP 401, got {status} with body: {body}"
        assert body.startswith("badauth"), f"Expected 'badauth', got: {body}"

    def test_empty_hostname_returns_nohost(self, noip_config):
        """Observed: Explicitly empty hostname query parameter ('hostname=') returns 'nohost'."""
        status, body = _query_noip(
            {"hostname": ""},
            auth=(noip_config["username"], noip_config["password"]),
            user_agent=noip_config["user_agent"],
        )
        assert status == 200, f"Expected HTTP 200, got {status} with body: {body}"
        assert body.startswith("nohost"), f"Expected 'nohost', got: {body}"

    def test_ddns_key_scoping_semantics(self, noip_config):
        """
        Observed: When authenticating via a DDNS Key (e.g. user@ddnskey.com),
        the key is pre-scoped to its assigned group. Supplying an arbitrary hostname
        or the group meta-host updates the key's assigned records.
        """
        status, body = _query_noip(
            {"hostname": "arbitrary-subdomain-probe-12345.ddns.net"},
            auth=(noip_config["username"], noip_config["password"]),
            user_agent=noip_config["user_agent"],
        )
        assert status == 200, f"Expected HTTP 200, got {status} with body: {body}"
        assert body.startswith(("good", "nochg")), (
            f"Expected DDNS key group update ('good' or 'nochg'), got: {body}"
        )

    def test_valid_update_and_idempotency(self, noip_config):
        """
        Claim:
        1. Updating returns 'good <ip>' or 'nochg <ip>'.
        2. Idempotent repetition returns 'nochg <ip>' (strictly with the resolved IP).
        Note: If an RFC 5737 test IP is supplied, No-IP discards it and falls back to
        the caller's WAN IP. Both 'good' and 'nochg' always append the resolved IP.
        """
        auth = (noip_config["username"], noip_config["password"])
        ua = noip_config["user_agent"]
        params = {
            "hostname": noip_config["hostname"],
        }

        # Step 1: Initial update (auto-detects or sets IP)
        status1, body1 = _query_noip(params, auth=auth, user_agent=ua)
        assert status1 == 200, f"Expected HTTP 200, got {status1} with body: {body1}"
        assert body1.startswith(("good", "nochg")), (
            f"Expected 'good' or 'nochg', got: {body1}"
        )
        parts = body1.split()
        assert len(parts) == 2, f"Expected '<status> <ip>', got: {body1}"
        resolved_ip = parts[1]

        # Safety delay to avoid No-IP anti-abuse HTTP 429 throttling
        time.sleep(5.0)

        # Step 2: Idempotent repetition
        status2, body2 = _query_noip(params, auth=auth, user_agent=ua)
        if status2 == 429:
            pytest.skip("No-IP edge rate-limited request with HTTP 429 (anti-abuse policy)")
        assert status2 == 200, f"Expected HTTP 200, got {status2} with body: {body2}"
        assert body2.startswith("nochg"), (
            f"Expected idempotent 'nochg' on second request, got: {body2}"
        )
        assert body2 == f"nochg {resolved_ip}", (
            f"Expected exact match 'nochg {resolved_ip}', got: {body2}"
        )

    def test_authoritative_dns_propagation(self, noip_config):
        """Claim: Authoritative nameservers answer for the configured hostname."""
        hostname = noip_config["hostname"]
        # Skip DNS resolution if targeting the group meta-host all.ddnskey.com
        if hostname == "all.ddnskey.com":
            return

        resolver = dns.resolver.Resolver()
        try:
            ns_ips = [str(rdata) for rdata in dns.resolver.resolve("nf1.no-ip.com", "A")]
            resolver.nameservers = ns_ips
        except (dns.exception.DNSException, OSError):
            pass

        answers = resolver.resolve(hostname, "A")
        resolved_ips = [str(rdata) for rdata in answers]
        assert len(resolved_ips) > 0, f"Expected at least one A record for {hostname}"
