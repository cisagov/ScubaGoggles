"""Offline URI regression tests for IPv6 DNS-over-HTTPS resolvers."""
from unittest.mock import Mock

import dns.message
import dns.query
import dns.rcode
import dns.rrset
import httpx
import pytest

from scubagoggles.robust_dns import RobustDNSClient

SERVERS = [
    ("cloudflare-dns.com", "cloudflare-dns.com"),
    ("1.1.1.1", "1.1.1.1"),
    ("2606:4700:4700::1111", "[2606:4700:4700::1111]"),
    ("2001:db8::53", "[2001:db8::53]"),
    ("::1", "[::1]"),
    ("2001:0db8:0000:0000:0000:0000:0000:0053",
     "[2001:0db8:0000:0000:0000:0000:0000:0053]"),
    ("[2001:db8::53]", "[2001:db8::53]"),
    ("::ffff:192.0.2.1", "[::ffff:192.0.2.1]"),
    ("resolver.example.test:8443", "resolver.example.test:8443"),
    ("[2001:db8::53]:8443", "[2001:db8::53]:8443"),
]


@pytest.fixture(name="client")
def dns_client_fixture(mocker):
    """Use a mocked system resolver and no network requests."""
    mocker.patch("scubagoggles.robust_dns.resolver.Resolver")
    return RobustDNSClient()


def successful_reply(query, uri, timeout):
    """Validate the real HTTP URL syntax, then return a local DNS answer."""
    parsed = httpx.URL(uri)
    assert parsed.scheme == "https"
    assert parsed.host
    assert timeout == 5
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text(
        query.question[0].name, 60, "IN", "TXT", '"test-response"'))
    return response


@pytest.mark.parametrize("server,authority", SERVERS)
def test_select_doh_server_uses_valid_uri(client, mocker, server, authority):
    """Selection accepts each supported authority without modifying its value."""
    client.preferred_doh_list = [server]
    request = mocker.patch("dns.query.https", side_effect=successful_reply)
    assert client.get_doh_server() == server
    assert request.call_count == 1
    assert request.call_args.args[1] == f"https://{authority}/dns-query"


@pytest.mark.parametrize("server,authority", SERVERS)
def test_cached_doh_queries_use_valid_uri(client, mocker, server, authority):
    """Repeated queries preserve cached hosts and respect the custom path."""
    client.doh_server = server
    request = mocker.patch("dns.query.https", side_effect=successful_reply)
    for _ in range(2):
        result = client.doh_query("example.test", 2, "custom-query")
        assert result["answers"] == ["test-response"]
        assert result["errors"] == []
        assert client.doh_server == server
    assert request.call_count == 2
    assert all(call.args[1] == f"https://{authority}/custom-query"
               for call in request.call_args_list)


def test_default_list_falls_back_to_ipv6(client, mocker):
    """A failed hostname can fall back to the built-in IPv6 resolver."""
    def ipv6_only(query, uri, timeout):
        if uri != "https://[2606:4700:4700::1111]/dns-query":
            raise OSError("This fixture accepts only the IPv6 resolver")
        return successful_reply(query, uri, timeout)

    request = mocker.patch("dns.query.https", side_effect=ipv6_only)
    client.resolver.resolve.side_effect = dns.resolver.NoAnswer
    result = client.query("example.test")
    assert result["answers"] == ["test-response"]
    assert client.doh_server == "2606:4700:4700::1111"
    assert request.call_count == 3  # hostname probe, IPv6 probe, actual query
    assert result["log_entries"][-1]["query_method"] == "DoH"


def test_ipv6_transient_errors_keep_retry_budget(client, mocker):
    """URI formatting does not change the retry or logging contract."""
    client.doh_server = "2001:db8::53"
    calls = Mock(side_effect=[OSError("temporary"), None])
    def retry_then_reply(query, uri, timeout):
        calls()
        return successful_reply(query, uri, timeout)

    request = mocker.patch("dns.query.https", side_effect=retry_then_reply)
    result = client.doh_query("example.test", 2)
    assert result["answers"] == ["test-response"]
    assert result["errors"] == ["temporary"]
    assert request.call_count == 2
