import pytest

from nettriage.util import TargetError, parse_target


@pytest.mark.parametrize(
    "raw, host, scheme, port, path",
    [
        ("example.com", "example.com", "https", 443, "/"),
        ("EXAMPLE.com.", "example.com", "https", 443, "/"),
        ("http://example.com", "example.com", "http", 80, "/"),
        ("https://example.com:8443/health?x=1", "example.com", "https", 8443, "/health?x=1"),
        ("example.com:8080", "example.com", "http", 8080, "/"),
        ("10.0.0.5", "10.0.0.5", "https", 443, "/"),
        ("bücher.example", "xn--bcher-kva.example", "https", 443, "/"),
    ],
)
def test_parse_target(raw, host, scheme, port, path):
    t = parse_target(raw)
    assert (t.host, t.scheme, t.port, t.path) == (host, scheme, port, path)


def test_ip_literal_is_flagged():
    assert parse_target("192.0.2.1").is_ip
    assert not parse_target("example.com").is_ip


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "-oProxyCommand=evil", "exa mple.com", "ftp://example.com", "example.com;rm -rf /", "$(whoami).example.com", "a" * 300 + ".com", "http://", "example.com --ports 1"],
)
def test_rejects_unsafe_or_invalid_targets(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_url_omits_default_port():
    assert parse_target("https://example.com:443/a").url == "https://example.com/a"
    assert parse_target("https://example.com:444/a").url == "https://example.com:444/a"
