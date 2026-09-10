"""What a pin is bound to, and which spellings of a URL name one origin."""

from __future__ import annotations

from pin.identity import from_http_origin


def test_one_origin_has_one_key_however_the_url_spells_it() -> None:
    """An explicit default port and userinfo do not change who answers.

    Three keys for one origin would let a server collect three first-use
    approvals, and the userinfo spelling would carry a credential into the key.
    """
    keys = {
        from_http_origin(url).key
        for url in (
            "https://acme.example.net/mcp",
            "https://acme.example.net:443/mcp",
            "https://user:Secret@acme.example.net/mcp",
            "HTTPS://ACME.Example.net/other/path",
        )
    }
    assert keys == {"http-origin:https://acme.example.net"}


def test_a_non_default_port_or_scheme_is_a_different_origin() -> None:
    """The control: collapsing every URL to its host would also pass the test above."""
    plain = from_http_origin("https://acme.example.net/mcp").key
    assert from_http_origin("https://acme.example.net:8443/mcp").key != plain
    assert from_http_origin("http://acme.example.net/mcp").key != plain
    assert from_http_origin("http://acme.example.net:80/mcp").key != plain
