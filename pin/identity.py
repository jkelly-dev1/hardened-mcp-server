"""What a pin is bound to.

A pin is a statement about a tool offered BY SOMEONE. Get the someone wrong and
the hash is arithmetic about nothing: a second server can offer a tool under a
name the first one owns, satisfy the pin because the pin only ever knew the
name, and be called with the first server's approval.

The spec closes off the obvious answer, explicitly and in two places. On
`server/discover`, revision 2026-07-28 says of `serverInfo`: "self-reported by
the server and is not verified by the protocol ... Clients SHOULD NOT use it to
change their behavior, and SHOULD NOT rely on it for security decisions." On
`tools/list` it says of cross-server name collisions that clients aggregating
several servers SHOULD disambiguate by prefixing with a server identifier, and
then that "The server `name` (from `serverInfo`) is not guaranteed to be unique
across servers and SHOULD NOT be relied upon for disambiguation."

So the protocol tells a client to namespace tools per server, and in the same
breath tells it that the only server-supplied name is unusable for the job. The
resolution is that identity must come from the host's own configuration, never
from the connection's payload. The host decided which binary to launch or which
URL to open; that decision is the identity, and nothing the server says can
change it.

`pin/shadow.py` measures what a name-bound pin costs.
"""

from __future__ import annotations

import hashlib
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """A stable, host-side name for one configured server.

    `value` is what pins are keyed by. `source` records how it was derived, so
    a store can refuse to compare pins that were anchored differently. An
    identity derived from a launch command and one derived from a URL are not
    the same kind of claim and must not silently unify.
    """

    value: str
    source: str

    @property
    def key(self) -> str:
        return f"{self.source}:{self.value}"


def from_stdio_command(command: str, args: tuple[str, ...] = ()) -> ServerIdentity:
    """Identity of a stdio server: the launch command the HOST configured.

    Arguments are included because they routinely select what the server does.
    A filesystem server rooted at /tmp and one rooted at $HOME are the same
    binary and are not the same trust decision.

    What this does not prove, stated because it is the honest limit: the
    command line names a path, not the bytes at that path. A server updated in
    place keeps this identity across the update. That is intentional here and
    it is exactly what makes rug pulls interesting. The identity is stable and
    the TOOL DEFINITION is what moved, so the pin is the thing that has to
    notice. A deployment wanting the stronger property should hash the
    executable and put that in `source`, which costs a stat and a read per
    connect and is out of scope for this measurement.
    """
    rendered = shlex.join([command, *args])
    return ServerIdentity(value=rendered, source="stdio-command")


def from_http_origin(url: str) -> ServerIdentity:
    """Identity of a Streamable HTTP server: scheme, host and port.

    Path is deliberately excluded: two paths on one origin are one trust
    boundary, because whoever controls the origin controls both. Including the
    path would let a server split itself into apparently distinct identities
    and collect a separate first-use approval for each.
    """
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"not an absolute URL: {url!r}")
    return ServerIdentity(
        value=f"{parts.scheme}://{parts.netloc}".lower(),
        source="http-origin",
    )


def from_self_reported_name(server_info_name: str) -> ServerIdentity:
    """The binding the spec warns against. Present ONLY to be measured.

    Nothing in the shipped client path calls this. `pin/shadow.py` uses it as
    the control arm, because a claim that host-side identity matters is worth
    more as a demonstrated difference than as a quotation from the spec.
    """
    return ServerIdentity(value=server_info_name, source="self-reported")


def digest(identity: ServerIdentity) -> str:
    """Short stable hash of an identity, for log lines and table columns."""
    return hashlib.sha256(identity.key.encode("utf-8")).hexdigest()[:12]
