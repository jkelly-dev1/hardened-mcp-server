"""The tool definitions everything else is measured against.

Four tools on one plausible server. They are not a random sample; each carries
a feature the 2026-07-28 revision added or widened, because a corpus of
`add(a, b)` tools would make every pinning policy look identical:

  ticket_lookup   annotations, and a parameter already marked `x-mcp-header`
                  in the APPROVED definition, so the measurement has a case
                  where the channel is legitimate and expected
  send_reply      a consequential action, with hints that matter
  search_kb       `$defs` and a `$ref`, plus an `outputSchema`
  export_records  a credential-shaped parameter, which is what makes the
                  header-mirroring mutation worth anything

Written as plain dicts rather than SDK models on purpose: the SDK's `Tool` type
is built with `extra="ignore"` and would silently drop the unknown top-level
key that mutation A8 plants, so a corpus expressed in it could not state the
problem. `pin/wire_server.py` serves these over the real protocol.
"""

from __future__ import annotations

import copy
from typing import Any

#: The approved baseline. Deep-copied by `baseline()` on every access, because
#: mutations edit nested structures and a shared reference would let one
#: measurement arm contaminate the next.
_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "ticket_lookup",
        "title": "Ticket Lookup",
        "description": (
            "Return the current status, owner and last comment for one support "
            "ticket. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ticket_id": {
                    "type": "string",
                    "description": "Ticket identifier, for example ACME-1421.",
                },
                "region": {
                    "type": "string",
                    "enum": ["us-east", "us-west", "eu-central"],
                    "description": "Data region the ticket lives in.",
                    # Legitimate and disclosed at approval time: the region has
                    # to reach the load balancer for routing, and it is not
                    # sensitive. Present so the measurement distinguishes
                    # "this tool mirrors a parameter" from "this tool STARTED
                    # mirroring a parameter", which are different events.
                    "x-mcp-header": "Region",
                },
            },
            "required": ["ticket_id", "region"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "send_reply",
        "title": "Send Reply",
        "description": (
            "Post a reply to a support ticket. The reply is visible to the "
            "customer and cannot be withdrawn."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ticket_id": {"type": "string"},
                "body": {
                    "type": "string",
                    "maxLength": 4000,
                    "description": "Reply text.",
                },
            },
            "required": ["ticket_id", "body"],
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "search_kb",
        "title": "Search Knowledge Base",
        "description": "Full-text search over published support articles.",
        "inputSchema": {
            "$defs": {
                "dateRange": {
                    "type": "object",
                    "properties": {
                        "from": {"type": "string", "format": "date"},
                        "to": {"type": "string", "format": "date"},
                    },
                }
            },
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "description": "Search terms."},
                "published": {"$ref": "#/$defs/dateRange"},
                "updated": {"$ref": "#/$defs/dateRange"},
            },
            "required": ["query"],
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "articles": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                        },
                        "required": ["id", "title"],
                    },
                }
            },
            "required": ["articles"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "attach_file",
        "title": "Attach File",
        "description": "Attach a stored document to a ticket.",
        # The approved definition already points somewhere this client cannot
        # follow. A pin covers the bytes it was shown. These bytes contain a
        # pointer, so the pin covers the POINTER and not the document at the
        # far end of it, which is where the rules about what may be attached
        # actually live. Nothing about the pointer has to change for those
        # rules to change. `pin/mutations.py::remote_schema_ edit` is the
        # trial that establishes what that costs, and
        # `pin/scan.py::unresolvable_refs` is the control that lets a host
        # decline to pin this at all.
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ticket_id": {"type": "string"},
                "attachment": {
                    "$ref": "https://schemas.example.net/support/attachment.json"
                },
            },
            "required": ["ticket_id", "attachment"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "export_records",
        "title": "Export Records",
        "description": (
            "Export ticket records to an approved destination. Requires a "
            "scoped export token issued by the support platform."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["single-ticket", "customer", "all"],
                },
                "export_token": {
                    "type": "string",
                    "description": (
                        "Scoped export credential. Never log or forward this "
                        "value."
                    ),
                },
                "destination": {
                    "type": "string",
                    "description": "Approved destination identifier.",
                },
            },
            "required": ["scope", "export_token", "destination"],
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
)


def baseline() -> list[dict[str, Any]]:
    """The approved definitions, freshly copied."""
    return [copy.deepcopy(tool) for tool in _TOOLS]


def by_name(name: str) -> dict[str, Any]:
    for tool in baseline():
        if tool["name"] == name:
            return tool
    raise KeyError(name)


#: Tool names in a stable order, for table columns.
NAMES: tuple[str, ...] = tuple(tool["name"] for tool in _TOOLS)
