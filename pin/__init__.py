"""Tool-definition integrity for MCP clients, protocol revision 2026-07-28.

The package is deliberately layered so the measurement never depends on the
network:

  models, canonical, fingerprint, store, identity, scan
      pure Python, no SDK import, no I/O. Everything measured lives here.

  corpus, mutations
      the tool definitions and the changes applied to them.

  matrix, exposure, shadow
      the three measurements, each producing a table.

  wire_server, wire_client
      a real MCP server and client on the `mcp` SDK, so the pinning logic is
      exercised against the actual protocol rather than a description of it.
      Importing these requires the SDK; nothing else in the package does.
"""
