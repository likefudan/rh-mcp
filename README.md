# rh-mcp

A read-only Python client for Robinhood's official MCP server
(`https://agent.robinhood.com/mcp/trading`), exposed two ways:

- **Library** — `RobinhoodMCPClient`, an async context manager. The intended
  consumer is the executor of an agentic trading system.
- **CLI** — `rh-mcp`, for inspecting the server and debugging that executor.

Safety, policy, and risk logic deliberately live in the consuming system rather
than in this client.

## Status

**Pre-implementation.** The design is settled and written up in `DESIGN.md`;
no client code exists yet.
