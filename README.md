# MCP Probe

A protocol conformance validator for MCP (Model Context Protocol) servers. Paste the URL of a remotely-hosted MCP server, click **Run Audit**, and get a structured report showing exactly where your server passes, warns, or fails against the MCP specification.

Think of it as a linter for MCP servers.

No AI API calls. No paid services. Just real JSON-RPC 2.0 messages fired at your server and responses analysed against known spec requirements.

---

## Running locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open [http://localhost:8000](http://localhost:8000).

---

## Deploying to Railway

1. Push this repo to GitHub.
2. Create a new Railway project → **Deploy from GitHub repo**.
3. Railway will auto-detect the `railway.toml` and use:
   ```
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```
4. No environment variables required.

---

## The 18 checks

| ID | Name | What it tests |
|----|------|---------------|
| CHECK-01 | Initialize handshake | Server responds to `initialize` with `result.protocolVersion` and `result.serverInfo` |
| CHECK-02 | Protocol version validity | `result.protocolVersion` is a recognised MCP version string |
| CHECK-03 | Capabilities declaration | `result.capabilities` is present and is an object |
| CHECK-04 | JSON-RPC version field | Every response includes `"jsonrpc": "2.0"` |
| CHECK-05 | Response ID echo | Every response `id` matches the request `id` that triggered it |
| CHECK-06 | tools/list responds | `tools/list` returns `result.tools` as an array |
| CHECK-07 | Tool schema completeness | Every tool has `name` (1-128 chars), `description`, and `inputSchema` |
| CHECK-08 | inputSchema validity | Every `inputSchema` has `type: "object"` and a `properties` object |
| CHECK-09 | Unknown tool handling | Server returns an error or `isError: true` for a non-existent tool |
| CHECK-10 | Missing required parameter handling | Server rejects calls that omit required parameters |
| CHECK-11 | Valid tool call succeeds | A tool with no required params can be called with empty arguments |
| CHECK-12 | Tool response content structure | Successful tool responses have `result.content` (array) and `result.isError` (boolean) |
| CHECK-13 | Method not found returns correct error code | Unknown methods return error code `-32601` |
| CHECK-14 | Malformed JSON-RPC handling | Server handles a notification (no `id`) without crashing |
| CHECK-15 | Invalid params error code | String `params` returns error code `-32602` or `-32600` |
| CHECK-16 | Response time baseline | `initialize` and `tools/list` both respond within 3000ms |
| CHECK-17 | Content-Type header | All JSON-RPC responses include `Content-Type: application/json` |
| CHECK-18 | No sensitive data in error messages | Error fields contain no file paths or stack traces |

---

## Verdict levels

| Score | Verdict |
|-------|---------|
| 90–100 | **COMPLIANT** — server conforms to the MCP specification |
| 70–89  | **MOSTLY COMPLIANT** — minor issues worth addressing |
| 50–69  | **PARTIALLY COMPLIANT** — significant gaps in conformance |
| 0–49   | **NON-COMPLIANT** — server has fundamental protocol issues |

Score formula: `(PASS × 1 + WARN × 0.5) / total_checks × 100`  
Skipped checks are excluded from the denominator.

---

## Known limitations

- Only tests servers reachable via HTTP/HTTPS (Streamable HTTP transport). Servers using stdio transport are not supported.
- Tool calls (CHECK-11) are made with empty arguments `{}`. Tools that require specific inputs to return meaningful results may show as WARN rather than PASS.
- CHECK-18 uses pattern matching for known sensitive data signatures — it is not exhaustive.
- The audit enforces a 30-second global timeout and 8-second per-request timeout. Extremely slow servers may accumulate FAIL results on timing checks even if they are otherwise conformant.
