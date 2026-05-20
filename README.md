# MCP Probe

MCP Probe audits MCP (Model Context Protocol) servers for protocol compliance. Paste your server URL, click Run Audit, and get a structured report showing exactly where your server passes, warns, or fails against the spec.

It works by firing real JSON-RPC 2.0 requests at your server and analysing the responses — no mocking, no simulation. 18 checks across 5 protocol layers.

---

## Running locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open [http://localhost:8000](http://localhost:8000).

---

## Deploying

**Render**
1. Push this repo to GitHub
2. New Web Service → connect the repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. No environment variables required

**Railway**
1. Push this repo to GitHub
2. New project → Deploy from GitHub repo
3. Railway auto-detects `railway.toml` — no configuration needed

---

## What it checks

| ID | Name | What it tests |
|----|------|---------------|
| CHECK-01 | Initialize handshake | Server responds to `initialize` with `result.protocolVersion` and `result.serverInfo` |
| CHECK-02 | Protocol version validity | `result.protocolVersion` is a recognised MCP version string |
| CHECK-03 | Capabilities declaration | `result.capabilities` is present and is an object |
| CHECK-04 | JSON-RPC version field | Every response includes `"jsonrpc": "2.0"` |
| CHECK-05 | Response ID echo | Every response `id` matches the exact request `id` that triggered it |
| CHECK-06 | tools/list responds | `tools/list` returns `result.tools` as an array |
| CHECK-07 | Tool schema completeness | Every tool has `name`, `description`, and `inputSchema` |
| CHECK-08 | inputSchema validity | Every `inputSchema` has `type: "object"` and a `properties` object |
| CHECK-09 | Unknown tool handling | Server returns an error for a non-existent tool name |
| CHECK-10 | Missing required parameter handling | Server rejects calls that omit required parameters |
| CHECK-11 | Valid tool call succeeds | A tool with no required params can be called with empty arguments |
| CHECK-12 | Tool response content structure | Tool responses include `result.content` (array) and `result.isError` (boolean) |
| CHECK-13 | Method not found error code | Unknown methods return error code `-32601` |
| CHECK-14 | Notification handling | Server handles a JSON-RPC notification (no `id`) without crashing |
| CHECK-15 | Invalid params error code | Non-object `params` returns error code `-32602` or `-32600` |
| CHECK-16 | Response time baseline | Core methods respond within 3000ms |
| CHECK-17 | Content-Type header | All responses include `Content-Type: application/json` |
| CHECK-18 | No sensitive data in errors | Error messages contain no file paths or stack traces |

---

## Scoring

| Score | Verdict |
|-------|---------|
| 90–100 | **COMPLIANT** |
| 70–89 | **MOSTLY COMPLIANT** |
| 50–69 | **PARTIALLY COMPLIANT** |
| 0–49 | **NON-COMPLIANT** |

Score = `(PASS × 1 + WARN × 0.5) / total_checks × 100`. Skipped checks are excluded.

A COMPLIANT verdict requires tool call checks (Layer 3) to have actually run — a server with no tools cannot score COMPLIANT.

---

## What it's useful for

MCP Probe is most useful at the **protocol layer** — verifying that your server speaks JSON-RPC 2.0 correctly, returns the right fields, handles errors by the spec, and responds within acceptable time. These are the kinds of issues that cause MCP clients to silently reject or ignore a server, and they can be hard to diagnose without a tool like this.

If your server passes all 18 checks, you can be confident the protocol foundation is solid. That's a prerequisite for everything else.

---

## What it doesn't do

**It does not verify that your tools work correctly.** MCP Probe checks that tool responses are structured right (`result.content`, `result.isError`), but it does not validate the content of those responses — whether the data returned is accurate, meaningful, or matches your declared schema.

**It does not test stdio transport.** MCP Probe only reaches servers over HTTP/HTTPS. Servers using stdio (the primary transport for Claude Desktop integrations) are not supported.

**It does not test SSE streaming.** The probe requests non-streaming JSON responses. Streaming tool results over Server-Sent Events are not verified.

**It calls your tools with empty arguments.** During CHECK-11, the probe calls the first tool it finds with no required parameters, using `{}` as arguments. If that tool has side effects, they will trigger. Know what tools your server exposes before auditing against a production instance.

A COMPLIANT score means your server speaks the protocol correctly — not that your tools do what they're supposed to do. End-to-end tool correctness still requires testing with a real MCP client.
