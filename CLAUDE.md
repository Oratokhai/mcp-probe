# MCP Probe — Project Context

## What this is
A protocol conformance validator for MCP (Model Context Protocol) servers. A developer pastes the URL of a remotely-hosted MCP server, clicks **Run Audit**, and gets a structured report showing where their server passes, warns, or fails against the MCP spec. Think of it as a linter for MCP servers.

No AI API calls. No paid services. Pure logic — the backend fires real JSON-RPC 2.0 messages and analyses responses.

---

## Project structure

```
mcp-probe/
├── main.py              # FastAPI app + all 18 check logic + /audit endpoint
├── requirements.txt     # fastapi, uvicorn, httpx, python-dotenv
├── frontend/
│   └── index.html       # Single-file frontend (vanilla JS, no frameworks)
├── railway.toml         # Railway deployment config
├── README.md            # Docs, check table, verdict levels
└── CLAUDE.md            # This file
```

---

## Running locally

```bash
pip3 install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open http://localhost:8000

---

## Backend — main.py

**Single endpoint:** `POST /audit`  
**Request body:** `{ "url": "https://your-mcp-server.com/mcp" }`  
**GET /** serves `frontend/index.html`

### Security / validation
- Rejects non-http/https URLs
- Blocks localhost / 127.0.0.1 / 0.0.0.0 (SSRF prevention)
- Global 30s audit timeout, 8s per-request timeout
- All outbound requests use `User-Agent: mcp-probe/1.0`

### The 18 checks (5 layers)

| ID | Layer | Name |
|----|-------|------|
| CHECK-01 | Handshake | Initialize handshake |
| CHECK-02 | Handshake | Protocol version validity |
| CHECK-03 | Handshake | Capabilities declaration |
| CHECK-04 | Handshake | JSON-RPC version field |
| CHECK-05 | Handshake | Response ID echo |
| CHECK-06 | Tool Discovery | tools/list responds |
| CHECK-07 | Tool Discovery | Tool schema completeness |
| CHECK-08 | Tool Discovery | inputSchema validity |
| CHECK-09 | Tool Call | Unknown tool handling |
| CHECK-10 | Tool Call | Missing required parameter handling |
| CHECK-11 | Tool Call | Valid tool call succeeds |
| CHECK-12 | Tool Call | Tool response content structure |
| CHECK-13 | Error Handling | Method not found returns correct error code |
| CHECK-14 | Error Handling | Malformed JSON-RPC handling |
| CHECK-15 | Error Handling | Invalid params error code |
| CHECK-16 | Response Hygiene | Response time baseline |
| CHECK-17 | Response Hygiene | Content-Type header |
| CHECK-18 | Response Hygiene | No sensitive data in error messages |

### Scoring
- Score = `(PASS × 1 + WARN × 0.5) / total_checks × 100` (SKIPs excluded)
- 90–100 → COMPLIANT, 70–89 → MOSTLY COMPLIANT, 50–69 → PARTIALLY COMPLIANT, 0–49 → NON-COMPLIANT

### Skip logic
- If CHECK-01 (handshake) FAILs → all remaining checks SKIPped
- If CHECK-06 (tools/list) FAILs → CHECK-07 through CHECK-12 SKIPped

---

## Frontend — frontend/index.html

Single HTML file, vanilla JS only, no frameworks.

### Visual design (just redesigned — do NOT revert)
- **Animated canvas aura**: wavy glowing semicircle centred at the bottom edge of the viewport, arcing upward. 7 stacked canvas rings giving a neon glow effect. Indigo/violet colour palette (#6366f1, #8b5cf6, #a78bfa).
- **Dark glass aesthetic**: near-black background (#06060f), cards with backdrop-filter blur, faint indigo borders.
- **Monospace system labels**: eyebrow reads `MCP.PROBE // PROTOCOL VALIDATOR`, layer titles like `L1 // Handshake & Protocol Conformance`.
- Canvas animation pauses when tab is hidden (visibility API).

### UI sections
1. Header (eyebrow + title + description)
2. Input card (URL field + Run Audit button)
3. Loading state (spinner + "Running 18 checks against [url]...")
4. Results: server info card + score card + stat chips + layered check rows
5. Each check row is collapsible — click to reveal detail + fix suggestion

---

## Deployment

Target: Railway  
`railway.toml` sets: `uvicorn main:app --host 0.0.0.0 --port $PORT`

Steps:
1. Push to GitHub
2. New Railway project → Deploy from GitHub repo
3. No env vars needed

---

## Known limitations
- Only tests HTTP/HTTPS servers (Streamable HTTP transport). stdio not supported.
- CHECK-11 calls tools with empty args `{}` — tools requiring specific inputs may WARN instead of PASS.
- CHECK-18 uses regex pattern matching for sensitive data — not exhaustive.

---

## What's done / what's left

### Done
- [x] All 18 checks implemented in main.py
- [x] Scoring + verdict logic
- [x] SSRF protection + timeout enforcement
- [x] Single-file frontend with animated aura canvas
- [x] Collapsible check rows with fix suggestions
- [x] railway.toml deployment config
- [x] README.md

### Possible next steps (not started)
- [ ] Share/export report as JSON or PDF
- [ ] History of past audits (localStorage)
- [ ] Copy-to-clipboard for report
- [ ] Deeper SSE transport support
- [ ] More granular fix suggestions per check
