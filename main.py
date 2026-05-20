import asyncio
import ipaddress
import socket
import time
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="MCP Probe")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

KNOWN_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
PROBE_HEADERS = {"User-Agent": "mcp-probe/1.0", "Content-Type": "application/json"}
INDIVIDUAL_TIMEOUT = 8.0
GLOBAL_TIMEOUT = 30.0

SENSITIVE_PATTERNS = re.compile(
    r"(Traceback|at line|stack trace|Exception in|/[a-zA-Z0-9_\-./]{4,}|[A-Z]:\\[^\s]+)",
    re.IGNORECASE,
)


def _resolve_and_validate_host(hostname: str) -> None:
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    for family, _, _, _, sockaddr in results:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("Target resolves to a private/internal IP address — not permitted")


class AuditRequest(BaseModel):
    url: str = Field(..., max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        parsed = urlparse(v)
        hostname = parsed.hostname or ""
        if not hostname:
            raise ValueError("URL must include a hostname")
        _resolve_and_validate_host(hostname)
        return v


def make_result(
    check_id: str,
    name: str,
    status: str,
    detail: str,
    fix: str = "",
) -> dict:
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "detail": detail,
        "fix": fix,
    }


def skipped(check_id: str, name: str, reason: str) -> dict:
    return make_result(check_id, name, "SKIP", reason)


async def post_jsonrpc(
    client: httpx.AsyncClient, url: str, payload: dict
) -> tuple[dict | None, float, str | None]:
    start = time.monotonic()
    try:
        resp = await client.post(url, json=payload, headers=PROBE_HEADERS)
        elapsed = (time.monotonic() - start) * 1000
        return resp.json(), elapsed, None
    except httpx.TimeoutException:
        elapsed = (time.monotonic() - start) * 1000
        return None, elapsed, "timeout"
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        return None, elapsed, str(e)


async def post_raw(
    client: httpx.AsyncClient, url: str, body: str
) -> tuple[int | None, dict | None, str | None]:
    try:
        resp = await client.post(
            url,
            content=body.encode(),
            headers=PROBE_HEADERS,
        )
        try:
            return resp.status_code, resp.json(), None
        except Exception:
            return resp.status_code, None, None
    except httpx.TimeoutException:
        return None, None, "timeout"
    except Exception as e:
        return None, None, str(e)


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_path = Path(__file__).parent / "frontend" / "index.html"
    return HTMLResponse(content=html_path.read_text(), status_code=200)


@app.post("/audit")
async def run_audit(req: AuditRequest):
    try:
        return await asyncio.wait_for(_do_audit(req.url), timeout=GLOBAL_TIMEOUT)
    except asyncio.TimeoutError:
        return JSONResponse(
            {"detail": f"Audit timed out after {GLOBAL_TIMEOUT:.0f}s — target server may be too slow."},
            status_code=504,
        )


async def _do_audit(url: str):
    results: list[dict] = []
    server_info: dict = {}
    audit_start = time.monotonic()

    # Track response metadata for cross-check validations
    all_responses: list[dict] = []
    response_times: list[float] = []
    id_pairs: list[tuple[int, Any]] = []

    async with httpx.AsyncClient(timeout=INDIVIDUAL_TIMEOUT, follow_redirects=False) as client:

        # ── LAYER 1: HANDSHAKE ─────────────────────────────────────────────

        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mcp-probe", "version": "1.0.0"},
            },
        }

        init_resp, init_ms, init_err = await post_jsonrpc(client, url, init_payload)
        response_times.append(init_ms)

        # CHECK-01
        if init_err or init_resp is None or "error" in (init_resp or {}):
            results.append(make_result(
                "CHECK-01", "Initialize handshake", "FAIL",
                f"No valid response received. {init_err or 'Server returned error.'}",
                "Ensure your server accepts POST requests with Content-Type: application/json and responds to the initialize method.",
            ))
            handshake_failed = True
        else:
            result_body = init_resp.get("result", {})
            has_protocol = "protocolVersion" in result_body
            has_server_info = "serverInfo" in result_body
            si = result_body.get("serverInfo", {})

            if not has_protocol:
                results.append(make_result(
                    "CHECK-01", "Initialize handshake", "FAIL",
                    "Response missing result.protocolVersion.",
                    "Return protocolVersion in the initialize response result.",
                ))
                handshake_failed = True
            elif not has_server_info or not si.get("name") or not si.get("version"):
                results.append(make_result(
                    "CHECK-01", "Initialize handshake", "WARN",
                    "Handshake succeeded but serverInfo.name or serverInfo.version is missing.",
                    "Include serverInfo with name and version in your initialize response.",
                ))
                handshake_failed = False
            else:
                results.append(make_result(
                    "CHECK-01", "Initialize handshake", "PASS",
                    f"Server responded with protocolVersion and serverInfo.",
                ))
                handshake_failed = False

            server_info = {
                "name": si.get("name", ""),
                "version": si.get("version", ""),
                "protocol_version": result_body.get("protocolVersion", ""),
            }
            all_responses.append(init_resp)
            id_pairs.append((1, init_resp.get("id")))

        if handshake_failed:
            skip_reason = "Handshake failed — cannot proceed"
            skip_ids = [
                ("CHECK-02", "Protocol version validity"),
                ("CHECK-03", "Capabilities declaration"),
                ("CHECK-04", "JSON-RPC version field"),
                ("CHECK-05", "Response ID echo"),
                ("CHECK-06", "tools/list responds"),
                ("CHECK-07", "Tool schema completeness"),
                ("CHECK-08", "inputSchema validity"),
                ("CHECK-09", "Unknown tool handling"),
                ("CHECK-10", "Missing required parameter handling"),
                ("CHECK-11", "Valid tool call succeeds"),
                ("CHECK-12", "Tool response content structure"),
                ("CHECK-13", "Method not found returns correct error code"),
                ("CHECK-14", "Notification handling"),
                ("CHECK-15", "Invalid params error code"),
                ("CHECK-16", "Response time baseline"),
                ("CHECK-17", "Content-Type header"),
                ("CHECK-18", "No sensitive data in error messages"),
            ]
            for cid, cname in skip_ids:
                results.append(skipped(cid, cname, skip_reason))
            audit_duration = int((time.monotonic() - audit_start) * 1000)
            return _build_response(results, server_info, audit_duration)

        # CHECK-02
        proto = result_body.get("protocolVersion", "")  # type: ignore[possibly-undefined]
        if not proto or not isinstance(proto, str):
            results.append(make_result(
                "CHECK-02", "Protocol version validity", "FAIL",
                "result.protocolVersion is missing or not a string.",
                "Return a string value for protocolVersion in the initialize response.",
            ))
        elif proto in KNOWN_VERSIONS:
            results.append(make_result(
                "CHECK-02", "Protocol version validity", "PASS",
                f"Protocol version '{proto}' is a recognised MCP version.",
            ))
        else:
            results.append(make_result(
                "CHECK-02", "Protocol version validity", "WARN",
                f"Protocol version '{proto}' is not a recognised MCP version string.",
                f"Use one of the known versions: {', '.join(sorted(KNOWN_VERSIONS))}.",
            ))

        # CHECK-03
        caps = result_body.get("capabilities")  # type: ignore[possibly-undefined]
        if caps is None:
            results.append(make_result(
                "CHECK-03", "Capabilities declaration", "FAIL",
                "result.capabilities is missing from the initialize response.",
                "Include a capabilities object in your initialize response, even if empty.",
            ))
        elif not isinstance(caps, dict):
            results.append(make_result(
                "CHECK-03", "Capabilities declaration", "FAIL",
                f"result.capabilities is not an object (got {type(caps).__name__}).",
                "capabilities must be a JSON object.",
            ))
        elif caps == {}:
            results.append(make_result(
                "CHECK-03", "Capabilities declaration", "WARN",
                "result.capabilities is an empty object.",
                "Declare your server's capabilities (tools, resources, prompts) in the capabilities object.",
            ))
        else:
            results.append(make_result(
                "CHECK-03", "Capabilities declaration", "PASS",
                f"Capabilities declared: {list(caps.keys())}",
            ))

        # Send notifications/initialized (fire and forget — no response expected)
        try:
            await client.post(
                url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=PROBE_HEADERS,
            )
        except Exception:
            pass

        # ── LAYER 2: TOOL DISCOVERY ────────────────────────────────────────

        tools_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        tools_resp, tools_ms, tools_err = await post_jsonrpc(client, url, tools_payload)
        response_times.append(tools_ms)
        tools_list: list[dict] = []
        tools_failed = False

        # CHECK-06
        if tools_err or tools_resp is None:
            results.append(make_result(
                "CHECK-06", "tools/list responds", "FAIL",
                f"Failed to get a response. {tools_err or ''}",
                "Implement the tools/list method on your server.",
            ))
            tools_failed = True
        elif "error" in tools_resp:
            results.append(make_result(
                "CHECK-06", "tools/list responds", "FAIL",
                f"Server returned an error: {tools_resp['error']}",
                "Implement the tools/list method and ensure it returns result.tools as an array.",
            ))
            tools_failed = True
        else:
            tools_list = tools_resp.get("result", {}).get("tools", None)
            if not isinstance(tools_list, list):
                results.append(make_result(
                    "CHECK-06", "tools/list responds", "FAIL",
                    "result.tools is not an array.",
                    "Return result.tools as a JSON array in the tools/list response.",
                ))
                tools_failed = True
                tools_list = []
            elif len(tools_list) == 0:
                results.append(make_result(
                    "CHECK-06", "tools/list responds", "WARN",
                    "tools/list returned an empty array — server has no tools.",
                    "If your server is meant to expose tools, implement them and return them here.",
                ))
            else:
                results.append(make_result(
                    "CHECK-06", "tools/list responds", "PASS",
                    f"tools/list returned {len(tools_list)} tool(s).",
                ))
            all_responses.append(tools_resp)
            id_pairs.append((2, tools_resp.get("id")))

        # CHECK-07
        if tools_failed:
            results.append(skipped("CHECK-07", "Tool schema completeness", "tools/list failed"))
            results.append(skipped("CHECK-08", "inputSchema validity", "tools/list failed"))
        else:
            missing_name, missing_schema, warn_desc = [], [], []
            for tool in tools_list:
                name = tool.get("name")
                desc = tool.get("description")
                schema = tool.get("inputSchema")
                if not name or not isinstance(name, str) or len(name) > 128:
                    missing_name.append(str(name))
                if not schema or not isinstance(schema, dict):
                    missing_schema.append(str(name))
                if not desc:
                    warn_desc.append(str(name))

            if missing_name or missing_schema:
                results.append(make_result(
                    "CHECK-07", "Tool schema completeness", "FAIL",
                    f"Tools missing name/valid name: {missing_name or 'none'}. Tools missing inputSchema: {missing_schema or 'none'}.",
                    "Every tool must have a name (1-128 chars) and an inputSchema object.",
                ))
            elif warn_desc:
                results.append(make_result(
                    "CHECK-07", "Tool schema completeness", "WARN",
                    f"Tools missing description: {warn_desc}.",
                    "Add a description to each tool to improve discoverability.",
                ))
            else:
                results.append(make_result(
                    "CHECK-07", "Tool schema completeness", "PASS",
                    f"All {len(tools_list)} tool(s) have name, description, and inputSchema.",
                ))

            # CHECK-08
            bad_schema, no_props = [], []
            for tool in tools_list:
                schema = tool.get("inputSchema", {})
                if not isinstance(schema.get("type"), str):
                    bad_schema.append(tool.get("name", "?"))
                elif not isinstance(schema.get("properties"), dict):
                    no_props.append(tool.get("name", "?"))

            if bad_schema:
                results.append(make_result(
                    "CHECK-08", "inputSchema validity", "FAIL",
                    f"Tools with invalid inputSchema (missing or non-string 'type'): {bad_schema}.",
                    "inputSchema must be a valid JSON Schema object with type: 'object'.",
                ))
            elif no_props:
                results.append(make_result(
                    "CHECK-08", "inputSchema validity", "WARN",
                    f"Tools with no 'properties' defined (accept no parameters): {no_props}.",
                    "Consider adding an empty properties object if the tool intentionally takes no parameters.",
                ))
            else:
                results.append(make_result(
                    "CHECK-08", "inputSchema validity", "PASS",
                    "All tool inputSchemas have type: 'object' and a properties object.",
                ))

        # ── LAYER 3: TOOL CALL BEHAVIOUR ──────────────────────────────────

        skip_tool_calls = tools_failed
        tool_call_skip = "tools/list failed — cannot test tool call behaviour"

        # CHECK-09
        if skip_tool_calls:
            results.append(skipped("CHECK-09", "Unknown tool handling", tool_call_skip))
        else:
            unk_payload = {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "__mcp_probe_nonexistent_tool__", "arguments": {}},
            }
            unk_resp, _, unk_err = await post_jsonrpc(client, url, unk_payload)
            if unk_err or unk_resp is None:
                results.append(make_result(
                    "CHECK-09", "Unknown tool handling", "FAIL",
                    f"Server did not respond. {unk_err or ''}",
                    "Handle calls to unknown tools gracefully by returning a JSON-RPC error.",
                ))
            elif "error" in unk_resp and unk_resp["error"].get("code") in (-32601, -32001):
                results.append(make_result(
                    "CHECK-09", "Unknown tool handling", "PASS",
                    f"Server returned expected error code {unk_resp['error']['code']} for unknown tool.",
                ))
            elif "error" in unk_resp:
                results.append(make_result(
                    "CHECK-09", "Unknown tool handling", "PASS",
                    f"Server returned an error (code {unk_resp['error'].get('code')}) for unknown tool.",
                ))
            elif unk_resp.get("result", {}).get("isError") is True:
                results.append(make_result(
                    "CHECK-09", "Unknown tool handling", "PASS",
                    "Server returned result.isError: true for unknown tool.",
                ))
            else:
                results.append(make_result(
                    "CHECK-09", "Unknown tool handling", "FAIL",
                    "Server returned a success result for a non-existent tool.",
                    "Return a JSON-RPC error (code -32001) or result with isError:true for unknown tools.",
                ))
            if unk_resp:
                all_responses.append(unk_resp)
                id_pairs.append((3, unk_resp.get("id")))

        # CHECK-10 & CHECK-11 & CHECK-12
        if skip_tool_calls:
            results.append(skipped("CHECK-10", "Missing required parameter handling", tool_call_skip))
            results.append(skipped("CHECK-11", "Valid tool call succeeds", tool_call_skip))
            results.append(skipped("CHECK-12", "Tool response content structure", tool_call_skip))
        else:
            # Find a tool with required params for CHECK-10
            tool_with_required = next(
                (t for t in tools_list if t.get("inputSchema", {}).get("required")), None
            )
            if tool_with_required is None:
                results.append(make_result(
                    "CHECK-10", "Missing required parameter handling", "WARN",
                    "No tools with required parameters found — cannot test this behaviour.",
                    "Add at least one tool with required parameters to enable this check.",
                ))
            else:
                mp_payload = {
                    "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                    "params": {"name": tool_with_required["name"], "arguments": {}},
                }
                mp_resp, _, mp_err = await post_jsonrpc(client, url, mp_payload)
                if mp_err or mp_resp is None:
                    results.append(make_result(
                        "CHECK-10", "Missing required parameter handling", "FAIL",
                        "Server did not respond when called with missing required params.",
                        "Return an error when required parameters are omitted.",
                    ))
                elif "error" in mp_resp or mp_resp.get("result", {}).get("isError") is True:
                    results.append(make_result(
                        "CHECK-10", "Missing required parameter handling", "PASS",
                        f"Server correctly rejected call to '{tool_with_required['name']}' with missing required params.",
                    ))
                else:
                    results.append(make_result(
                        "CHECK-10", "Missing required parameter handling", "FAIL",
                        f"Server returned success for '{tool_with_required['name']}' despite missing required params.",
                        "Validate required parameters and return an error if they are missing.",
                    ))

            # CHECK-11: find a tool safe to call with no args
            safe_tool = next(
                (t for t in tools_list if not t.get("inputSchema", {}).get("required")), None
            )
            valid_call_resp = None
            if safe_tool is None:
                results.append(make_result(
                    "CHECK-11", "Valid tool call succeeds", "WARN",
                    "No tool found with no required parameters — skipping safe invocation.",
                    "Consider adding a tool that works with no arguments for easier testing.",
                ))
            else:
                vc_payload = {
                    "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                    "params": {"name": safe_tool["name"], "arguments": {}},
                }
                vc_resp, _, vc_err = await post_jsonrpc(client, url, vc_payload)
                if vc_err or vc_resp is None:
                    results.append(make_result(
                        "CHECK-11", "Valid tool call succeeds", "FAIL",
                        f"Server did not respond when calling '{safe_tool['name']}' with no args. {vc_err or ''}",
                        "Ensure tool calls return a valid result even with empty arguments.",
                    ))
                elif "error" in vc_resp:
                    results.append(make_result(
                        "CHECK-11", "Valid tool call succeeds", "FAIL",
                        f"Server returned an error for '{safe_tool['name']}' called with empty arguments.",
                        "Tools with no required parameters should succeed when called with empty arguments.",
                    ))
                else:
                    content = vc_resp.get("result", {}).get("content", [])
                    if content == []:
                        results.append(make_result(
                            "CHECK-11", "Valid tool call succeeds", "WARN",
                            f"Tool '{safe_tool['name']}' returned an empty content array.",
                            "Consider returning at least one content item even for no-op tools.",
                        ))
                    else:
                        results.append(make_result(
                            "CHECK-11", "Valid tool call succeeds", "PASS",
                            f"Tool '{safe_tool['name']}' returned a valid response with content.",
                        ))
                    valid_call_resp = vc_resp
                    all_responses.append(vc_resp)
                    id_pairs.append((11, vc_resp.get("id")))

            # CHECK-12
            if valid_call_resp is None:
                results.append(make_result(
                    "CHECK-12", "Tool response content structure", "WARN",
                    "No successful tool call was made — cannot verify content structure.",
                    "Ensure at least one tool can be called with no arguments.",
                ))
            else:
                r = valid_call_resp.get("result", {})
                content = r.get("content")
                is_error = r.get("isError")
                if not isinstance(content, list):
                    results.append(make_result(
                        "CHECK-12", "Tool response content structure", "FAIL",
                        "result.content is missing or not an array.",
                        "Tool responses must include result.content as an array.",
                    ))
                elif not isinstance(is_error, bool):
                    results.append(make_result(
                        "CHECK-12", "Tool response content structure", "WARN",
                        "result.isError is missing — should be present and boolean per spec.",
                        "Include result.isError (boolean) in every tool call response.",
                    ))
                else:
                    results.append(make_result(
                        "CHECK-12", "Tool response content structure", "PASS",
                        "Tool response has result.content (array) and result.isError (boolean).",
                    ))

        # ── LAYER 4: ERROR HANDLING QUALITY ───────────────────────────────

        # CHECK-13
        inv_payload = {
            "jsonrpc": "2.0", "id": 4,
            "method": "__mcp_probe_invalid_method__", "params": {},
        }
        inv_resp, _, inv_err = await post_jsonrpc(client, url, inv_payload)
        if inv_err or inv_resp is None:
            results.append(make_result(
                "CHECK-13", "Method not found returns correct error code", "FAIL",
                f"Server did not respond. {inv_err or ''}",
                "Return a -32601 error for unknown methods.",
            ))
        elif "error" in inv_resp:
            code = inv_resp["error"].get("code")
            if code == -32601:
                results.append(make_result(
                    "CHECK-13", "Method not found returns correct error code", "PASS",
                    "Server returned -32601 (Method not found) for an unknown method.",
                ))
            else:
                results.append(make_result(
                    "CHECK-13", "Method not found returns correct error code", "WARN",
                    f"Server returned an error but with code {code} instead of -32601.",
                    "Use error code -32601 for unknown methods per the JSON-RPC 2.0 spec.",
                ))
        else:
            results.append(make_result(
                "CHECK-13", "Method not found returns correct error code", "FAIL",
                "Server returned a success result for an invalid method name.",
                "Return a -32601 error for any method your server does not implement.",
            ))
        if inv_resp:
            all_responses.append(inv_resp)
            id_pairs.append((4, inv_resp.get("id")))

        # CHECK-14: notification (missing id) — fire and forget, should not crash
        status_code, malformed_resp, malformed_err = await post_raw(
            client, url, '{"jsonrpc": "2.0", "method": "tools/list"}'
        )
        if malformed_err == "timeout" or status_code is None:
            results.append(make_result(
                "CHECK-14", "Notification handling", "FAIL",
                "Server did not respond or timed out when sent a JSON-RPC notification (no id field).",
                "Notifications (requests without an id) should be accepted silently — do not crash or hang.",
            ))
        elif status_code and status_code >= 500:
            results.append(make_result(
                "CHECK-14", "Notification handling", "FAIL",
                f"Server returned HTTP {status_code} for a JSON-RPC notification (no id field).",
                "Notifications should be processed without error — return 200/202/204, not 5xx.",
            ))
        else:
            results.append(make_result(
                "CHECK-14", "Notification handling", "PASS",
                f"Server accepted a JSON-RPC notification without error (HTTP {status_code}).",
            ))

        # CHECK-15
        ip_payload = {
            "jsonrpc": "2.0", "id": 5,
            "method": "tools/call", "params": "this_is_a_string_not_an_object",
        }
        ip_resp, _, ip_err = await post_jsonrpc(client, url, ip_payload)
        if ip_err or ip_resp is None:
            results.append(make_result(
                "CHECK-15", "Invalid params error code", "FAIL",
                f"Server did not respond. {ip_err or ''}",
                "Return -32602 when params is not an object.",
            ))
        elif "error" in ip_resp:
            code = ip_resp["error"].get("code")
            if code in (-32602, -32600):
                results.append(make_result(
                    "CHECK-15", "Invalid params error code", "PASS",
                    f"Server returned expected error code {code} for invalid params type.",
                ))
            else:
                results.append(make_result(
                    "CHECK-15", "Invalid params error code", "WARN",
                    f"Server returned an error (code {code}) for invalid params — expected -32602 or -32600.",
                    "Use -32602 (Invalid params) when the params field has the wrong type.",
                ))
        else:
            results.append(make_result(
                "CHECK-15", "Invalid params error code", "FAIL",
                "Server returned a success result when params was a string instead of an object.",
                "Validate that params is an object and return -32602 if not.",
            ))
        if ip_resp:
            all_responses.append(ip_resp)
            id_pairs.append((5, ip_resp.get("id")))

        # ── LAYER 5: RESPONSE HYGIENE ──────────────────────────────────────

        # CHECK-16
        max_time = max(response_times) if response_times else 0
        if max_time <= 3000:
            results.append(make_result(
                "CHECK-16", "Response time baseline", "PASS",
                f"Slowest response: {max_time:.0f}ms (initialize + tools/list both within 3000ms).",
            ))
        elif max_time <= 8000:
            results.append(make_result(
                "CHECK-16", "Response time baseline", "WARN",
                f"Slowest response: {max_time:.0f}ms — between 3000ms and 8000ms.",
                "Investigate slow responses; target under 3000ms for core lifecycle methods.",
            ))
        else:
            results.append(make_result(
                "CHECK-16", "Response time baseline", "FAIL",
                f"Slowest response: {max_time:.0f}ms — exceeds 8000ms threshold.",
                "Reduce response latency; the initialize and tools/list methods must respond quickly.",
            ))

        # CHECK-17: Content-Type — re-issue initialize and inspect raw headers
        ct_pass = True
        ct_missing = False
        ct_detail = ""
        try:
            raw_resp = await client.post(url, json=init_payload, headers=PROBE_HEADERS)
            ct = raw_resp.headers.get("content-type", "")
            if not ct:
                ct_pass = False
                ct_missing = True
                ct_detail = "Content-Type header is missing."
            elif "application/json" not in ct.lower():
                ct_pass = False
                ct_detail = f"Content-Type is '{ct}' — expected application/json."
            else:
                ct_detail = f"Content-Type: {ct}"
        except Exception as e:
            ct_pass = False
            ct_detail = f"Could not verify Content-Type: {e}"

        if ct_pass:
            results.append(make_result(
                "CHECK-17", "Content-Type header", "PASS", ct_detail,
            ))
        elif ct_missing:
            results.append(make_result(
                "CHECK-17", "Content-Type header", "WARN", ct_detail,
                "Set Content-Type: application/json on all JSON-RPC responses.",
            ))
        else:
            results.append(make_result(
                "CHECK-17", "Content-Type header", "FAIL", ct_detail,
                "Return Content-Type: application/json for all JSON-RPC responses.",
            ))

        # CHECK-18: Sensitive data in error messages
        sensitive_hits: list[str] = []
        for resp in all_responses:
            err = resp.get("error", {})
            for field in ("message", "data"):
                val = err.get(field, "")
                if val and isinstance(val, str) and SENSITIVE_PATTERNS.search(val):
                    sensitive_hits.append(f"error.{field}: {val[:120]}")

        if sensitive_hits:
            results.append(make_result(
                "CHECK-18", "No sensitive data in error messages", "WARN",
                f"Potentially sensitive content in error responses: {sensitive_hits[:3]}",
                "Avoid exposing file paths, stack traces, or internal details in error messages.",
            ))
        else:
            results.append(make_result(
                "CHECK-18", "No sensitive data in error messages", "PASS",
                "No file paths, stack traces, or internal details detected in error responses.",
            ))

        # CHECK-04 & CHECK-05 — evaluated after all responses are collected
        bad_jsonrpc = [r for r in all_responses if r.get("jsonrpc") != "2.0"]
        if bad_jsonrpc:
            results.append(make_result(
                "CHECK-04", "JSON-RPC version field", "FAIL",
                f"{len(bad_jsonrpc)} response(s) missing or have wrong jsonrpc field.",
                "Every response must include \"jsonrpc\": \"2.0\".",
            ))
        else:
            results.append(make_result(
                "CHECK-04", "JSON-RPC version field", "PASS",
                "All responses include \"jsonrpc\": \"2.0\".",
            ))

        id_mismatches = []
        for sent_id, recv_id in id_pairs:
            if recv_id != sent_id:
                id_mismatches.append(f"sent {sent_id} → got {recv_id}")
        if id_mismatches:
            results.append(make_result(
                "CHECK-05", "Response ID echo", "FAIL",
                f"ID mismatches: {'; '.join(id_mismatches)}.",
                "Each response must echo back the exact id from the request that triggered it.",
            ))
        else:
            results.append(make_result(
                "CHECK-05", "Response ID echo", "PASS",
                f"All {len(id_pairs)} response(s) echoed the correct request id.",
            ))

    # Sort results by check_id
    results.sort(key=lambda r: r["check_id"])

    audit_duration = int((time.monotonic() - audit_start) * 1000)
    return _build_response(results, server_info, audit_duration)


def _build_response(results: list[dict], server_info: dict, audit_duration: int) -> JSONResponse:
    countable = [r for r in results if r["status"] != "SKIP"]
    skip_count = sum(1 for r in results if r["status"] == "SKIP")
    total = len(countable)
    pass_count = sum(1 for r in countable if r["status"] == "PASS")
    warn_count = sum(1 for r in countable if r["status"] == "WARN")
    fail_count = sum(1 for r in countable if r["status"] == "FAIL")

    score = 0
    if total > 0:
        score = round((pass_count * 1 + warn_count * 0.5) / total * 100)

    tool_check_ids = {"CHECK-09", "CHECK-10", "CHECK-11", "CHECK-12"}
    tool_checks_ran = any(
        r["check_id"] in tool_check_ids and r["status"] != "SKIP"
        for r in results
    )

    if score >= 90 and tool_checks_ran:
        verdict = "COMPLIANT"
    elif score >= 90:
        verdict = "MOSTLY COMPLIANT"
    elif score >= 70:
        verdict = "MOSTLY COMPLIANT"
    elif score >= 50:
        verdict = "PARTIALLY COMPLIANT"
    else:
        verdict = "NON-COMPLIANT"

    return JSONResponse({
        "results": results,
        "score": score,
        "verdict": verdict,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "skip_count": skip_count,
        "total_checks": total,
        "server_info": server_info,
        "audit_duration_ms": audit_duration,
    })
