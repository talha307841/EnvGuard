"""Local dashboard server for EnvGuard."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from envguard.config import get_events_path, load_config


def _read_events(limit: int = 250) -> list[dict[str, Any]]:
    config = load_config()
    events_path = get_events_path(config)
    if not events_path.exists():
        return []

    lines = events_path.read_text(encoding="utf-8").splitlines()
    if limit > 0:
        lines = lines[-limit:]

    events: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(events))


def _summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    total_attempts = len(events)
    saved_you_count = sum(1 for e in events if e.get("saved_you"))
    total_masked_values = sum(int(e.get("masked_count") or 0) for e in events)

    agents = Counter((e.get("agent") or "unknown") for e in events)
    top_agents = [
        {"agent": name, "count": count}
        for name, count in agents.most_common(5)
    ]

    latest = events[0] if events else None
    return {
        "total_attempts": total_attempts,
        "saved_you_count": saved_you_count,
        "total_masked_values": total_masked_values,
        "top_agents": top_agents,
        "latest": latest,
    }


def _format_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def _render_html(events: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    rows: list[str] = []
    for e in events[:80]:
        ts = escape(_format_ts(str(e.get("timestamp", ""))))
        agent = escape(str(e.get("agent", "unknown")))
        event_type = escape(str(e.get("event_type", "")))
        file_path = escape(str(e.get("file_path", "")))
        masked_count = int(e.get("masked_count") or 0)
        status = "PROTECTED" if masked_count > 0 else "SAFE"
        status_class = "status-protected" if masked_count > 0 else "status-safe"

        llm_view_items = e.get("llm_view") or []
        llm_view = "<br>".join(escape(str(item)) for item in llm_view_items[:6])

        rows.append(
            "<tr>"
            f"<td>{ts}</td>"
            f"<td>{agent}</td>"
            f"<td>{event_type}</td>"
            f"<td class='path'>{file_path}</td>"
            f"<td><span class='status {status_class}'>{status}</span></td>"
            f"<td>{masked_count}</td>"
            f"<td class='mono'>{llm_view}</td>"
            "</tr>"
        )

    top_agents_html = "".join(
        f"<li><span>{escape(str(item['agent']))}</span><b>{int(item['count'])}</b></li>"
        for item in summary.get("top_agents", [])
    )

    latest = summary.get("latest") or {}
    latest_text = "No access events yet."
    if latest:
        latest_text = (
            f"{escape(_format_ts(str(latest.get('timestamp', ''))))} | "
            f"{escape(str(latest.get('agent', 'unknown')))} | "
            f"{escape(str(latest.get('file_path', '')))}"
        )

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>EnvGuard Dashboard</title>
  <style>
    :root {{
      --bg: #f8f6ef;
      --panel: #fffdf8;
      --ink: #1d2a2f;
      --muted: #5f6c72;
      --safe: #2f9e44;
      --protect: #f08c00;
      --warn: #d63336;
      --line: #e3ded1;
      --accent: #1f6f8b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
      background: radial-gradient(circle at 20% 0%, #fff8dd 0%, var(--bg) 42%);
      color: var(--ink);
    }}
    .wrap {{ max-width: 1200px; margin: 24px auto; padding: 0 16px 40px; }}
    .head {{ display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px; }}
    .title {{ font-family: 'Avenir Next', 'Trebuchet MS', sans-serif; font-size: 30px; letter-spacing: 0.4px; margin: 0; }}
    .sub {{ color: var(--muted); font-size: 14px; }}

    .cards {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }}
    .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
    .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }}
    .value {{ font-size: 28px; margin-top: 6px; font-weight: 700; }}
    .value.safe {{ color: var(--safe); }}
    .value.protect {{ color: var(--protect); }}

    .grid {{ display: grid; gap: 12px; grid-template-columns: 1.4fr 1fr; margin-top: 12px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
    .panel h3 {{ margin: 0 0 10px; font-size: 16px; }}
    ul {{ margin: 0; padding: 0; list-style: none; }}
    li {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px dashed var(--line); }}
    li:last-child {{ border-bottom: 0; }}

    .table-wrap {{ margin-top: 12px; overflow: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; }}
    table {{ border-collapse: collapse; width: 100%; min-width: 1020px; }}
    th, td {{ border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; padding: 10px; font-size: 13px; }}
    th {{ color: var(--muted); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; position: sticky; top: 0; background: #fffaf0; }}
    .status {{ padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
    .status-safe {{ background: #e6fcf0; color: var(--safe); }}
    .status-protected {{ background: #fff4e6; color: var(--protect); }}
    .path {{ max-width: 280px; word-break: break-all; }}
    .mono {{ font-family: 'IBM Plex Mono', 'Consolas', monospace; white-space: pre-wrap; }}

    .foot {{ margin-top: 10px; color: var(--muted); font-size: 12px; }}

    @media (max-width: 980px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .title {{ font-size: 24px; }}
    }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"head\">
      <h1 class=\"title\">EnvGuard Dashboard</h1>
      <div class=\"sub\">Local-only monitor for coding-agent .env access attempts</div>
    </div>

    <div class=\"cards\">
      <div class=\"card\">
        <div class=\"label\">Total Attempts</div>
        <div class=\"value\">{int(summary.get('total_attempts', 0))}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Times EnvGuard Saved You</div>
        <div class=\"value protect\">{int(summary.get('saved_you_count', 0))}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Masked Secret Values</div>
        <div class=\"value safe\">{int(summary.get('total_masked_values', 0))}</div>
      </div>
    </div>

    <div class=\"grid\">
      <div class=\"panel\">
        <h3>Latest Access</h3>
        <div class=\"mono\">{latest_text}</div>
      </div>
      <div class=\"panel\">
        <h3>Top Agents</h3>
        <ul>{top_agents_html or '<li><span>none</span><b>0</b></li>'}</ul>
      </div>
    </div>

    <div class=\"table-wrap\">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Agent</th>
            <th>Event</th>
            <th>Target File</th>
            <th>Status</th>
            <th>Masked</th>
            <th>What LLM Saw</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows) or '<tr><td colspan="7">No events yet</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class=\"foot\">Auto-refresh every 3 seconds.</div>
  </div>
  <script>
    setTimeout(function () {{ window.location.reload(); }}, 3000);
  </script>
</body>
</html>
"""


class _DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        events = _read_events(limit=250)
        summary = _summarize(events)

        if self.path == "/api/events":
            self._send_json({"events": events})
            return

        if self.path == "/api/summary":
            self._send_json(summary)
            return

        self._send_html(_render_html(events, summary))

    def log_message(self, format: str, *args) -> None:
        return


def serve_dashboard(host: str, port: int) -> None:
    """Run the local dashboard server until interrupted."""
    server = ThreadingHTTPServer((host, port), _DashboardHandler)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
