"""
Security Dashboard.

Generates a single self-contained HTML file summarizing everything in
the security event log - the same data metrics.py and trace.py read,
rendered as an interactive report. The full event history is embedded
as JSON in the page, and vanilla JS handles filtering/search/rendering
client-side - no server needed, still just one HTML file to open.

Usage (from repo root):
    python -m gateway.dashboard

Then open logs/dashboard.html in a browser.
"""

import json
import os
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .events import LOG_FILE, LOG_DIR

DASHBOARD_FILE = os.path.join(LOG_DIR, "dashboard.html")

RISK_LABELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", None: "UNKNOWN"}
RISK_COLORS = {1: "#3fb950", 2: "#d29922", 3: "#f85149", None: "#8b949e"}

MAX_EMBEDDED_EVENTS = 1000


def load_events():
    events = []
    try:
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except FileNotFoundError:
        pass
    return events


def truncate(s, n=60):
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def bar_row(label, allowed, blocked, color_allowed="#3fb950", color_blocked="#f85149"):
    total = allowed + blocked
    if total == 0:
        return ""
    pct_allowed = allowed / total * 100
    pct_blocked = blocked / total * 100
    return f"""
    <div class="bar-row">
      <div class="bar-label">{label}</div>
      <div class="bar-track">
        <div class="bar-segment" style="width:{pct_allowed:.1f}%; background:{color_allowed};"
             title="{allowed} allowed"></div>
        <div class="bar-segment" style="width:{pct_blocked:.1f}%; background:{color_blocked};"
             title="{blocked} blocked"></div>
      </div>
      <div class="bar-count">{allowed} / {blocked}</div>
    </div>
    """


def build_html(events):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not events:
        body = "<p class='empty'>No events logged yet. Run some gateway calls first.</p>"
        return HTML_TEMPLATE.format(generated_at=generated_at, body=body)

    total = len(events)
    allowed = sum(1 for e in events if e["decision"] == "allowed")
    blocked = total - allowed
    block_rate = blocked / total * 100
    unique_tasks = len(set(e["task_id"] for e in events))

    by_action = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_action[e["action"]][e["decision"]] += 1

    by_risk = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_risk[e["risk_level"]][e["decision"]] += 1

    by_work = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in events:
        by_work[e["work_type"]][e["decision"]] += 1

    blocked_resources = Counter(
        e["resource"] for e in events if e["decision"] == "blocked"
    )

    action_bars = "".join(
        bar_row(action, c["allowed"], c["blocked"])
        for action, c in sorted(by_action.items())
    )

    risk_bars = "".join(
        bar_row(RISK_LABELS.get(r, str(r)), c["allowed"], c["blocked"])
        for r, c in sorted(by_risk.items(), key=lambda kv: (kv[0] is None, kv[0]))
    )

    work_bars = "".join(
        bar_row(wt, c["allowed"], c["blocked"])
        for wt, c in sorted(by_work.items())
    )

    blocked_rows = "".join(
        f"<tr><td>{count}</td><td><code title=\"{truncate(resource, 300)}\">{truncate(resource)}</code></td></tr>"
        for resource, count in blocked_resources.most_common(10)
    ) or "<tr><td colspan='2' class='empty'>No blocked resources yet</td></tr>"

    events_for_js = sorted(events, key=lambda e: e["timestamp"], reverse=True)[:MAX_EMBEDDED_EVENTS]
    events_json = json.dumps(events_for_js).replace("</", "<\\/")

    body = f"""
    <div class="cards">
      <div class="card">
        <div class="card-value">{total}</div>
        <div class="card-label">Total Events</div>
      </div>
      <div class="card">
        <div class="card-value">{unique_tasks}</div>
        <div class="card-label">Unique Tasks</div>
      </div>
      <div class="card allowed-card">
        <div class="card-value">{allowed}</div>
        <div class="card-label">Allowed</div>
      </div>
      <div class="card blocked-card">
        <div class="card-value">{blocked}</div>
        <div class="card-label">Blocked</div>
      </div>
      <div class="card">
        <div class="card-value">{block_rate:.0f}%</div>
        <div class="card-label">Block Rate</div>
      </div>
    </div>

    <div class="panels">
      <div class="panel">
        <h2>By Action Type</h2>
        {action_bars}
      </div>
      <div class="panel">
        <h2>By Risk Level</h2>
        {risk_bars}
      </div>
      <div class="panel">
        <h2>By Work Type</h2>
        {work_bars}
      </div>
    </div>

    <div class="panels">
      <div class="panel">
        <h2>Most Frequently Blocked Resources</h2>
        <table>
          <thead><tr><th>Count</th><th>Resource</th></tr></thead>
          <tbody>{blocked_rows}</tbody>
        </table>
      </div>
    </div>

    <div class="panel wide">
      <h2>Events</h2>
      <div class="filters">
        <select id="filter-work-type" autocomplete="off">
          <option value="">All Work Types</option>
        </select>
        <select id="filter-decision" autocomplete="off">
          <option value="">All Decisions</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
        </select>
        <select id="filter-risk" autocomplete="off">
          <option value="">All Risk Levels</option>
          <option value="1">Low</option>
          <option value="2">Medium</option>
          <option value="3">High</option>
        </select>
        <input id="filter-search" type="text" placeholder="Search resource..." autocomplete="off">
        <span id="filter-count" class="filter-count"></span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Task</th><th>Work Type</th><th>Action</th>
            <th>Resource</th><th>Risk</th><th>Decision</th>
          </tr>
        </thead>
        <tbody id="events-tbody"></tbody>
      </table>
    </div>

    <script id="events-data" type="application/json">{events_json}</script>
    <script>
    (function() {{
      const RISK_LABELS = {{1: "LOW", 2: "MEDIUM", 3: "HIGH"}};
      const RISK_COLORS = {{1: "#3fb950", 2: "#d29922", 3: "#f85149"}};

      const events = JSON.parse(document.getElementById('events-data').textContent);

      const workTypeSelect = document.getElementById('filter-work-type');
      const decisionSelect = document.getElementById('filter-decision');
      const riskSelect = document.getElementById('filter-risk');
      const searchInput = document.getElementById('filter-search');
      const countLabel = document.getElementById('filter-count');
      const tbody = document.getElementById('events-tbody');

      workTypeSelect.value = "";
      decisionSelect.value = "";
      riskSelect.value = "";
      searchInput.value = "";

      const workTypes = Array.from(new Set(events.map(e => e.work_type))).filter(Boolean).sort();
      workTypes.forEach(wt => {{
        const opt = document.createElement('option');
        opt.value = wt;
        opt.textContent = wt;
        workTypeSelect.appendChild(opt);
      }});

      function riskLabel(r) {{ return RISK_LABELS[r] || 'UNKNOWN'; }}
      function riskColor(r) {{ return RISK_COLORS[r] || '#8b949e'; }}

      function escapeHtml(str) {{
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
      }}

      function truncateStr(val, n) {{
        n = n || 60;
        const str = (val === null || val === undefined) ? '(none)' : String(val);
        return str.length <= n ? str : str.slice(0, n) + '…';
      }}

      function render() {{
        const wt = workTypeSelect.value;
        const decision = decisionSelect.value;
        const risk = riskSelect.value;
        const search = searchInput.value.trim().toLowerCase();

        const filtered = events.filter(e => {{
          if (wt && e.work_type !== wt) return false;
          if (decision && e.decision !== decision) return false;
          if (risk && String(e.risk_level) !== risk) return false;
          if (search && !String(e.resource || '').toLowerCase().includes(search)) return false;
          return true;
        }});

        tbody.innerHTML = '';
        if (filtered.length === 0) {{
          tbody.innerHTML = '<tr><td colspan="7" class="empty">No matching events</td></tr>';
        }} else {{
          filtered.slice(0, 200).forEach(e => {{
            const tr = document.createElement('tr');
            const tsShort = (e.timestamp.split('T')[1] || '').split('.')[0];
            const fullResource = (e.resource === null || e.resource === undefined) ? '(none)' : String(e.resource);
            tr.innerHTML = `
              <td class="mono">${{tsShort}}</td>
              <td class="mono">${{e.task_id}}</td>
              <td>${{e.work_type}}</td>
              <td>${{e.action}}</td>
              <td><code title="${{escapeHtml(fullResource)}}">${{escapeHtml(truncateStr(e.resource))}}</code></td>
              <td><span class="risk-pill" style="background:${{riskColor(e.risk_level)}}22; color:${{riskColor(e.risk_level)}};">${{riskLabel(e.risk_level)}}</span></td>
              <td><span class="decision-pill ${{e.decision}}">${{e.decision.toUpperCase()}}</span></td>
            `;
            tbody.appendChild(tr);
          }});
        }}

        countLabel.textContent = `Showing ${{Math.min(filtered.length, 200)}} of ${{filtered.length}} matching (${{events.length}} total)`;
      }}

      [workTypeSelect, decisionSelect, riskSelect].forEach(el => el.addEventListener('change', render));
      searchInput.addEventListener('input', render);

      render();
    }})();
    </script>
    """

    return HTML_TEMPLATE.format(generated_at=generated_at, body=body)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LLM403</title>
<style>
  :root {{
    --bg: #0d1117;
    --panel: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --muted: #8b949e;
    --accent: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 32px;
  }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 24px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
  }}
  h1 {{
    margin: 0;
    font-size: 22px;
    color: #fff;
  }}
  .generated {{
    color: var(--muted);
    font-size: 13px;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 28px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px;
    text-align: center;
  }}
  .card-value {{
    font-size: 30px;
    font-weight: 700;
    color: #fff;
  }}
  .card-label {{
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 4px;
  }}
  .allowed-card .card-value {{ color: var(--green); }}
  .blocked-card .card-value {{ color: var(--red); }}

  .panels {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 16px;
  }}
  .panel {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px;
  }}
  .panel.wide {{ grid-column: 1 / -1; }}
  .panel h2 {{
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 0 0 14px 0;
  }}

  .bar-row {{
    display: grid;
    grid-template-columns: 90px 1fr 70px;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    font-size: 13px;
  }}
  .bar-label {{ color: var(--text); text-transform: capitalize; }}
  .bar-track {{
    display: flex;
    height: 14px;
    border-radius: 4px;
    overflow: hidden;
    background: #21262d;
  }}
  .bar-count {{ color: var(--muted); text-align: right; }}

  .filters {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
    flex-wrap: wrap;
  }}
  .filters select, .filters input {{
    background: #0d1117;
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
  }}
  .filters input {{ flex: 1; min-width: 160px; }}
  .filter-count {{ color: var(--muted); font-size: 12px; margin-left: auto; }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    table-layout: fixed;
  }}
  th {{
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.04em;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 8px 10px;
    border-bottom: 1px solid #21262d;
    overflow: hidden;
  }}
  tr:last-child td {{ border-bottom: none; }}
  code {{
    background: #21262d;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
    color: #79c0ff;
    display: inline-block;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    vertical-align: bottom;
  }}
  .mono {{ font-family: "SF Mono", Consolas, monospace; color: var(--muted); }}
  .risk-pill, .decision-pill {{
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
  }}
  .decision-pill.allowed {{ background: #3fb95022; color: var(--green); }}
  .decision-pill.blocked {{ background: #f8514922; color: var(--red); }}
  .empty {{ color: var(--muted); text-align: center; padding: 20px; }}
</style>
</head>
<body>
<header>
  <h1>LLM403</h1>
  <div class="generated">Generated {generated_at}</div>
</header>
{body}
</body>
</html>
"""


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    events = load_events()
    html = build_html(events)

    with open(DASHBOARD_FILE, "w") as f:
        f.write(html)

    print(f"Dashboard written to {DASHBOARD_FILE}")

    try:
        webbrowser.open(f"file://{os.path.abspath(DASHBOARD_FILE)}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
