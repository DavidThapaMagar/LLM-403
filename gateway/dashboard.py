"""
Security Dashboard.

Generates a single self-contained HTML file summarizing everything in
the security event log. The full event history is embedded as JSON,
and vanilla JS handles filtering/search/rendering client-side - no
server needed, still just one HTML file to open.

Click any resource in the Events table (or the Most Frequently
Blocked Resources table) to see what it is - a known attack file's
actual content (read live from disk), a description, and an
attack-type tag - auto-classified for anything not in the known list.

Click any Task ID in the Events table to see that task's full
chronological trace - every action it took, allowed or blocked, with
reasons - like gateway/trace.py, but inline in the browser.

sandbox/secrets.txt content is deliberately never embedded or shown,
even though it could be read - the whole point of this lab is
preventing that file from leaking, so the dashboard itself shouldn't
be a way to leak it.

Usage (from repo root):
    python -m gateway.dashboard

Then open logs/dashboard.html in a browser.
"""

import json
import os
import webbrowser
from collections import defaultdict
from datetime import datetime, timezone

from .events import LOG_FILE, LOG_DIR

DASHBOARD_FILE = os.path.join(LOG_DIR, "dashboard.html")

RISK_LABELS = {1: "LOW", 2: "MEDIUM", 3: "HIGH", None: "UNKNOWN"}

SECRET_PATH = "sandbox/secrets.txt"

# kind: "legit" | "attack" | "target"
FILE_DESCRIPTIONS = {
    "sandbox/notes.txt": (
        "legit", "Sandbox Notes",
        "Standard sandbox file used for legitimate reads and writes. "
        "The home base for non-adversarial tasks."
    ),
    "sandbox/secrets.txt": (
        "target", "Target Resource",
        "The protected secret file. Every exfiltration attempt in this "
        "lab is trying to reach this file."
    ),
    "attacks/malicious_notes.txt": (
        "attack", "Indirect Prompt Injection",
        "A planted note that tries to convince the agent to take an "
        "unauthorized action."
    ),
    "attacks/malicious_notes_v2.txt": (
        "attack", "Indirect Prompt Injection (direct ask)",
        "Variant that asks directly for the secret file's contents."
    ),
    "attacks/malicious_notes_v3.txt": (
        "attack", "Command Injection via Prompt Injection",
        "Tries to get the agent to run a shell command that reaches "
        "the secret."
    ),
    "attacks/malicious_notes_v4.txt": (
        "attack", "Stored / Persistent Prompt Injection",
        "Plants an instruction inside a written file to trigger on a "
        "later read."
    ),
    "attacks/malicious_notes_v5.txt": (
        "attack", "Social-Engineering Injection",
        "A softer, more persuasive phrasing of a direct ask."
    ),
    "attacks/malicious_notes_v6.txt": (
        "attack", "Maximally Naturalised Injection",
        "Frames the request as an implied prior agreement, with no "
        "explicit ask."
    ),
    "attacks/malicious_notes_v7a.txt": (
        "attack", "Multi-Step Trajectory (Step 1)",
        "Soft redirect - points to a second file as optional extra "
        "reading."
    ),
    "attacks/malicious_notes_v7b.txt": (
        "attack", "Multi-Step Trajectory (Step 2)",
        "Escalates the chain by framing a read of the secret file as a "
        "routine 'checklist' step."
    ),
    "attacks/malicious_notes_v7c.txt": (
        "attack", "Fused Exfiltration",
        "Bundles the malicious ask into a legitimate save action - no "
        "second file needed."
    ),
    "echo hello": (
        "legit", "Baseline Allowed Command",
        "The only command in the global allow-list. Used as a control "
        "case for command-related tests."
    ),
}


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


def load_resource_info():
    info = {}
    for resource, (kind, label, description) in FILE_DESCRIPTIONS.items():
        entry = {"kind": kind, "label": label, "description": description}
        looks_like_file = "/" in resource
        if looks_like_file and resource != SECRET_PATH:
            try:
                with open(resource) as f:
                    entry["content"] = f.read()[:3000]
            except OSError:
                pass
        elif resource == SECRET_PATH:
            entry["content_hidden"] = True
        info[resource] = entry
    return info


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

    events_for_js = sorted(events, key=lambda e: e["timestamp"], reverse=True)[:1000]
    events_json = json.dumps(events_for_js).replace("</", "<\\/")

    resource_info = load_resource_info()
    resource_info_json = json.dumps(resource_info).replace("</", "<\\/")

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
        <h2>Most Frequently Blocked Resources <span class="hint">(click a row)</span></h2>
        <table>
          <thead><tr><th>Count</th><th>Resource</th></tr></thead>
          <tbody id="blocked-resources-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="panel wide">
      <h2>Events <span class="hint">(click a Task ID for its trace, or a resource for details)</span></h2>
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

    <div id="resource-modal" class="modal-overlay" style="display:none;">
      <div class="modal-card">
        <button class="modal-close" id="modal-close-btn">&times;</button>
        <div class="modal-resource mono" id="modal-resource"></div>
        <div id="modal-badge-row"></div>
        <p id="modal-description"></p>
        <div id="modal-content-wrap" style="display:none;">
          <h3>File Contents</h3>
          <pre id="modal-content"></pre>
        </div>
      </div>
    </div>

    <div id="trace-modal" class="modal-overlay" style="display:none;">
      <div class="modal-card wide-card">
        <button class="modal-close" id="trace-modal-close-btn">&times;</button>
        <div class="trace-header">
          <div class="trace-title" id="trace-title"></div>
          <div class="trace-meta" id="trace-meta"></div>
        </div>
        <div class="trace-steps" id="trace-steps"></div>
        <div class="trace-summary" id="trace-summary"></div>
      </div>
    </div>

    <script id="events-data" type="application/json">{events_json}</script>
    <script id="resource-info-data" type="application/json">{resource_info_json}</script>
    <script>
    (function() {{
      const RISK_LABELS = {{1: "LOW", 2: "MEDIUM", 3: "HIGH"}};
      const RISK_COLORS = {{1: "#3fb950", 2: "#d29922", 3: "#f85149"}};
      const KIND_COLORS = {{attack: "#f85149", legit: "#3fb950", target: "#d29922", unknown: "#8b949e"}};

      const events = JSON.parse(document.getElementById('events-data').textContent);
      const resourceInfo = JSON.parse(document.getElementById('resource-info-data').textContent);

      const workTypeSelect = document.getElementById('filter-work-type');
      const decisionSelect = document.getElementById('filter-decision');
      const riskSelect = document.getElementById('filter-risk');
      const searchInput = document.getElementById('filter-search');
      const countLabel = document.getElementById('filter-count');
      const eventsTbody = document.getElementById('events-tbody');
      const blockedTbody = document.getElementById('blocked-resources-tbody');

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

      // --- Attack classification for resources not in the known list ---
      function classify(resource) {{
        if (resource === null || resource === undefined) {{
          return {{kind: "attack", label: "Adversarial Argument", description: "None/null was passed where a string was expected — tests whether the gateway crashes or cleanly denies malformed input."}};
        }}
        if (typeof resource !== 'string') {{
          return {{kind: "attack", label: "Adversarial Argument", description: "A non-string value (list, dict, or number) was passed — tests type validation."}};
        }}
        if (resource === '') {{
          return {{kind: "attack", label: "Adversarial Argument", description: "An empty string was passed as the resource — tests handling of degenerate input."}};
        }}
        if (resource.length > 200) {{
          return {{kind: "attack", label: "Oversized Input", description: "A very long payload — tests for resource exhaustion or a missing length limit."}};
        }}
        if (resource.toLowerCase().includes('secret')) {{
          return {{kind: "attack", label: "Secret Exfiltration Attempt", description: "Directly names or targets the protected secret file."}};
        }}
        if (resource.includes('../') || resource.startsWith('./')) {{
          return {{kind: "attack", label: "Path Traversal", description: "Attempts to escape the sandbox using directory traversal segments."}};
        }}
        if (/\\u0000/.test(resource)) {{
          return {{kind: "attack", label: "Null Byte Injection", description: "Embeds a null byte — a classic string-truncation / validation-bypass trick."}};
        }}
        if (/[\\uFF00-\\uFFEF]/.test(resource)) {{
          return {{kind: "attack", label: "Unicode Homoglyph", description: "Uses a full-width lookalike character to evade exact-string filtering."}};
        }}
        if (resource.includes(';') || resource.includes('&&') || resource.includes('|')) {{
          return {{kind: "attack", label: "Command Injection", description: "Attempts to chain a second command using a shell metacharacter."}};
        }}
        if (resource !== resource.trim()) {{
          return {{kind: "attack", label: "Whitespace Variant", description: "Leading or trailing whitespace added to try to slip past an exact-match allow-list."}};
        }}
        if (resource === resource.toUpperCase() && resource !== resource.toLowerCase()) {{
          return {{kind: "attack", label: "Case Variant", description: "An all-uppercase variant of a path — tests case-sensitive matching."}};
        }}
        return {{kind: "unknown", label: null, description: "No known attack pattern matched. Likely a legitimate resource."}};
      }}

      function getResourceInfo(resource) {{
        if (resource !== null && resource !== undefined && Object.prototype.hasOwnProperty.call(resourceInfo, resource)) {{
          return Object.assign({{known: true}}, resourceInfo[resource]);
        }}
        return Object.assign({{known: false}}, classify(resource));
      }}

      // --- Resource modal ---
      function openModal(resource) {{
        const info = getResourceInfo(resource);
        const displayResource = (resource === null || resource === undefined) ? '(none)' : String(resource);

        document.getElementById('modal-resource').textContent = displayResource;

        const badgeRow = document.getElementById('modal-badge-row');
        badgeRow.innerHTML = '';
        if (info.label) {{
          const badge = document.createElement('span');
          badge.className = 'attack-badge';
          badge.style.background = (KIND_COLORS[info.kind] || '#8b949e') + '22';
          badge.style.color = KIND_COLORS[info.kind] || '#8b949e';
          badge.style.borderColor = (KIND_COLORS[info.kind] || '#8b949e') + '55';
          badge.textContent = info.label;
          badgeRow.appendChild(badge);
        }}

        document.getElementById('modal-description').textContent = info.description || 'No description available.';

        const contentWrap = document.getElementById('modal-content-wrap');
        const contentEl = document.getElementById('modal-content');
        if (info.content) {{
          contentEl.textContent = info.content;
          contentWrap.style.display = 'block';
        }} else if (info.content_hidden) {{
          contentEl.textContent = '🔒 Contents intentionally not shown — this is the file every attack in this lab tries to reach.';
          contentWrap.style.display = 'block';
        }} else {{
          contentWrap.style.display = 'none';
        }}

        document.getElementById('resource-modal').style.display = 'flex';
      }}

      function closeModal() {{
        document.getElementById('resource-modal').style.display = 'none';
      }}

      document.getElementById('modal-close-btn').addEventListener('click', closeModal);
      document.getElementById('resource-modal').addEventListener('click', (e) => {{
        if (e.target.id === 'resource-modal') closeModal();
      }});

      // --- Trace modal ---
      function openTraceModal(taskId) {{
        const taskEvents = events
          .filter(e => e.task_id === taskId)
          .slice()
          .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
        if (taskEvents.length === 0) return;

        const first = taskEvents[0];
        document.getElementById('trace-title').textContent = `Task ${{taskId}}`;
        document.getElementById('trace-meta').textContent =
          `${{first.agent_name}} · work_type=${{first.work_type}} · ${{taskEvents.length}} event(s)`;

        const stepsEl = document.getElementById('trace-steps');
        stepsEl.innerHTML = '';
        taskEvents.forEach((e, i) => {{
          const div = document.createElement('div');
          div.className = 'trace-step';
          const marker = e.decision === 'allowed' ? 'OK' : 'BLOCKED';
          const markerColor = e.decision === 'allowed' ? '#3fb950' : '#f85149';
          const resourceDisplay = truncateStr(e.resource, 40);
          div.innerHTML = `
            <div class="trace-step-num">${{i + 1}}</div>
            <div>step ${{e.step}}</div>
            <div style="color:${{markerColor}}; font-weight:600;">${{marker}}</div>
            <div>${{e.action}}: <code>${{escapeHtml(resourceDisplay)}}</code></div>
            <div><span class="risk-pill" style="background:${{riskColor(e.risk_level)}}22; color:${{riskColor(e.risk_level)}};">${{riskLabel(e.risk_level)}}</span></div>
            <div class="mono" style="text-align:right;">${{(e.timestamp.split('T')[1]||'').split('.')[0]}}</div>
          `;
          stepsEl.appendChild(div);
          if (e.decision === 'blocked') {{
            const reasonDiv = document.createElement('div');
            reasonDiv.className = 'trace-step-reason';
            reasonDiv.textContent = 'reason: ' + e.reason;
            stepsEl.appendChild(reasonDiv);
          }}
        }});

        const allowedCount = taskEvents.filter(e => e.decision === 'allowed').length;
        const blockedCount = taskEvents.length - allowedCount;
        document.getElementById('trace-summary').textContent =
          `Summary: ${{allowedCount}} allowed, ${{blockedCount}} blocked`;

        document.getElementById('trace-modal').style.display = 'flex';
      }}

      function closeTraceModal() {{
        document.getElementById('trace-modal').style.display = 'none';
      }}

      document.getElementById('trace-modal-close-btn').addEventListener('click', closeTraceModal);
      document.getElementById('trace-modal').addEventListener('click', (e) => {{
        if (e.target.id === 'trace-modal') closeTraceModal();
      }});

      document.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape') {{ closeModal(); closeTraceModal(); }}
      }});

      // --- Events table ---
      let currentFiltered = [];

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

        currentFiltered = filtered.slice(0, 200);
        eventsTbody.innerHTML = '';

        if (currentFiltered.length === 0) {{
          eventsTbody.innerHTML = '<tr><td colspan="7" class="empty">No matching events</td></tr>';
        }} else {{
          currentFiltered.forEach((e, idx) => {{
            const tr = document.createElement('tr');
            const tsShort = (e.timestamp.split('T')[1] || '').split('.')[0];
            tr.innerHTML = `
              <td class="mono">${{tsShort}}</td>
              <td class="mono"><span class="task-cell" data-task-id="${{escapeHtml(e.task_id)}}">${{escapeHtml(e.task_id)}}</span></td>
              <td>${{e.work_type}}</td>
              <td>${{e.action}}</td>
              <td><code class="resource-cell" data-idx="${{idx}}">${{escapeHtml(truncateStr(e.resource))}}</code></td>
              <td><span class="risk-pill" style="background:${{riskColor(e.risk_level)}}22; color:${{riskColor(e.risk_level)}};">${{riskLabel(e.risk_level)}}</span></td>
              <td><span class="decision-pill ${{e.decision}}">${{e.decision.toUpperCase()}}</span></td>
            `;
            eventsTbody.appendChild(tr);
          }});
        }}

        countLabel.textContent = `Showing ${{currentFiltered.length}} of ${{filtered.length}} matching (${{events.length}} total)`;
      }}

      eventsTbody.addEventListener('click', (ev) => {{
        const taskCell = ev.target.closest('.task-cell');
        if (taskCell) {{
          openTraceModal(taskCell.dataset.taskId);
          return;
        }}
        const resCell = ev.target.closest('.resource-cell');
        if (resCell) {{
          const idx = parseInt(resCell.dataset.idx, 10);
          const item = currentFiltered[idx];
          if (item) openModal(item.resource);
        }}
      }});

      [workTypeSelect, decisionSelect, riskSelect].forEach(el => el.addEventListener('change', render));
      searchInput.addEventListener('input', render);

      // --- Most Frequently Blocked Resources (rendered from full history, not filtered) ---
      let topBlockedList = [];

      function renderBlockedResources() {{
        const counts = {{}};
        events.forEach(e => {{
          if (e.decision === 'blocked') {{
            const key = (e.resource === null || e.resource === undefined) ? '(none)' : e.resource;
            counts[key] = (counts[key] || 0) + 1;
          }}
        }});
        topBlockedList = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);

        blockedTbody.innerHTML = '';
        if (topBlockedList.length === 0) {{
          blockedTbody.innerHTML = '<tr><td colspan="2" class="empty">No blocked resources yet</td></tr>';
          return;
        }}
        topBlockedList.forEach(([resource, count], idx) => {{
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>${{count}}</td>
            <td><code class="resource-cell" data-blocked-idx="${{idx}}">${{escapeHtml(truncateStr(resource))}}</code></td>
          `;
          blockedTbody.appendChild(tr);
        }});
      }}

      blockedTbody.addEventListener('click', (ev) => {{
        const cell = ev.target.closest('.resource-cell');
        if (!cell) return;
        const idx = parseInt(cell.dataset.blockedIdx, 10);
        const item = topBlockedList[idx];
        if (item) openModal(item[0]);
      }});

      render();
      renderBlockedResources();
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
  h1 {{ margin: 0; font-size: 22px; color: #fff; }}
  .generated {{ color: var(--muted); font-size: 13px; }}
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
  .card-value {{ font-size: 30px; font-weight: 700; color: #fff; }}
  .card-label {{
    font-size: 12px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.05em; margin-top: 4px;
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
    font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--muted); margin: 0 0 14px 0;
  }}
  .panel h2 .hint {{
    text-transform: none; letter-spacing: normal; font-weight: 400;
    color: #6e7681; font-size: 12px;
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
    display: flex; height: 14px; border-radius: 4px;
    overflow: hidden; background: #21262d;
  }}
  .bar-count {{ color: var(--muted); text-align: right; }}

  .filters {{
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 14px; flex-wrap: wrap;
  }}
  .filters select, .filters input {{
    background: #0d1117; border: 1px solid var(--border); color: var(--text);
    border-radius: 6px; padding: 6px 10px; font-size: 13px;
  }}
  .filters input {{ flex: 1; min-width: 160px; }}
  .filter-count {{ color: var(--muted); font-size: 12px; margin-left: auto; }}

  table {{
    width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed;
  }}
  th {{
    text-align: left; color: var(--muted); font-weight: 500;
    text-transform: uppercase; font-size: 11px; letter-spacing: 0.04em;
    padding: 8px 10px; border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; overflow: hidden; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{
    background: #21262d; padding: 2px 6px; border-radius: 4px;
    font-size: 12px; color: #79c0ff; display: inline-block; max-width: 100%;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom;
  }}
  .resource-cell, .task-cell {{ cursor: pointer; }}
  .resource-cell:hover {{ background: #30363d; text-decoration: underline; }}
  .task-cell:hover {{ color: var(--accent); text-decoration: underline; }}
  .mono {{ font-family: "SF Mono", Consolas, monospace; color: var(--muted); }}
  .risk-pill, .decision-pill {{
    padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600;
  }}
  .decision-pill.allowed {{ background: #3fb95022; color: var(--green); }}
  .decision-pill.blocked {{ background: #f8514922; color: var(--red); }}
  .empty {{ color: var(--muted); text-align: center; padding: 20px; }}

  .modal-overlay {{
    position: fixed; inset: 0; background: rgba(0,0,0,0.65);
    align-items: center; justify-content: center; z-index: 1000; padding: 20px;
  }}
  .modal-card {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 24px; max-width: 640px; width: 100%; max-height: 80vh;
    overflow-y: auto; position: relative;
  }}
  .modal-card.wide-card {{ max-width: 760px; }}
  .modal-close {{
    position: absolute; top: 10px; right: 14px; background: none; border: none;
    color: var(--muted); font-size: 22px; cursor: pointer; line-height: 1;
  }}
  .modal-close:hover {{ color: var(--text); }}
  .modal-resource {{
    font-size: 13px; background: #0d1117; border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px; margin-bottom: 12px;
    word-break: break-all; color: #79c0ff;
  }}
  .attack-badge {{
    display: inline-block; border: 1px solid; padding: 3px 10px;
    border-radius: 12px; font-size: 12px; font-weight: 600; margin-bottom: 12px;
  }}
  #modal-description {{ color: var(--text); font-size: 14px; line-height: 1.5; margin: 0 0 4px 0; }}
  #modal-content-wrap h3 {{ font-size: 12px; text-transform: uppercase; color: var(--muted); margin: 16px 0 8px 0; }}
  #modal-content-wrap pre {{
    background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
    padding: 12px; font-size: 12px; white-space: pre-wrap; word-break: break-word;
    max-height: 240px; overflow-y: auto; color: var(--text); margin: 0;
  }}

  .trace-title {{ font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 4px; }}
  .trace-meta {{ color: var(--muted); font-size: 12px; }}
  .trace-steps {{ display: flex; flex-direction: column; gap: 8px; margin: 16px 0; }}
  .trace-step {{
    display: grid;
    grid-template-columns: 22px 56px 66px 1fr 66px 74px;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 6px;
    background: #0d1117;
    border: 1px solid var(--border);
    font-size: 12px;
  }}
  .trace-step-num {{ color: var(--muted); font-weight: 600; text-align: center; }}
  .trace-step-reason {{
    color: var(--red); font-size: 11px; padding-left: 36px; margin-top: -6px;
  }}
  .trace-summary {{
    color: var(--muted); font-size: 13px; border-top: 1px solid var(--border);
    padding-top: 12px; margin-top: 4px;
  }}
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
