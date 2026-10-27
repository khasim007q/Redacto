"""Read-only HTML report for one revocation request (spec §13).

One self-contained page: stores, lineage, plan preview, execution timeline and
receipt. Like receipts, it holds ids, labels, counts and redacted reasons, never
record content. Every value is HTML-escaped.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

from redacto.engine import Engine
from redacto.errors import RedactoError
from redacto.policy import classify

# Status words carry their meaning in text; colour only reinforces it, and
# nothing short of a verified state is green.
_TONE = {
    "VERIFIED_WITHIN_SCOPE": "ok",
    "success": "ok",
    "verified": "ok",
    "reachable": "ok",
    "done": "ok",
    "DELETE_RECORD": "act",
    "REDACT_SPAN": "act",
    "INVALIDATE_INDEX": "act",
    "INVALIDATE_CACHE": "act",
    "already_absent": "muted",
    "SKIP_PRESERVE": "muted",
    "preserved": "muted",
    "dry_run": "muted",
}


def _badge(value: Any) -> str:
    text = str(value if value is not None else "")
    tone = _TONE.get(text, "warn")
    return f'<span class="badge {tone}">{escape(text)}</span>'


def _table(headers: list[str], rows: list[list[str]], *, table_id: str = "") -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    ident = f' id="{table_id}"' if table_id else ""
    return f'<div class="scroll"><table{ident}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _lineage_svg(trace: dict[str, Any]) -> str:
    """Source on the left; confirmed (solid), exposure (dotted), candidate (dashed)."""
    rows: list[tuple[str, str, str]] = []
    for node in trace.get("confirmed_descendants", []):
        relation = (node.get("via") or [{}])[-1].get("relation", "")
        rows.append((node["record_id"], f"{relation} · depth {node.get('depth')}", "confirmed"))
    for node in trace.get("weak_exposure", []):
        rows.append((node["record_id"], "READ_FROM · exposure only", "exposure"))
    for edge in trace.get("candidate_relationships", []):
        rows.append((edge["record_id"], f"{edge.get('relation_guess')} · candidate", "candidate"))
    if not rows:
        return "<p>No recorded lineage for this target.</p>"
    row_h, top, width = 44, 20, 760
    height = top * 2 + row_h * len(rows)
    src_y = height / 2
    source = escape(trace.get("source", {}).get("record_id", ""))
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Lineage of {source}">',
        f'<rect class="node src" x="8" y="{src_y - 18}" width="230" height="36" rx="6"/>',
        f'<text x="20" y="{src_y + 5}">{source}</text>',
    ]
    for index, (record_id, label, kind) in enumerate(rows):
        y = top + row_h * index + row_h / 2
        parts.append(f'<path class="edge {kind}" d="M238 {src_y} C330 {src_y} 330 {y} 420 {y}"/>')
        parts.append(f'<rect class="node {kind}" x="420" y="{y - 16}" width="332" height="32" rx="6"/>')
        parts.append(f'<text x="432" y="{y - 1}">{escape(record_id)}</text>')
        parts.append(f'<text class="sub" x="432" y="{y + 12}">{escape(label)}</text>')
    parts.append("</svg>")
    legend = (
        '<p class="legend"><span class="key confirmed"></span> confirmed lineage '
        '<span class="key exposure"></span> exposure only (never authorises deletion) '
        '<span class="key candidate"></span> candidate (advisory)</p>'
    )
    return "".join(parts) + legend


def build_report(engine: Engine, *, request_id: str) -> str:
    request = engine.repo.get_request(request_id)
    if request is None:
        raise RedactoError("unknown_request", "No such revocation request.", {"request_id": request_id})
    plan = engine.repo.latest_plan_for_request(request_id)
    items = sorted(
        engine.repo.plan_items(plan["plan_id"]) if plan else [],
        key=lambda item: (classify.severity(item["evidence_class"]), item["record_id"]),
    )
    actions = engine.repo.actions_for_request(request_id)
    receipt_row = engine.repo.receipt_for_request(request_id)
    receipt = receipt_row["summary"] if receipt_row else None
    if isinstance(receipt, str):
        receipt = json.loads(receipt)
    status = engine.status(transport="report")

    store_rows = [
        [
            escape(str(a.get("adapter_id"))),
            _badge("reachable" if a.get("health", {}).get("reachable") else "unreachable"),
            escape(", ".join(k for k, v in (a.get("capabilities") or {}).items() if v is True)),
        ]
        for a in status.get("adapters", [])
    ]

    lineage = "<p>Fact and secret revocations target a value, not a document's lineage.</p>"
    if request["target_kind"] == "source":
        try:
            lineage = _lineage_svg(engine.trace(source_id=request["target_id"]))
        except RedactoError as exc:
            lineage = f"<p>Lineage unavailable: {escape(exc.message)}</p>"

    item_rows = [
        [
            escape(item["record_id"]),
            escape(item["record_id"].split(":", 1)[0]),
            _badge(item["evidence_class"]),
            _badge(item["proposed_action"]),
            "yes" if item["approved"] else "no",
            escape(item["risk"]),
            _badge(item["state"]),
            escape(item["reason_redacted"]),
        ]
        for item in items
    ]
    action_rows = [
        [
            escape(a.get("finished_at") or a.get("started_at") or ""),
            escape(a.get("adapter_id") or ""),
            escape(a.get("operation") or ""),
            _badge(a.get("result")),
            escape(a.get("error_code") or ""),
        ]
        for a in actions
    ]

    if receipt:
        counts = "".join(
            f"<div class='stat'><b>{escape(str(v))}</b><span>{escape(k.replace('_', ' '))}</span></div>"
            for k, v in receipt.get("counts", {}).items()
        )
        store_results = _table(
            ["Store", "Outcome", "Residuals"],
            [
                [escape(s["store_id"]), _badge(s["outcome"]), escape(str(s.get("residual_count", 0)))]
                for s in receipt.get("stores", [])
            ],
        )
        limitations = "".join(f"<li>{escape(x)}</li>" for x in receipt.get("limitations", []))
        receipt_html = (
            f"<p>{_badge(receipt.get('status'))} checked {escape(str(receipt.get('checked_at')))}</p>"
            f"<div class='stats'>{counts}</div>{store_results}"
            f"<h3>Limitations</h3><ul>{limitations}</ul>"
            f"<p class='statement'>{escape(receipt.get('statement', ''))}</p>"
        )
    else:
        receipt_html = "<p>Not verified yet. Run verify to produce a receipt.</p>"

    title = f"Redacto report: {request['target_id']}"
    return _PAGE.format(
        title=escape(title),
        target=escape(request["target_id"]),
        kind=escape(request["target_kind"]),
        mode=escape(request["mode"]),
        request_id=escape(request_id),
        plan=escape(f"{plan['plan_id']} v{plan['version']}" if plan else "none"),
        state=_badge(plan["state"] if plan else request["state"]),
        stores=_table(["Store", "Health", "Supports"], store_rows),
        lineage=lineage,
        items=_table(
            ["Record", "Store", "Evidence", "Action", "Approved", "Risk", "State", "Why"],
            item_rows,
            table_id="items",
        ),
        timeline=_table(["When", "Store", "Operation", "Result", "Error"], action_rows)
        if action_rows
        else "<p>Nothing applied yet.</p>",
        receipt=receipt_html,
    )


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#fafaf9; --fg:#1c1917; --muted:#57534e; --line:#d6d3d1; --panel:#fff;
  --ok:#15803d; --warn:#b45309; --act:#1d4ed8; --cand:#9333ea; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#1c1917; --fg:#f5f5f4; --muted:#a8a29e;
  --line:#44403c; --panel:#292524; --ok:#4ade80; --warn:#fbbf24; --act:#93c5fd; --cand:#d8b4fe; }} }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:24px 16px; }}
section {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin:16px 0; }}
h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:0 0 12px; }}
.meta {{ color:var(--muted); }} .scroll {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-size:14px; }}
th, td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
.badge {{ font-weight:600; font-size:12px; padding:1px 6px; border-radius:4px; border:1px solid currentColor; white-space:nowrap; }}
.badge.ok {{ color:var(--ok); }} .badge.warn {{ color:var(--warn); }} .badge.act {{ color:var(--act); }} .badge.muted {{ color:var(--muted); }}
svg {{ width:100%; height:auto; }} svg text {{ fill:var(--fg); font-size:12px; }} svg text.sub {{ fill:var(--muted); font-size:10px; }}
.node {{ fill:var(--panel); stroke:var(--line); }} .node.src {{ stroke:var(--fg); }}
.edge {{ fill:none; stroke-width:1.6; }} .edge.confirmed {{ stroke:var(--act); }}
.edge.exposure {{ stroke:var(--muted); stroke-dasharray:2 4; }} .edge.candidate {{ stroke:var(--cand); stroke-dasharray:7 5; }}
.legend .key {{ display:inline-block; width:28px; border-top:2px solid; margin:0 4px 3px 12px; }}
.key.confirmed {{ border-color:var(--act); }} .key.exposure {{ border-color:var(--muted); border-top-style:dotted; }}
.key.candidate {{ border-color:var(--cand); border-top-style:dashed; }}
.stats {{ display:flex; flex-wrap:wrap; gap:12px; margin:8px 0 12px; }}
.stat {{ border:1px solid var(--line); border-radius:6px; padding:6px 10px; min-width:96px; }}
.stat b {{ display:block; font-size:20px; }} .stat span {{ color:var(--muted); font-size:12px; }}
.filters {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:8px; }}
select {{ background:var(--panel); color:var(--fg); border:1px solid var(--line); border-radius:4px; padding:2px 4px; }}
.statement {{ font-weight:600; }}
</style></head>
<body><main>
<h1>Revocation of {target}</h1>
<p class="meta">{kind} target · {mode} · request {request_id} · plan {plan} · {state}</p>
<section><h2>Stores</h2>{stores}</section>
<section><h2>Lineage</h2>{lineage}</section>
<section><h2>Plan preview</h2>
<div class="filters">
<label>Store <select data-col="1"><option value="">all</option></select></label>
<label>Evidence <select data-col="2"><option value="">all</option></select></label>
<label>Action <select data-col="3"><option value="">all</option></select></label>
</div>{items}</section>
<section><h2>Execution timeline</h2>{timeline}</section>
<section><h2>Verification receipt</h2>{receipt}</section>
<p class="meta">Generated by Redacto. Holds ids, counts and redacted reasons only, never record content.
Verified within configured scope, not a claim of universal erasure.</p>
</main>
<script>
(() => {{
  const table = document.getElementById("items");
  if (!table) return;
  const rows = [...table.tBodies[0].rows];
  const selects = [...document.querySelectorAll(".filters select")];
  for (const sel of selects) {{
    const col = +sel.dataset.col;
    [...new Set(rows.map(r => r.cells[col].textContent))].sort()
      .forEach(v => sel.add(new Option(v, v)));
    sel.addEventListener("change", apply);
  }}
  function apply() {{
    for (const row of rows) {{
      row.hidden = selects.some(s => s.value && row.cells[+s.dataset.col].textContent !== s.value);
    }}
  }}
}})();
</script>
</body></html>
"""
