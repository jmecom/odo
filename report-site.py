#!/usr/bin/env python3
"""Generate a static HTML browser for Carlini final report bundles."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 5,
}

FIELD_NAME_RE = {
    "severity": ("severity", "risk", "impact"),
    "component": ("affected component", "affected area", "component"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a static report browser from Carlini maintainer-ready report bundles."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Directories containing REPORT bundles or parent directories to scan",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report-site",
        help="Output directory for the generated static site (default: report-site)",
    )
    return parser.parse_args()


def is_bundle(path: Path) -> bool:
    return (path / "README.md").is_file() and (path / "findings").is_dir()


def discover_bundles(inputs: list[Path]) -> list[Path]:
    bundles: list[Path] = []
    seen: set[Path] = set()

    for root in inputs:
        if not root.exists():
            raise FileNotFoundError(f"Input path does not exist: {root}")

        candidates: list[Path] = []
        if is_bundle(root):
            candidates.append(root)
        if root.is_dir():
            for readme in root.rglob("README.md"):
                candidate = readme.parent
                if is_bundle(candidate):
                    candidates.append(candidate)

        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            bundles.append(candidate)

    return sorted(bundles)


def clean_inline_markdown(value: str) -> str:
    value = re.sub(r"`([^`]*)`", r"\1", value)
    value = value.replace("**", "").replace("*", "").replace("_", "")
    return re.sub(r"\s+", " ", value).strip()


def extract_title(text: str, fallback: str) -> str:
    match = re.search(r"(?m)^#{1,6}\s+(.+?)\s*$", text)
    if match:
        return clean_inline_markdown(match.group(1))

    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return clean_inline_markdown(stripped[:120])

    return fallback


def extract_field(text: str, field_names: tuple[str, ...]) -> str | None:
    names = "|".join(re.escape(name) for name in field_names)
    patterns = (
        rf"(?im)^\s*(?:[-*]\s*)?(?:{names})\s*[:|-]\s*(.+?)\s*$",
        rf"(?im)^\|\s*(?:{names})\s*\|\s*(.+?)\s*(?:\||$)",
    )

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            value = clean_inline_markdown(match.group(1))
            if value:
                return value
    return None


def normalize_severity(value: str | None, text: str) -> str:
    candidates = []
    if value:
        candidates.append(value)
    candidates.append(text)

    for candidate in candidates:
        lowered = candidate.lower()
        for label in ("critical", "high", "medium", "low", "informational", "info"):
            if re.search(rf"\b{label}\b", lowered):
                return "informational" if label == "info" else label
    return "unknown"


def extract_summary(text: str) -> str:
    in_code = False
    paragraph: list[str] = []

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if not stripped:
            if paragraph:
                break
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith("|"):
            continue
        if re.match(r"^(?:[-*]\s*)?(severity|risk|impact|component|affected component|affected area)\s*[:|-]", stripped, re.I):
            continue
        paragraph.append(clean_inline_markdown(stripped.lstrip("-* ").strip()))

    if paragraph:
        return re.sub(r"\s+", " ", " ".join(paragraph)).strip()

    collapsed = re.sub(r"\s+", " ", text).strip()
    return collapsed[:240]


def bundle_name(bundle: Path) -> str:
    if bundle.name == "REPORT":
        return bundle.parent.name
    return bundle.name


def artifact_id(bundle: Path, finding_dir: Path) -> str:
    raw = f"{bundle_name(bundle)}_{finding_dir.name}"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")
    return slug or "finding"


def copy_finding_artifacts(
    finding_dir: Path, output_root: Path, item_id: str
) -> list[dict[str, str]]:
    artifact_root = output_root / "artifacts" / item_id
    artifact_root.mkdir(parents=True, exist_ok=True)

    report_src = finding_dir / "REPORT.md"
    report_dst = artifact_root / "REPORT.md"
    shutil.copy2(report_src, report_dst)

    patch_src = finding_dir / "patch.diff"
    if patch_src.is_file():
        shutil.copy2(patch_src, artifact_root / "patch.diff")

    poc_src = finding_dir / "poc"
    if poc_src.is_dir():
        shutil.copytree(poc_src, artifact_root / "poc", dirs_exist_ok=True)

    links: list[dict[str, str]] = []
    for path in sorted(artifact_root.rglob("*")):
        if path.is_file():
            links.append(
                {
                    "label": str(path.relative_to(artifact_root)).replace("\\", "/"),
                    "href": str(path.relative_to(output_root)).replace("\\", "/"),
                }
            )

    return links


def collect_findings(bundles: list[Path], output_root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []

    for bundle in bundles:
        for finding_dir in sorted((bundle / "findings").glob("*")):
            report_path = finding_dir / "REPORT.md"
            if not report_path.is_file():
                continue

            text = report_path.read_text(encoding="utf-8", errors="replace")
            severity_field = extract_field(text, FIELD_NAME_RE["severity"])
            severity = normalize_severity(severity_field, text)
            component = extract_field(text, FIELD_NAME_RE["component"]) or "Unspecified component"
            title = extract_title(text, finding_dir.name.replace("_", " "))
            summary = extract_summary(text)
            item_id = artifact_id(bundle, finding_dir)
            links = copy_finding_artifacts(finding_dir, output_root, item_id)

            findings.append(
                {
                    "id": item_id,
                    "bundle": bundle_name(bundle),
                    "bundlePath": str(bundle.resolve()),
                    "title": title,
                    "severity": severity,
                    "severityRank": SEVERITY_ORDER[severity],
                    "component": component,
                    "summary": summary,
                    "reportBody": text,
                    "reportPath": str(report_path.resolve()),
                    "artifactLinks": links,
                }
            )

    findings.sort(
        key=lambda item: (
            item["severityRank"],
            str(item["bundle"]).lower(),
            str(item["title"]).lower(),
        )
    )
    return findings


def render_index(findings: list[dict[str, object]], bundle_count: int) -> str:
    payload = {
        "bundleCount": bundle_count,
        "findingCount": len(findings),
        "findings": findings,
    }
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Carlini Final Reports</title>
  <style>
    :root {{
      --bg: #f4efe4;
      --panel: rgba(255, 252, 246, 0.92);
      --panel-strong: #fffaf1;
      --line: #d8cbb3;
      --ink: #1d2c2b;
      --muted: #5c6966;
      --accent: #0e6a62;
      --accent-soft: rgba(14, 106, 98, 0.12);
      --critical: #8b1e26;
      --high: #b44b1c;
      --medium: #9b7c18;
      --low: #3a7a47;
      --informational: #486d8d;
      --unknown: #727272;
      --shadow: 0 18px 48px rgba(48, 41, 29, 0.12);
      --radius: 20px;
      --radius-sm: 14px;
      --mono: "SFMono-Regular", "Menlo", "Monaco", monospace;
      --sans: "Avenir Next", "Trebuchet MS", sans-serif;
      --serif: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(14, 106, 98, 0.16), transparent 30%),
        radial-gradient(circle at top right, rgba(180, 75, 28, 0.18), transparent 28%),
        linear-gradient(180deg, #f7f2e8 0%, var(--bg) 100%);
      font-family: var(--serif);
    }}

    .shell {{
      width: min(1440px, calc(100vw - 32px));
      margin: 24px auto;
      display: grid;
      grid-template-columns: minmax(320px, 430px) minmax(0, 1fr);
      gap: 20px;
    }}

    .panel {{
      background: var(--panel);
      border: 1px solid rgba(216, 203, 179, 0.9);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }}

    .sidebar {{
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      min-height: calc(100vh - 48px);
      position: sticky;
      top: 24px;
    }}

    .hero {{
      padding: 18px 18px 20px;
      border-radius: var(--radius-sm);
      background:
        linear-gradient(135deg, rgba(14, 106, 98, 0.16), rgba(255, 250, 241, 0.7)),
        linear-gradient(180deg, rgba(255, 255, 255, 0.86), rgba(255, 250, 241, 0.95));
      border: 1px solid rgba(14, 106, 98, 0.18);
    }}

    .eyebrow {{
      font-family: var(--sans);
      font-size: 12px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 10px;
    }}

    h1, h2, h3 {{
      margin: 0;
      line-height: 1.05;
      font-weight: 700;
    }}

    h1 {{
      font-size: clamp(32px, 4vw, 48px);
      margin-bottom: 10px;
    }}

    .hero p,
    .muted {{
      margin: 0;
      color: var(--muted);
      font-family: var(--sans);
      line-height: 1.5;
    }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}

    .stat {{
      padding: 14px;
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.7);
      border: 1px solid rgba(216, 203, 179, 0.8);
    }}

    .stat strong {{
      display: block;
      font-family: var(--sans);
      font-size: 28px;
      line-height: 1;
      margin-bottom: 6px;
    }}

    .stat span {{
      font-family: var(--sans);
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}

    .controls {{
      display: grid;
      gap: 12px;
    }}

    .search {{
      width: 100%;
      padding: 14px 16px;
      border-radius: 999px;
      border: 1px solid rgba(14, 106, 98, 0.22);
      background: rgba(255, 255, 255, 0.82);
      color: var(--ink);
      font-family: var(--sans);
      font-size: 15px;
      outline: none;
      transition: border-color 120ms ease, box-shadow 120ms ease;
    }}

    .search:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 4px rgba(14, 106, 98, 0.12);
    }}

    .filter-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}

    .filter {{
      border: 1px solid rgba(216, 203, 179, 0.96);
      background: rgba(255, 255, 255, 0.74);
      color: var(--muted);
      border-radius: 999px;
      padding: 8px 12px;
      font-family: var(--sans);
      font-size: 13px;
      cursor: pointer;
      transition: transform 120ms ease, background 120ms ease, color 120ms ease;
    }}

    .filter:hover {{
      transform: translateY(-1px);
    }}

    .filter.active {{
      background: var(--accent);
      color: white;
      border-color: transparent;
    }}

    .findings {{
      display: grid;
      gap: 10px;
      min-height: 0;
      overflow: auto;
      padding-right: 2px;
    }}

    .card {{
      padding: 16px;
      border-radius: var(--radius-sm);
      border: 1px solid rgba(216, 203, 179, 0.9);
      background: rgba(255, 255, 255, 0.8);
      cursor: pointer;
      transition: transform 140ms ease, border-color 140ms ease, box-shadow 140ms ease;
    }}

    .card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 10px 24px rgba(48, 41, 29, 0.08);
    }}

    .card.selected {{
      border-color: rgba(14, 106, 98, 0.55);
      box-shadow: 0 12px 28px rgba(14, 106, 98, 0.12);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.95), rgba(240, 250, 248, 0.92));
    }}

    .card-top,
    .detail-meta {{
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      font-family: var(--sans);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: white;
    }}

    .critical {{ background: var(--critical); }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .informational {{ background: var(--informational); }}
    .unknown {{ background: var(--unknown); }}

    .repo {{
      font-family: var(--mono);
      font-size: 12px;
      color: var(--muted);
    }}

    .card h3 {{
      margin-top: 12px;
      font-size: 24px;
    }}

    .summary {{
      margin-top: 10px;
      color: var(--muted);
      font-family: var(--sans);
      line-height: 1.55;
    }}

    .component {{
      margin-top: 12px;
      font-family: var(--sans);
      font-size: 13px;
      color: var(--ink);
    }}

    .detail {{
      min-height: calc(100vh - 48px);
      padding: 28px;
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      gap: 22px;
    }}

    .detail-header {{
      display: grid;
      gap: 14px;
    }}

    .detail h2 {{
      font-size: clamp(28px, 3vw, 42px);
    }}

    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}

    .info-box {{
      padding: 16px;
      border-radius: var(--radius-sm);
      background: var(--panel-strong);
      border: 1px solid rgba(216, 203, 179, 0.9);
    }}

    .info-box strong {{
      display: block;
      margin-bottom: 8px;
      font-family: var(--sans);
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }}

    .info-box span,
    .info-box a {{
      color: var(--ink);
      font-family: var(--sans);
      line-height: 1.5;
      word-break: break-word;
    }}

    .info-box a {{
      color: var(--accent);
    }}

    .detail-main {{
      display: grid;
      grid-template-columns: minmax(0, 1.4fr) minmax(240px, 0.8fr);
      gap: 16px;
      min-height: 0;
    }}

    .report-shell,
    .artifacts {{
      min-height: 0;
      border-radius: var(--radius);
      border: 1px solid rgba(216, 203, 179, 0.9);
      background: rgba(255, 255, 255, 0.76);
      overflow: hidden;
    }}

    .section-head {{
      padding: 14px 16px;
      border-bottom: 1px solid rgba(216, 203, 179, 0.84);
      font-family: var(--sans);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      color: var(--muted);
      background: rgba(255, 250, 241, 0.9);
    }}

    pre {{
      margin: 0;
      padding: 18px;
      font-family: var(--mono);
      font-size: 13px;
      line-height: 1.6;
      color: var(--ink);
      white-space: pre-wrap;
      overflow: auto;
    }}

    .artifact-list {{
      margin: 0;
      padding: 12px;
      display: grid;
      gap: 8px;
      max-height: 100%;
      overflow: auto;
    }}

    .artifact-link {{
      display: block;
      padding: 12px 14px;
      border-radius: 12px;
      background: rgba(14, 106, 98, 0.06);
      color: var(--ink);
      text-decoration: none;
      border: 1px solid rgba(14, 106, 98, 0.12);
      font-family: var(--mono);
      font-size: 13px;
    }}

    .artifact-link:hover {{
      background: rgba(14, 106, 98, 0.1);
    }}

    .empty {{
      padding: 24px;
      border-radius: var(--radius-sm);
      border: 1px dashed rgba(216, 203, 179, 0.96);
      color: var(--muted);
      font-family: var(--sans);
      text-align: center;
    }}

    @media (max-width: 980px) {{
      .shell {{
        grid-template-columns: 1fr;
      }}

      .sidebar,
      .detail {{
        min-height: auto;
        position: static;
      }}

      .detail-main,
      .detail-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <aside class="panel sidebar">
      <section class="hero">
        <div class="eyebrow">Maintainer Ready</div>
        <h1>Final Reports</h1>
        <p>Navigate the accepted findings across every generated report bundle, sorted by severity and ready for a deeper read.</p>
      </section>

      <section class="stats" id="stats"></section>

      <section class="controls">
        <input id="search" class="search" type="search" placeholder="Search title, repo, component, summary">
        <div class="filter-row" id="filters"></div>
        <p class="muted" id="resultCount"></p>
      </section>

      <section class="findings" id="findingList"></section>
    </aside>

    <main class="panel detail">
      <section class="detail-header" id="detailHeader"></section>
      <section class="detail-grid" id="detailGrid"></section>
      <section class="detail-main">
        <article class="report-shell">
          <div class="section-head">Report</div>
          <pre id="reportBody"></pre>
        </article>
        <aside class="artifacts">
          <div class="section-head">Artifacts</div>
          <div class="artifact-list" id="artifactList"></div>
        </aside>
      </section>
    </main>
  </div>

  <script id="report-data" type="application/json">{data}</script>
  <script>
    const payload = JSON.parse(document.getElementById("report-data").textContent);
    const severities = ["all", "critical", "high", "medium", "low", "informational", "unknown"];
    const state = {{
      query: "",
      severity: "all",
      selectedId: payload.findings.length ? payload.findings[0].id : null
    }};

    const statsNode = document.getElementById("stats");
    const filtersNode = document.getElementById("filters");
    const listNode = document.getElementById("findingList");
    const countNode = document.getElementById("resultCount");
    const detailHeaderNode = document.getElementById("detailHeader");
    const detailGridNode = document.getElementById("detailGrid");
    const reportBodyNode = document.getElementById("reportBody");
    const artifactListNode = document.getElementById("artifactList");
    const searchNode = document.getElementById("search");

    function titleCase(value) {{
      if (value === "all") return "All";
      if (value === "informational") return "Info";
      return value.charAt(0).toUpperCase() + value.slice(1);
    }}

    function countBySeverity(level) {{
      return payload.findings.filter((item) => item.severity === level).length;
    }}

    function renderStats() {{
      const topSeverity = payload.findings.length ? titleCase(payload.findings[0].severity) : "None";
      const stats = [
        {{ value: payload.bundleCount, label: "Bundles" }},
        {{ value: payload.findingCount, label: "Findings" }},
        {{ value: topSeverity, label: "Top Severity" }}
      ];

      statsNode.innerHTML = stats.map((stat) => `
        <div class="stat">
          <strong>${{stat.value}}</strong>
          <span>${{stat.label}}</span>
        </div>
      `).join("");
    }}

    function renderFilters() {{
      filtersNode.innerHTML = severities.map((level) => {{
        const count = level === "all" ? payload.findingCount : countBySeverity(level);
        const active = state.severity === level ? "active" : "";
        return `<button class="filter ${{active}}" data-severity="${{level}}">${{titleCase(level)}} · ${{count}}</button>`;
      }}).join("");

      for (const button of filtersNode.querySelectorAll(".filter")) {{
        button.addEventListener("click", () => {{
          state.severity = button.dataset.severity;
          render();
        }});
      }}
    }}

    function filteredFindings() {{
      const query = state.query.trim().toLowerCase();
      return payload.findings.filter((item) => {{
        const severityMatch = state.severity === "all" || item.severity === state.severity;
        if (!severityMatch) return false;
        if (!query) return true;
        const haystack = [
          item.title,
          item.bundle,
          item.component,
          item.summary
        ].join(" ").toLowerCase();
        return haystack.includes(query);
      }});
    }}

    function renderList(items) {{
      countNode.textContent = `${{items.length}} finding${{items.length === 1 ? "" : "s"}} visible`;

      if (!items.length) {{
        listNode.innerHTML = '<div class="empty">No findings match the current filters.</div>';
        return;
      }}

      if (!items.some((item) => item.id === state.selectedId)) {{
        state.selectedId = items[0].id;
      }}

      listNode.innerHTML = items.map((item) => {{
        const selected = item.id === state.selectedId ? "selected" : "";
        return `
          <article class="card ${{selected}}" data-id="${{item.id}}">
            <div class="card-top">
              <span class="badge ${{item.severity}}">${{titleCase(item.severity)}}</span>
              <span class="repo">${{item.bundle}}</span>
            </div>
            <h3>${{item.title}}</h3>
            <p class="summary">${{item.summary}}</p>
            <div class="component">${{item.component}}</div>
          </article>
        `;
      }}).join("");

      for (const card of listNode.querySelectorAll(".card")) {{
        card.addEventListener("click", () => {{
          state.selectedId = card.dataset.id;
          render();
        }});
      }}
    }}

    function renderDetail(item) {{
      if (!item) {{
        detailHeaderNode.innerHTML = '<div class="empty">No accepted findings were found.</div>';
        detailGridNode.innerHTML = "";
        reportBodyNode.textContent = "";
        artifactListNode.innerHTML = '<div class="empty">No artifacts copied.</div>';
        return;
      }}

      detailHeaderNode.innerHTML = `
        <div class="detail-meta">
          <span class="badge ${{item.severity}}">${{titleCase(item.severity)}}</span>
          <span class="repo">${{item.bundle}}</span>
        </div>
        <h2>${{item.title}}</h2>
        <p class="muted">${{item.summary}}</p>
      `;

      detailGridNode.innerHTML = `
        <div class="info-box">
          <strong>Component</strong>
          <span>${{item.component}}</span>
        </div>
        <div class="info-box">
          <strong>Original Report</strong>
          <span>${{item.reportPath}}</span>
        </div>
        <div class="info-box">
          <strong>Bundle</strong>
          <span>${{item.bundlePath}}</span>
        </div>
        <div class="info-box">
          <strong>Copied Artifacts</strong>
          <span>${{item.artifactLinks.length}} file${{item.artifactLinks.length === 1 ? "" : "s"}}</span>
        </div>
      `;

      reportBodyNode.textContent = item.reportBody;

      if (!item.artifactLinks.length) {{
        artifactListNode.innerHTML = '<div class="empty">No artifacts copied for this finding.</div>';
        return;
      }}

      artifactListNode.innerHTML = item.artifactLinks.map((link) => `
        <a class="artifact-link" href="${{link.href}}">${{link.label}}</a>
      `).join("");
    }}

    function render() {{
      renderStats();
      renderFilters();
      const items = filteredFindings();
      renderList(items);
      renderDetail(items.find((item) => item.id === state.selectedId) || items[0] || null);
    }}

    searchNode.addEventListener("input", (event) => {{
      state.query = event.target.value;
      render();
    }});

    render();
  </script>
</body>
</html>
"""


def prepare_output_dir(output_root: Path) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_root / "artifacts"
    if artifacts_dir.exists():
        shutil.rmtree(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)


def main() -> int:
    args = parse_args()
    inputs = [Path(path).expanduser() for path in args.inputs]
    output_root = Path(args.output).expanduser()

    try:
        bundles = discover_bundles(inputs)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    prepare_output_dir(output_root)

    findings = collect_findings(bundles, output_root)
    index_html = render_index(findings, len(bundles))
    (output_root / "index.html").write_text(index_html, encoding="utf-8")

    print(
        f"Wrote static report site with {len(findings)} findings from {len(bundles)} bundles to {output_root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
