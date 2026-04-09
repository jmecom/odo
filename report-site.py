#!/usr/bin/env python3
"""Generate a Markdown report for Carlini final report bundles."""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
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

SEVERITY_LEVELS = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
)

FIELD_NAME_RE = {
    "severity": ("severity", "risk", "impact"),
    "component": ("affected component", "affected area", "component"),
}

HEADING_RE = re.compile(r"^(#{1,6})(\s+.*)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown report from Carlini maintainer-ready report bundles."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Directories containing REPORT bundles or parent directories to scan",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report.md",
        help="Output Markdown file path (default: report.md)",
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
        if stripped.startswith(("```", "~~~")):
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
        if re.match(
            r"^(?:[-*]\s*)?(severity|risk|impact|component|affected component|affected area)\s*[:|-]",
            stripped,
            re.I,
        ):
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


def severity_label(value: str) -> str:
    if value == "informational":
        return "Informational"
    return value.capitalize()


def collect_artifact_links(finding_dir: Path) -> list[dict[str, str]]:
    links: list[dict[str, str]] = []

    for path in sorted(finding_dir.rglob("*")):
        if path.is_file():
            resolved = path.resolve()
            links.append(
                {
                    "label": str(path.relative_to(finding_dir)).replace("\\", "/"),
                    "path": str(resolved),
                    "href": resolved.as_uri(),
                }
            )

    return links


def collect_findings(bundles: list[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []

    for bundle in bundles:
        for finding_dir in sorted((bundle / "findings").glob("*")):
            report_path = finding_dir / "REPORT.md"
            if not report_path.is_file():
                continue

            text = report_path.read_text(encoding="utf-8", errors="replace")
            severity_field = extract_field(text, FIELD_NAME_RE["severity"])
            severity = normalize_severity(severity_field, text)
            component = (
                extract_field(text, FIELD_NAME_RE["component"])
                or "Unspecified component"
            )
            findings.append(
                {
                    "bundle": bundle_name(bundle),
                    "bundlePath": str(bundle.resolve()),
                    "title": extract_title(text, finding_dir.name.replace("_", " ")),
                    "severity": severity,
                    "severityRank": SEVERITY_ORDER[severity],
                    "component": component,
                    "summary": extract_summary(text),
                    "reportBody": text.rstrip(),
                    "reportPath": str(report_path.resolve()),
                    "artifactLinks": collect_artifact_links(finding_dir),
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


def shift_markdown_headings(text: str, levels: int) -> str:
    if levels <= 0:
        return text

    shifted: list[str] = []
    in_code = False

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            in_code = not in_code
            shifted.append(line)
            continue

        if not in_code:
            match = HEADING_RE.match(line)
            if match:
                hashes, rest = match.groups()
                shifted.append(f"{'#' * min(6, len(hashes) + levels)}{rest}")
                continue

        shifted.append(line)

    return "\n".join(shifted)


def resolve_output_path(raw_output: str) -> Path:
    output = Path(raw_output).expanduser()
    if output.exists() and output.is_dir():
        return output / "report.md"
    if output.suffix.lower() == ".md":
        return output
    return output.parent / f"{output.name}.md"


def escape_table_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_table(headers: list[str], rows: list[list[object]]) -> str:
    rendered_rows = [[escape_table_cell(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]

    for row in rendered_rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(values: list[str]) -> str:
        return "| " + " | ".join(
            value.ljust(widths[index]) for index, value in enumerate(values)
        ) + " |"

    separator = "| " + " | ".join("-" * width for width in widths) + " |"
    return "\n".join(
        [format_row(headers), separator, *(format_row(row) for row in rendered_rows)]
    )


def render_snapshot(findings: list[dict[str, object]], bundle_count: int) -> str:
    top_severity = severity_label(findings[0]["severity"]) if findings else "None"
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return "\n".join(
        [
            "## Snapshot",
            "",
            f"- Bundles: **{bundle_count}**",
            f"- Findings: **{len(findings)}**",
            f"- Top Severity: **{top_severity}**",
            f"- Generated: **{generated_at}**",
        ]
    )


def render_severity_breakdown(findings: list[dict[str, object]]) -> str:
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        counts[str(finding["severity"])] += 1

    rows = [[severity_label(level), counts[level]] for level in SEVERITY_LEVELS]
    return "\n".join(
        [
            "## Severity Breakdown",
            "",
            render_table(["Severity", "Findings"], rows),
        ]
    )


def render_bundle_summary(findings: list[dict[str, object]]) -> str:
    bundles: dict[str, dict[str, object]] = {}

    for finding in findings:
        bundle = str(finding["bundle"])
        entry = bundles.setdefault(
            bundle,
            {
                "count": 0,
                "topRank": SEVERITY_ORDER["unknown"],
                "topSeverity": "unknown",
            },
        )
        entry["count"] += 1
        if int(finding["severityRank"]) < int(entry["topRank"]):
            entry["topRank"] = finding["severityRank"]
            entry["topSeverity"] = finding["severity"]

    rows = [
        [bundle, data["count"], severity_label(str(data["topSeverity"]))]
        for bundle, data in sorted(
            bundles.items(),
            key=lambda item: (int(item[1]["topRank"]), item[0].lower()),
        )
    ]

    if not rows:
        rows = [["None", 0, "None"]]

    return "\n".join(
        [
            "## Bundle Summary",
            "",
            render_table(["Bundle", "Findings", "Highest Severity"], rows),
        ]
    )


def render_finding_index(findings: list[dict[str, object]]) -> str:
    rows = [
        [
            index,
            severity_label(str(finding["severity"])),
            finding["bundle"],
            finding["title"],
        ]
        for index, finding in enumerate(findings, start=1)
    ]

    if not rows:
        rows = [["-", "None", "-", "No accepted findings were found"]]

    return "\n".join(
        [
            "## Finding Index",
            "",
            render_table(["#", "Severity", "Bundle", "Title"], rows),
        ]
    )


def render_artifact_list(links: list[dict[str, str]]) -> str:
    if not links:
        return "No source artifacts found."

    return "\n".join(
        f"- [{link['label']}]({link['href']}) - `{link['path']}`" for link in links
    )


def render_findings(findings: list[dict[str, object]]) -> str:
    if not findings:
        return "\n".join(["## Findings", "", "No accepted findings were found."])

    sections = ["## Findings"]

    for index, finding in enumerate(findings, start=1):
        report_body = shift_markdown_headings(str(finding["reportBody"]), 3).strip()
        sections.extend(
            [
                "",
                f"### {index}. {finding['title']}",
                "",
                f"- Severity: **{severity_label(str(finding['severity']))}**",
                f"- Bundle: `{finding['bundle']}`",
                f"- Component: {finding['component']}",
                f"- Summary: {finding['summary']}",
                f"- Original Report: `{finding['reportPath']}`",
                f"- Bundle Path: `{finding['bundlePath']}`",
                "",
                "#### Artifacts",
                "",
                render_artifact_list(finding["artifactLinks"]),
                "",
                "#### Full Report",
                "",
                report_body or "_Empty report body._",
                "",
                "---",
            ]
        )

    return "\n".join(sections).rstrip()


def render_report(findings: list[dict[str, object]], bundle_count: int) -> str:
    parts = [
        "# Carlini Final Reports",
        "",
        "Maintainer-ready summary of accepted findings across the discovered report bundles.",
        "",
        render_snapshot(findings, bundle_count),
        "",
        render_severity_breakdown(findings),
        "",
        render_bundle_summary(findings),
        "",
        render_finding_index(findings),
        "",
        render_findings(findings),
        "",
    ]
    return "\n".join(parts)


def main() -> int:
    args = parse_args()
    inputs = [Path(path).expanduser() for path in args.inputs]
    output_path = resolve_output_path(args.output)

    try:
        bundles = discover_bundles(inputs)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1

    findings = collect_findings(bundles)
    report = render_report(findings, len(bundles))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")

    print(
        f"Wrote Markdown report with {len(findings)} findings from {len(bundles)} bundles to {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
