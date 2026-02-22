from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .model import Network, Node, Service, ValidationError
from .risk import SEVERITY_ORDER, meets_severity_threshold, score_network


def _load_network_from_json(data: dict[str, object], fallback_name: str) -> Network:
    nodes = []
    for node_data in data.get("nodes", []):
        services = [Service(**svc) for svc in node_data.get("services", [])]
        nodes.append(
            Node(
                id=node_data["id"],
                role=node_data.get("role", "unknown"),
                services=tuple(services),
            )
        )

    return Network(name=data.get("name", fallback_name), nodes=tuple(nodes))


def _load_network(input_ref: str) -> Network:
    if input_ref == "-":
        payload = json.load(sys.stdin)
        return _load_network_from_json(payload, fallback_name="stdin-network")

    path = Path(input_ref)
    payload = json.loads(path.read_text(encoding="utf-8"))
    return _load_network_from_json(payload, fallback_name=path.stem)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RadarNet risk scorer")
    parser.add_argument("input", help="Path to network JSON file or '-' for stdin")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default=None,
        help="Exit with code 2 if report severity is at or above this value",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only print summary fields (hide findings)",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        report = score_network(_load_network(args.input))
    except (ValidationError, json.JSONDecodeError, KeyError, TypeError) as exc:
        parser.error(f"Invalid input: {exc}")

    if args.format == "json":
        payload = report.to_dict()
        if args.summary_only:
            payload.pop("findings", None)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Network: {report.network_name}")
        print(f"Score: {report.score}/{report.max_score} ({report.ratio:.2%})")
        print(f"Severity: {report.severity}")
        if report.findings and not args.summary_only:
            print("Findings:")
            for finding in report.findings:
                print(f"- {finding}")

    if args.fail_on and meets_severity_threshold(report, args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
