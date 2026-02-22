import json
import subprocess
import sys

import pytest

from radarnet.model import Network, Node, Service, ValidationError
from radarnet.risk import meets_severity_threshold, score_network


def test_score_network_generates_findings_for_unsecure_services():
    network = Network(
        name="demo",
        nodes=(
            Node(
                id="api-1",
                role="api",
                services=(
                    Service(
                        name="http",
                        port=80,
                        public=True,
                        encrypted=False,
                        authenticated=False,
                        criticality=5,
                    ),
                ),
            ),
        ),
    )

    report = score_network(network)

    assert report.score > 0
    assert report.severity in {"medium", "high", "critical"}
    assert any("unencrypted" in finding for finding in report.findings)
    assert any("no authentication" in finding for finding in report.findings)


def test_empty_node_is_treated_as_visibility_gap():
    network = Network(name="demo", nodes=(Node(id="db-1", role="db", services=()),))

    report = score_network(network)

    assert report.score >= 2
    assert any("visibility gap" in finding for finding in report.findings)


def test_invalid_port_raises_validation_error():
    network = Network(
        name="demo",
        nodes=(Node(id="api-1", role="api", services=(Service(name="x", port=70000),)),),
    )

    with pytest.raises(ValidationError):
        score_network(network)


def test_threshold_comparison():
    network = Network(name="tiny", nodes=(Node(id="a", role="r", services=(Service(name="s", port=1),)),))
    report = score_network(network)
    assert meets_severity_threshold(report, "low") is True


def test_cli_json_output(tmp_path):
    sample = {
        "name": "n1",
        "nodes": [
            {
                "id": "edge",
                "role": "gateway",
                "services": [{"name": "http", "port": 80, "public": True, "encrypted": False, "authenticated": False, "criticality": 5}],
            }
        ],
    }
    input_path = tmp_path / "network.json"
    input_path.write_text(json.dumps(sample), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "radarnet.cli", str(input_path), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["network_name"] == "n1"
    assert payload["severity"] in {"medium", "high", "critical"}


def test_cli_supports_stdin_and_summary_only():
    sample = {
        "name": "stdin-net",
        "nodes": [
            {
                "id": "edge",
                "role": "gateway",
                "services": [{"name": "http", "port": 80, "public": True, "encrypted": False, "authenticated": False, "criticality": 5}],
            }
        ],
    }

    result = subprocess.run(
        [sys.executable, "-m", "radarnet.cli", "-", "--format", "json", "--summary-only"],
        input=json.dumps(sample),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["network_name"] == "stdin-net"
    assert "findings" not in payload
