import subprocess
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path

import vulnmalper


def test_version_defined():
    assert vulnmalper.VERSION


def test_package_version_matches_module():
    assert pkg_version("vulnmalper") == vulnmalper.VERSION


def test_module_is_single_file():
    assert Path(vulnmalper.__file__).name == "vulnmalper.py"


def test_cli_help_exits_zero():
    result = subprocess.run(
        [sys.executable, str(Path(vulnmalper.__file__)), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "usage: vulnmalper" in result.stdout


def test_normalize_url_lowercases_scheme_and_netloc():
    assert vulnmalper._normalize_url("HTTP://Example.com:80/foo") == "http://example.com:80/foo"
    assert vulnmalper._normalize_url("https://example.com/login?redirect=1") == (
        "https://example.com/login?redirect=1"
    )


def test_is_worth_scanning_excludes_static_assets():
    assert vulnmalper._is_worth_scanning("https://example.com/login?redirect=1")
    assert not vulnmalper._is_worth_scanning("https://example.com/static/app.js")


def test_parse_netmalper_endpoints_and_ports():
    graph = {
        "meta": {"target": "example.com"},
        "nodes": [
            {
                "id": "e1",
                "type": "endpoint",
                "data": {"url": "https://example.com/login?redirect=1"},
            },
            {"id": "e2", "type": "endpoint", "data": {"url": "http://192.0.2.10/"}},
            {
                "id": "p1",
                "type": "port",
                "data": {
                    "host": "192.0.2.10",
                    "port": 8080,
                    "service": "http",
                    "product": "nginx",
                },
            },
            {
                "id": "p2",
                "type": "port",
                "data": {"host": "192.0.2.10", "port": 22, "service": "ssh"},
            },
        ],
    }

    targets, services, meta = vulnmalper.parse_netmalper(graph)

    assert meta["target"] == "example.com"
    urls = {t.url for t in targets}
    assert "https://example.com/login?redirect=1" in urls
    assert "http://192.0.2.10/" in urls
    assert "http://192.0.2.10:8080/" in urls
    assert len(services) == 1
    assert services[0].service == "ssh"
