import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest

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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="signal semantics tested on Linux")
def test_sigint_kills_child_processes():
    """Ctrl+C must terminate in-flight tool processes (no orphans) and exit 130."""
    work = tempfile.mkdtemp(prefix="vuln_test_int_")
    try:
        bin_dir = os.path.join(work, "bin")
        os.makedirs(bin_dir)
        fake = os.path.join(bin_dir, "nuclei")
        pid_file = os.path.join(work, "pid")
        with open(fake, "w") as f:
            f.write(
                "#!/bin/sh\n"
                "echo $$ > " + pid_file + "\n"
                "trap '' INT TERM HUP\n"
                "while :; do sleep 1; done\n"
            )
        os.chmod(fake, 0o755)

        graph = os.path.join(work, "graph.json")
        with open(graph, "w") as f:
            json.dump(
                {
                    "meta": {"target": "example.com"},
                    "nodes": [
                        {"id": "e1", "type": "endpoint", "data": {"url": "http://127.0.0.1:65534/"}}
                    ],
                },
                f,
            )

        env = dict(os.environ)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        env["NO_COLOR"] = "1"

        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(vulnmalper.__file__)),
                graph,
                "--only",
                "nuclei",
                "--runner",
                "local",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            child_pid = None
            deadline = time.time() + 30
            while time.time() < deadline:
                if os.path.exists(pid_file):
                    with open(pid_file) as pf:
                        child_pid = int(pf.read().strip())
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
            assert child_pid is not None, "fake tool never started"
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

        assert proc.returncode == 128 + signal.SIGINT
        with pytest.raises(OSError):
            os.kill(child_pid, 0)
    finally:
        shutil.rmtree(work, ignore_errors=True)
