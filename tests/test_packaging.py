"""Packaging and plugin manifest checks."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_dependencies_include_http_clients_and_server():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    joined = " ".join(dependencies)
    assert "httpx" in joined
    assert "uvicorn" in joined
    assert "httpx" not in " ".join(project["project"]["optional-dependencies"]["dev"])


def test_ci_covers_linux_and_windows_and_runtime_install():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "ubuntu-latest" in workflow
    assert "windows-latest" in workflow
    assert "pip install ." in workflow
    assert "python -m redacto --help" in workflow


def test_status_does_not_create_a_stray_database(tmp_path):
    from helpers import make_settings
    from redacto.engine import Engine

    settings = make_settings(tmp_path / "unconfigured")
    engine = Engine(settings)
    status = engine.status(transport="test")
    assert status["service"] == "redacto"
    assert not settings.db_path.exists()
