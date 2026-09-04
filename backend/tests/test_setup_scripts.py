"""Exercise installer logic without package installs, service changes or scans."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def bash(script, *, env=None, cwd=None):
    candidates = [Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"] if os.name == "nt" else []
    executable = next((str(p) for p in candidates if p.is_file()), None) or shutil.which("bash")
    if not executable:
        pytest.skip("Bash is unavailable")
    return subprocess.run(
        [executable, "--noprofile", "--norc"], input=script,
        text=True, capture_output=True, timeout=15, cwd=cwd or ROOT,
        env={**os.environ, **(env or {})},
    )


@pytest.mark.parametrize("name", ["setup.sh", "uninstall.sh", "deploy.sh"])
def test_shell_syntax(name):
    result = bash("bash -n " + name)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("domain,valid", [
    ("scanner.example.com", True), ("a.io", True), ("scan-1.example.co.uk", True),
    ("localhost", False), ("-bad.example.com", False), ("bad-.example.com", False),
    ("example.com;id", False), ("https://example.com", False),
    ("a" * 64 + ".com", False),
])
def test_deploy_domain_expression_in_bash(domain, valid):
    line = next(line for line in source("deploy.sh").splitlines() if "valid public domain" in line)
    expression = line.split(" || fail", 1)[0]
    result = bash(expression, env={"DOMAIN": domain})
    assert result.returncode != 2, result.stderr  # invalid regex is not a validation failure
    assert (result.returncode == 0) is valid


@pytest.mark.parametrize("service", ["redis", "mongo"])
def test_compose_healthchecks_expand_credentials_in_shell(service):
    command_name = "redis-cli" if service == "redis" else "mongosh"
    line = next(line for line in source("docker-compose.yml").splitlines() if 'test:' in line and command_name in line)
    command = json.loads(line.split("test:", 1)[1])[1].replace("$$", "$")
    stubs = r'''
redis-cli() {
  [ "$REDISCLI_AUTH" = "$EXPECTED" ] || return 1
  printf 'PONG\n'
}
mongosh() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --username) shift; [ "$1" = "$EXPECTED_USER" ] || return 1 ;;
      --password) shift; [ "$1" = "$EXPECTED" ] || return 1 ;;
    esac
    shift
  done
  printf '1\n'
}
'''
    secret = 'test password with $dollar "double" and \'single\''
    result = bash(stubs + command, env={
        "EXPECTED": secret, "EXPECTED_USER": "test user",
        "REDIS_PASSWORD": secret, "MONGO_INITDB_ROOT_PASSWORD": secret,
        "MONGO_INITDB_ROOT_USERNAME": "test user",
    })
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("new_version_available", [True, False])
def test_python_discovery_skips_old_interpreters(new_version_available):
    function = re.search(r"find_python\(\) \{.*?\n\}", source("setup.sh"), re.S).group()
    stubs = '''
OS=linux
VENV=/nonexistent-recontitan-test
command() { case "$2" in python3|python|python3.12) return 0 ;; *) return 1 ;; esac; }
python3() { return 1; }
python() { return 1; }
python3.12() { return "$TEST_VERSION_STATUS"; }
'''
    result = bash(stubs + function + '\nfind_python\nstatus=$?\nprintf "%s" "$PY_CMD"\nexit "$status"',
                  env={"TEST_VERSION_STATUS": "0" if new_version_available else "1"})
    assert (result.returncode == 0) is new_version_available
    assert result.stdout == ("python3.12" if new_version_available else "")


def test_deploy_preserves_existing_configuration(tmp_path):
    config = tmp_path / ".env"
    config.write_text("MONGO_PASS=existing-test-password\n", encoding="utf-8")
    before = config.read_bytes()
    block = source("deploy.sh").split("if [[ -f .env ]]; then", 1)[1].split("\nfi\nchmod 600 .env", 1)[0]
    stubs = 'log() { :; }; fail() { exit 89; }; docker() { exit 90; }; python3() { exit 91; }\n'
    result = bash(stubs + "if [[ -f .env ]]; then" + block + "\nfi", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert config.read_bytes() == before


def test_homebrew_python_is_found_outside_path(tmp_path):
    prefix = tmp_path / "brew"
    binary = prefix / "bin" / "python3.12"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    function = re.search(r"find_python\(\) \{.*?\n\}", source("setup.sh"), re.S).group()
    stubs = '''
OS=macos
VENV=/nonexistent-recontitan-test
brew() { printf '%s' "$TEST_BREW_PREFIX"; }
command() {
  case "$2" in brew|"$TEST_BREW_PREFIX/bin/python3.12") builtin command "$@" ;; *) return 1 ;; esac
}
'''
    result = bash(stubs + function + '\nfind_python || exit 1\nprintf "%s" "$PY_CMD"',
                  env={"TEST_BREW_PREFIX": prefix.as_posix()})
    assert result.returncode == 0, result.stderr
    assert result.stdout == binary.as_posix()


def test_manifests_are_appended_and_launcher_is_portable():
    assert '} >> "$MANIFEST"' in source("setup.sh")
    assert 'echo.>> "%MANIFEST%"' in source("setup.bat")
    launcher = source("backend/start.bat").lower()
    assert "%~dp0..\\.venv\\scripts\\python.exe" in launcher
    assert "taskkill" not in launcher and "e:\\recontitan" not in launcher
    for name in ("setup.sh", "setup.bat", "backend/start.bat"):
        assert "ASYNC_SCANS_ENABLED=false" in source(name)


def test_project_danger_default_is_preserved_and_described_honestly():
    assert "ALLOW_DANGER_MODE=true" in source(".env.example")
    assert "ALLOW_DANGER_MODE=true" in source("deploy.sh")
    assert "${ALLOW_DANGER_MODE:-true}" in source("docker-compose.yml")
    assert "Left disabled deliberately" not in source("deploy.sh")


@pytest.mark.skipif(os.name != "nt", reason="Windows batch failure branch")
def test_windows_python_install_failure_is_not_recorded(tmp_path):
    text = source("setup.bat")
    start = text.index("  winget install --id Python.Python.3.12")
    end = text.index("  echo PYTHON_INSTALLED_BY_SETUP=1", start)
    block = text[start:end].replace("winget install --id Python.Python.3.12 -e --source winget", "cmd /d /c exit 1").replace("pause", "rem pause")
    script = tmp_path / "failure.bat"
    script.write_text('@echo off\n' + block + '\necho wrong-success\n', encoding="utf-8")
    result = subprocess.run(["cmd", "/d", "/c", str(script)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 1
    assert "wrong-success" not in result.stdout


def test_local_scan_mode_disables_queue_without_disabling_persistence(monkeypatch):
    from app.config import Settings
    monkeypatch.setenv("ASYNC_SCANS_ENABLED", "false")
    monkeypatch.setenv("SERVERLESS", "false")
    settings = Settings()
    assert settings.ASYNC_SCANS_ENABLED is False
    assert settings.SERVERLESS is False


def test_disabled_queue_is_advertised_and_rejected_before_database_access(monkeypatch):
    from fastapi import HTTPException
    from starlette.requests import Request
    from app.models.schemas import ScanRequest
    from app.routers import scans
    from app.services import capabilities
    monkeypatch.setattr(scans.settings, "ASYNC_SCANS_ENABLED", False)
    monkeypatch.setattr(capabilities.settings, "ASYNC_SCANS_ENABLED", False)
    monkeypatch.setattr(scans, "validate_scan_target", lambda *a, **k: (True, "example.com", ""))
    def unexpected_db():
        raise AssertionError("local mode must not dispatch based on database presence")
    monkeypatch.setattr(scans, "get_db", unexpected_db)
    assert capabilities.runtime_report()["async_scans"] is False
    with pytest.raises(HTTPException) as error:
        scans.initiate_scan(ScanRequest(target="example.com", scan_type="full"), Request({"type": "http"}))
    assert error.value.status_code == 503
    assert "/api/test-scan" in error.value.detail
