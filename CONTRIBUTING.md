# Contributing to ReconTitan

Thank you for improving ReconTitan. Contributions must preserve its authorized-testing and safe-by-default design.

## Development workflow

```bash
python -m venv .venv
source .venv/bin/activate             # Git Bash on Windows: source .venv/Scripts/activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
export PYTHONPATH=backend
pytest -q backend/tests
```

Create a focused branch:

```bash
git switch -c feature/concise-name
```

Before opening a pull request, run:

```bash
pytest -q backend/tests
python -m compileall -q backend/app
node --check frontend/dashboard.js
node --check frontend/report.js
bash -n deploy.sh
```

## Security requirements

- Never commit `.env`, credentials, private scan targets, raw secrets, or customer reports.
- Keep `ALLOW_PRIVATE_TARGETS=false` and `ENABLE_ACTIVE_VULN_TOOLS=false` as defaults.
- Use the bounded safe HTTP client for scanner traffic.
- Revalidate redirects and target scope.
- Redact secret values in findings.
- Treat heuristic detections as candidates requiring manual verification.
- Add regression tests for endpoint, middleware, targeting, and parsing changes.

## Pull requests

Explain what changed, why, user/security impact, validation performed, and known limitations. Keep unrelated changes out of the same pull request.
