# Publishing

Quick notes for cutting a release to PyPI.

## Build + upload

Preferred: configure a PyPI Trusted Publisher for:

- Owner: `yingchen-coding`
- Repository: `agentguard`
- Workflow: `publish.yml`
- Environment: `pypi`

Then run the `publish` workflow manually for the first release. Later GitHub releases publish
automatically. The workflow builds in one job and publishes the exact uploaded artifact in a
separate OIDC-only job, so no long-lived PyPI token is stored in GitHub.

Annotated git tags alone do not trigger this workflow. After Trusted Publisher setup, publish a
GitHub Release from the existing version tag (for example `v0.1.2`) or run the workflow manually.
Verify both surfaces before changing the README install command:

```bash
curl -fsS https://api.github.com/repos/yingchen-coding/agentguard/releases/latest
python -m pip index versions agentguard
```

Fallback: use a **clean virtualenv** with current tooling (avoids stale `pkginfo`/`twine` that
mis-validate modern PEP 639 metadata):

```bash
python3 -m venv /tmp/pub && source /tmp/pub/bin/activate
pip install -U build twine
rm -rf dist && python3 -m build          # -> dist/*.whl + *.tar.gz
twine check dist/*                        # should pass on current twine
twine upload dist/*                        # needs a PyPI API token
```

The package targets `Metadata-Version: 2.4` with `License-Expression: MIT` (PEP 639). Modern PyPI
accepts this; only very old local `twine`/`pkginfo` will complain on `twine check` — that's a
local-tooling issue, not a package defect (verify with a clean install: `pip install dist/*.whl &&
agentguard --version`).

## Before the first PyPI release

As of 2026-06-07, `agentguard` is **not published on PyPI**. Keep README install commands pointed
at GitHub until `https://pypi.org/project/agentguard/` resolves and a clean environment verifies:

```bash
python -m pip install agentguard
agentguard --version
```

Replace the `YOUR_USERNAME` placeholder with the real GitHub org/user in: <!-- agentguard-allow AL502 -->

- `README.md` (badges, links, Action reference)
- `pyproject.toml` (`[project.urls]`)
- `action.yml` is fine as-is once the repo exists
- `docs/findings.md` (link back to README is relative — fine)

```bash
grep -rl YOUR_USERNAME . | grep -v .git
```

## Version bump

Update `version` in `pyproject.toml` and `__version__` in `agentguard/__init__.py` (keep them in
sync), add a `CHANGELOG.md` entry, tag `vX.Y.Z`.
