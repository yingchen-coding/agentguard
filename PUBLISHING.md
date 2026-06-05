# Publishing

Quick notes for cutting a release to PyPI.

## Build + upload

Use a **clean virtualenv** with current tooling (avoids stale `pkginfo`/`twine` that mis-validate
modern PEP 639 metadata):

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
agent-lint --version`).

## Before the first release

Replace the `YOUR_USERNAME` placeholder with the real GitHub org/user in: <!-- agent-lint-allow AL502 -->

- `README.md` (badges, links, Action reference)
- `pyproject.toml` (`[project.urls]`)
- `action.yml` is fine as-is once the repo exists
- `docs/findings.md` (link back to README is relative — fine)

```bash
grep -rl YOUR_USERNAME . | grep -v .git
```

## Version bump

Update `version` in `pyproject.toml` and `__version__` in `agent_lint/__init__.py` (keep them in
sync), add a `CHANGELOG.md` entry, tag `vX.Y.Z`.
