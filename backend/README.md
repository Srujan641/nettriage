# nettriage (backend)

The diagnostic engine, CLI, packet-capture analyser and local API. See the project README one level up.

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e ".[api,dev]"
./.venv/bin/nettriage example.com        # CLI
./.venv/bin/nettriage serve              # API on http://127.0.0.1:8000
./.venv/bin/pytest                       # tests
```
