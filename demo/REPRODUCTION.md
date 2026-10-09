# Demo notebook failure — reproduction and root cause

This document records the reproduction of the reported demo failure, the root
cause, and how the fix in this PR addresses it. It satisfies the ticket's
requirement that the original failure be reproduced and documented before the
fix is applied.

## Reproduction summary

| Item | Value |
| --- | --- |
| Operating system | Linux (x86_64), CI `ubuntu-latest` |
| Python | 3.12 (`demo/.python-version`) |
| uv | 0.12.x (installed via `astral-sh/setup-uv`) |
| Jupyter Lab launch | `uv run jupyter lab` |
| Failing artifacts | `demo/workflows/01…04-*.ipynb`, Jupyter static assets |
| Error | `AttributeError: 'FileFindHandler' object has no attribute 'allowed_symlink_directory'` |

## What was reproduced

Launching Jupyter Lab with `uv run jupyter lab` started the server process, but
every request to serve a static asset (`/static/lab/main.*.js`,
`/static/favicons/favicon.ico`) returned **HTTP 500** with:

```
AttributeError: 'FileFindHandler' object has no attribute 'allowed_symlink_directory'
```

Because Jupyter Lab could not serve its own static assets, the demo notebooks
could not be opened or run interactively, and there was no non-interactive
command that would execute them either. The demo was effectively unverifiable
end to end.

## Root cause — a `jupyter_server` / `tornado` version incompatibility

The crash was an interaction between `jupyter_server 2.21.0` and `tornado 6.4+`:

- `jupyter_server 2.21.0` defines its own `FileFindHandler`
  (`.../jupyter_server/base/handlers.py:983`) which overrides `initialize()`
  **without calling `super().initialize()`**.
- In tornado 6.4+, `StaticFileHandler.__init__` is what sets
  `self.allowed_symlink_directory`. Because jupyter_server's
  `FileFindHandler.initialize` skips the parent, that attribute was never set on
  the handler.
- tornado 6.5's `_resolve_symlink_target()` (line 3092) unconditionally reads
  `self.allowed_symlink_directory`, so any `/static/*` request raised an
  `AttributeError` and became an HTTP 500.

Why the obvious fixes did not work:

- **Upgrading tornado** (6.5.9 → 6.5.10) did not help — the bug lives in
  jupyter_server, not in a tornado patch level.
- **Downgrading tornado** to 6.4.2 did not help either, because the
  `allowed_symlink_directory` requirement already exists in tornado 6.4+. It was
  also reverted in practice, because `uv run` re-syncs from `uv.lock` on every
  launch, undoing any manual `uv pip install tornado==6.4.2`.
- The real fix was upgrading **`jupyter_server` to 2.21.1**, the release that
  patches this exact issue (it sets `allowed_symlink_directory` per request in
  `validate_absolute_path`).

## How the fix resolves it

The ticket then redirected the whole approach: **replace the Jupyter notebooks
with plain Python scripts**, dropping the Jupyter dependency chain (and this
entire failure class) from the demo.

| Failure mode | Resolution |
| --- | --- |
| Jupyter static-asset HTTP 500 (tornado/jupyter_server) | Notebooks replaced with plain scripts; the Jupyter chain is no longer needed to run the demo. `jupyter-server` bumped to 2.21.1 for the interactive path. |
| Kernel selection / interactive advance | Plain scripts executed by `python`; no kernel. |
| Undeclared certificate | `run-demo-smoke.py` generates ephemeral signing material. |
| Un-isolated / undeclared environment | `uv sync --locked` into `demo/.venv`; fresh state per run. |
| Notebook state / order / prior credentials | Each script uses fresh random issuer labels and UUIDs; the driver runs them from a fresh server with in-memory storage. |
| Rate-limit state leaking between runs | Fresh server per run with `APP_RATE_LIMIT__STRICT_BURST_SIZE` raised. |
| Silent drift from server API | CI `demo-smoke` job executes all four scripts against a freshly started server and fails on any assertion or startup error. |

The scripts retain the exact API interactions and assertions of the notebooks,
so the fix narrows the failure surface to the runtime/verification gap without
weakening coverage.

## Cross-platform boundary

Reproduction and verification were performed on Linux (CI). macOS and Windows
set-up instructions in `demo/README.md` are provided but were **not** exercised
in CI; this boundary is stated explicitly in the README.
