# Demo Workflows with the Status List Server

Typical scenarios for interacting with the Status List Server are showcased
by means of notebooks. To run the notebooks, you will need a Python environment
and a live server. The setup works on macOS, Linux, and Windows.

## Catalog of notebook workflows

You'll find notebooks for the following scenarios in the `./workflows` directory:

- [A Token Issuer maintains a Token Status List at the Status List Server](./workflows/01-an-issuer-maintains-a-status-list.ipynb)
- [Token Issuers can maintain multiple Token Status Lists](./workflows/02-issuers-can-maintain-multiple-status-lists.ipynb)
- [Issuer B cannot update Issuer A's list](./workflows/03-issuer-b-cannot-update-issuer-a-list.ipynb)
- [Unregistered issuers cannot publish lists](./workflows/04-unregistered-issuers-cannot-publish-lists.ipynb)

## Set up the Python environment

Run the commands in this section from the `demo` directory. Both options create
the environment in `demo/.venv`.

### Option 1: uv (recommended)

[uv](https://docs.astral.sh/uv/) installs the Python version pinned in
`.python-version` and the exact dependencies locked in `uv.lock`.

Install uv on macOS or Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On macOS, `brew install uv` works as well.

Install uv on Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

On Windows, `winget install --id=astral-sh.uv -e` works as well.

Create the environment:

```bash
uv sync
```

If your network uses a TLS-intercepting proxy, uv can fail with certificate
errors. Set `UV_SYSTEM_CERTS=1` so uv trusts the operating system's certificate
store:

| Shell      | Command                      |
| ---------- | ---------------------------- |
| bash / zsh | `export UV_SYSTEM_CERTS=1`   |
| PowerShell | `$env:UV_SYSTEM_CERTS = "1"` |
| cmd        | `set UV_SYSTEM_CERTS=1`      |

If `uv help sync` does not list `UV_SYSTEM_CERTS`, your uv release predates it;
set `UV_NATIVE_TLS=1` the same way instead. Newer releases still accept
`UV_NATIVE_TLS`.

### Option 2: pip

Python 3.10, 3.11, or 3.12 is required. Create and activate a virtual
environment, then install the dependencies. If your default interpreter is
newer, name a supported one explicitly, for example `python3.12` instead of
`python3`, or `py -3.12` instead of `py`.

macOS or Linux (bash / zsh):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell refuses to run the activation script, run
`Set-ExecutionPolicy -Scope Process RemoteSigned` and try again.

Windows (cmd):

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

`requirements.txt` pins every package by hash, so pip rejects any extra package
listed in the same install command. Install additional packages with a separate
`pip install` command.

With this option, drop the `uv run` prefix from the commands below and run them
inside the activated environment.

## Start a live Status List Server

The server signs status list tokens, so it needs a certificate and a matching
signing key. Generate a self-signed pair for local development once, from the
`demo` directory:

```bash
uv run python generate-dev-cert.py
```

This writes `tls.crt` and `tls.key` to the root of the repository; both are
ignored by Git. Existing files are kept unless you pass `--force`.

Then start the server with in-memory storage from the root of the repository;
no `.env` file or database is needed.

The server rate-limits credential registration and status list writes per
client IP address. By default each allows 10 requests and then gets back one
request per minute, which is less than the notebooks need when run back to back.
The commands below raise the limit to 100 for this local server, enough for
several full runs of all four notebooks.

macOS or Linux (bash / zsh):

```bash
APP_SERVER__CERT__STORE__CERTIFICATE_PATH=tls.crt \
APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=tls.key \
APP_RATE_LIMIT__STRICT_BURST_SIZE=100 \
cargo run
```

Windows (PowerShell):

```powershell
$env:APP_SERVER__CERT__STORE__CERTIFICATE_PATH = "tls.crt"
$env:APP_SERVER__CERT__STORE__SIGNING_KEY_PATH = "tls.key"
$env:APP_RATE_LIMIT__STRICT_BURST_SIZE = "100"
cargo run
```

Windows (cmd):

```bat
set APP_SERVER__CERT__STORE__CERTIFICATE_PATH=tls.crt
set APP_SERVER__CERT__STORE__SIGNING_KEY_PATH=tls.key
set APP_RATE_LIMIT__STRICT_BURST_SIZE=100
cargo run
```

If a cell still fails with HTTP `429`, restart the server. The limit refills
slowly, so waiting a minute only allows one more request, and requests rejected
for missing or invalid authentication count against it too.

The notebooks connect to `http://localhost:8000` by default. If
`APP_SERVER__PORT` is set in the environment of the notebook kernel, or in a
`.env` file at the root of the repository, the notebooks use that port instead.

## Run the notebooks

From the `demo` directory, open Jupyter Lab to explore and run the workflows:

```bash
uv run jupyter lab
```

To execute a notebook top to bottom without opening Jupyter Lab:

```bash
uv run jupyter execute workflows/01-an-issuer-maintains-a-status-list.ipynb
```

To use an IDE instead, select the interpreter in `demo/.venv` as the kernel:

- **VS Code**: open a notebook, click **Select Kernel**, choose
  **Python Environments**, and pick the interpreter in `demo/.venv`.
- **PyCharm**: open **Settings** > **Python Interpreter**, choose
  **Add Interpreter** > **Add Local Interpreter**, select an existing
  environment, and point it to `demo/.venv/bin/python` (macOS, Linux) or
  `demo\.venv\Scripts\python.exe` (Windows).

## Update dependencies

After changing the dependencies in `pyproject.toml`, refresh the lock file and
the pip fallback, then commit both:

```bash
uv lock
uv export --format requirements-txt -o requirements.txt
```
