# Demo Workflows with the Status List Server

Typical scenarios for interacting with the Status List Server are showcased
by means of plain Python scripts. To run them, you will need a Python environment
and a live server. The setup works on macOS, Linux, and Windows; Linux is the
only platform exercised in CI (see [Smoke check](#smoke-check)).

## Catalog of workflow scripts

You'll find the following scenarios in the `./workflows` directory:

- [A Token Issuer maintains a Token Status List at the Status List Server](./workflows/01-an-issuer-maintains-a-status-list.py)
- [Token Issuers can maintain multiple Token Status Lists](./workflows/02-issuers-can-maintain-multiple-status-lists.py)
- [Issuer B cannot update Issuer A's list](./workflows/03-issuer-b-cannot-update-issuer-a-list.py)
- [Unregistered issuers cannot publish lists](./workflows/04-unregistered-issuers-cannot-publish-lists.py)

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

If behind a TLS-intercepting proxy, set `UV_SYSTEM_CERTS=1`.

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
request per minute, which is less than the workflow scripts need when run back
to back. The commands below raise the limit to 100 for this local server,
enough for several full runs of all four workflow scripts.

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

If a workflow still fails with HTTP `429`, restart the server. The limit
refills slowly, so waiting a minute only allows one more request, and requests
rejected for missing or invalid authentication count against it too.

The workflow scripts connect to `http://localhost:8000` by default. If
`APP_SERVER__PORT` is set in the environment, or in a `.env` file at the root of
the repository, the scripts use that port instead.

## Run the workflows

Each workflow is a plain Python script in `./workflows`. With a live server
running (see above), execute one from the `demo` directory:

```bash
uv run python workflows/01-an-issuer-maintains-a-status-list.py
```

Each script uses fresh random issuer credentials and status list IDs, so a run
never depends on state left behind by an earlier one. An assertion failure exits
non-zero and names the failing script.

To use an IDE instead, select the interpreter in `demo/.venv` as the Python
interpreter for the `demo` directory.

## Smoke check

The repository runs every workflow script end to end against a freshly started
server in CI, so the scripts cannot silently drift from the server API or the
setup instructions. The same driver is available locally as a one-shot,
non-interactive command. This is the single command to run all four workflows
end to end: it does **not** require the manual environment, certificate, or
server-start steps above — it provisions everything itself.

```bash
uv run python run-demo-smoke.py
```

From a clean checkout it:

1. syncs the isolated demo environment with `uv sync --locked`;
2. generates temporary signing material (self-signed certificate and key);
3. starts the Status List Server on a free port with in-memory storage and a
   raised rate limit;
4. executes all four workflow scripts in order from fresh state;
5. stops the server and removes the temporary material even on failure.

On failure, the exit code is non-zero and the logs (server and per-workflow) are
kept and reported so the owning script can be identified. The retained material
also includes the freshly generated signing key and certificate; these are
throwaway self-signed demo credentials (never committed) and are kept so the
server and workflow logs remain inspectable when uploaded as CI artifacts. The
smoke check is covered in CI by the `demo-smoke` job (Linux only), which runs
this driver **twice** with a bounded timeout (proving repeated runs are
isolated), then asserts that `demo/workflows` is unchanged by execution, and
uploads the logs as artifacts when it fails.

## Start the demo interactively

To explore the workflows by hand instead of running them headlessly, use the
same driver in interactive mode. It starts the server with temporary signing
material and in-memory storage, then opens Jupyter Lab rooted at the `demo`
directory so you can run and step through the workflow scripts. The scripts are
plain Python files (not notebooks), so in Jupyter Lab each opens in a code
editor; you can run them with the editor's "Run" action, or in your IDE of
choice (select the interpreter in `demo/.venv`). The server stays up for the
whole session and is stopped (and the temporary material removed) when you exit
Jupyter.

```bash
uv run python run-demo-smoke.py --interactive
```

## Update dependencies

After changing the dependencies in `pyproject.toml`, refresh the lock file and
the pip fallback, then commit both:

```bash
uv lock
uv export --format requirements-txt -o requirements.txt
```
