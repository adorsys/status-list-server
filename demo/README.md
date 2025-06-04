# Demo Workflows with the Status List Server

Typical scenarios for interacting with the Status List Server are showcased
by means of notebooks. To run the notebooks, a live server is required, and
you will need to set up a Python environment.

## Catalog of notebook workflows

You'll find notebooks for the following scenarios in the `./workflows` directory:

- [A Token Issuer maintains a Token Status List at the Status List Server](./workflows/01-an-issuer-maintains-a-status-list.ipynb)
- [Token Issuers can maintain multiple Token Status Lists](./workflows/02-issuers-can-maintain-multiple-status-lists.ipynb)
- [Issuer B cannot update Issuer A's list](./workflows/03-issuer-b-cannot-update-issuer-a-list.ipynb)

## Start a live Status List Server

A live instance of the server is required and should be started independently.
By default, it is assumed the server runs on `http://localhost:8000` or on the
port configured in a `.env` file at the root of the project. But you can
always change this address when running a workflow.

## Create a virtual environment to run the notebooks

The `environment.yml` file encodes a tested working environment that you can
spin up with [conda](https://docs.conda.io/projects/conda/en/stable/index.html).
If you do not already have `conda` installed, you will need to install it first.
Go for the `Miniconda` option if you are unfamiliar with conda distributions.

Once installed, run the following command to replicate the tested environment:

```bash
conda env create -f environment.yml
```

Then activate it with:

```bash
conda activate demo-status-list-server
```

## Run Jupyter notebooks

Run the following command to open the Jupyter Lab interface in your default web
browser, enabling you to explore and run the provided workflows.

```bash
jupyter lab .
```
