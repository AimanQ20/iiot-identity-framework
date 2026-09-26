# Single-Zone IIoT Decentralized Identity Framework

Shared starter repository for a two-member implementation of the complete device-to-fog identity lifecycle.

## Setup (VS Code / PowerShell)

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn fog.app:app --reload
```

Open `http://127.0.0.1:8000/docs` to test the API.

Run tests:

```powershell
pytest -q
```

## Branches

- Member 1: `feature/registration-merkle`
- Member 2: `feature/tokens-access`

Read `docs/CONTRACTS.md` before changing shared request/response formats.

