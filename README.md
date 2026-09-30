# IIoT Decentralized Identity and Access-Control Framework

A single-zone Industrial Internet of Things (IIoT) identity framework that demonstrates secure device onboarding, decentralized identifiers, ECC proof-of-possession, Merkle-tree identity proofs, temporary JWT authorization, permanent identity-based access, and immediate revocation.

The project uses a FastAPI fog node, simulated IIoT devices, SQLite persistence, and a Streamlit dashboard.

## Main Features

- Nonce-based PSK authentication using HMAC-SHA256
- ECDSA P-256 device keys and proof-of-possession
- Decentralized identifier (DID) generation
- SHA-256 Merkle tree construction
- Trusted epoch/root registry
- Merkle inclusion-proof generation and verification
- Short-lived JWT access tokens
- Temporary token-based resource access
- Permanent Merkle-identity-based access
- Immediate device and token revocation
- Security-attack demonstrations
- Automated pytest suite
- Streamlit frontend for the complete workflow

## Technology Stack

- Python 3.11 or later
- FastAPI and Uvicorn
- Streamlit
- SQLite and SQLAlchemy
- ECDSA P-256
- SHA-256 and HMAC-SHA256
- JWT
- HTTPX
- pandas
- pytest

## Project Structure

```text
iiot-identity-framework/
├── dashboard/
│   └── full_dashboard.py       # Complete Streamlit user interface
├── devices/
│   ├── device.py               # Simulated IIoT device and cryptographic operations
│   └── simulator.py            # Command-line registration demonstration
├── fog/
│   ├── app.py                  # FastAPI application and routes
│   ├── database.py             # Database configuration
│   ├── models.py               # SQLAlchemy models
│   ├── schemas.py              # API request/response models
│   ├── registration.py         # PSK and proof-of-possession registration
│   ├── merkle.py               # Merkle tree and inclusion proofs
│   ├── token_service.py        # Temporary JWT issuance and validation
│   ├── access_service.py       # Temporary and permanent access decisions
│   ├── verification.py         # Permanent identity verification
│   └── revocation.py           # Device and token revocation
├── tests/                      # Automated tests
├── performance/                # Integrated benchmark and generated results
├── docs/                       # Contracts, security evaluation and contributions
├── data/                       # Generated SQLite database and demo output
├── requirements.txt
└── README.md
```

## Installation

Open the project folder in VS Code and run the following commands in PowerShell.

### 1. Create the virtual environment

If Python is available through the `python` command:

```powershell
python -m venv .venv
```

### 2. Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, allow scripts only for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Ensure `requirements.txt` includes `streamlit`, `httpx`, and `pandas` for the dashboard.

## Running the Complete Project

The API and dashboard run in two separate terminals.

### Terminal 1: Start the fog API

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn fog.app:app --reload
```

The API is available at:

- Health check: <http://127.0.0.1:8000/health>
- Swagger API documentation: <http://127.0.0.1:8000/docs>

Keep this terminal running.

### Terminal 2: Start the Streamlit dashboard

```powershell
.\.venv\Scripts\Activate.ps1
python -m streamlit run dashboard/full_dashboard.py
```

Open the dashboard at:

<http://localhost:8501>

## Recommended Demonstration Order

Use the dashboard tabs from left to right:

1. **Registration:** Register one device or all demonstration devices. The dashboard performs PSK authentication and ECC proof-of-possession automatically.
2. **Batch and Merkle:** Finalize the pending batch to build a Merkle tree, anchor its trusted root, and activate the devices.
3. **Temporary Access:** Issue a short-lived JWT and use it to request resource access.
4. **Permanent Access:** Load a device's inclusion proof and request access using its permanent Merkle identity.
5. **Revocation:** Revoke a device or temporary token and confirm that revocation takes effect immediately.
6. **Security Attacks:** Demonstrate that tampered tokens, revoked-token replay, forged Merkle proofs, and epoch mismatches are denied.
7. **Registry:** Inspect registered devices and trusted epochs.
8. **Audit Log:** Review events generated during the dashboard session.

For the revoked-token replay demonstration, issue a token first, copy its JTI, revoke that JTI in the Revocation tab, and then run the replay attack.

## Running the Device Simulator

The command-line simulator demonstrates registration of the predefined devices and finalizes their batch:

```powershell
python -m devices.simulator
```

## Running Automated Tests

```powershell
python -m pytest -q
```

The final integrated submission contains **41 passing tests**, including four
consolidated attack demonstrations. Run the tests after every change.

Run only the assignment-level security attacks with:

```powershell
python -m pytest tests/test_security_attacks.py -q
```

## Performance Evaluation

Generate fresh measurements, CSV summaries and four graphs from the final
implementation:

```powershell
python -m performance.benchmark_full_system
```

Results are written to `performance/results/` and automatically displayed in
the dashboard's **Benchmarks** tab. The benchmark repeats device counts 5, 10,
25, 50, 100 and 200 five times using an isolated in-memory database.

## Identity and Access Workflow

```text
Device requests nonce
        ↓
PSK HMAC authentication
        ↓
Device submits DID and ECC public key
        ↓
ECC proof-of-possession challenge
        ↓
Device enters pending registration batch
        ↓
Fog node finalizes Merkle tree and trusted epoch
        ↓
Temporary JWT access or permanent Merkle-proof access
        ↓
Current device/token revocation status checked
        ↓
Access allowed or denied
```

## Security Demonstrations

| Demonstration | Expected protection |
|---|---|
| Tampered JWT | Signature validation rejects the modified token |
| Revoked-token replay | JTI revocation lookup rejects the previously valid token |
| Tampered Merkle proof | Reconstructed root does not match the trusted epoch root |
| Epoch mismatch | Proof and claimed trusted epoch do not match |

See `docs/SECURITY_EVALUATION.md` for the attacker model, detecting component
and expected denial code. See `docs/CONTRIBUTIONS.md` for the three-member work
division and integration decisions.

An old Merkle proof may remain historically valid after device revocation, but it must not authorize current access. The authorization path therefore checks both cryptographic membership and current revocation state.

## Resetting Local Demonstration Data

Stop the API before removing the local SQLite database:

```powershell
Remove-Item .\data\iiot.db -ErrorAction SilentlyContinue
```

Restart the API afterward. The database tables are recreated by the application.

## Notes

- This is an educational single-zone prototype.
- The local trusted-root registry simulates an immutable root anchor.
- Production deployment would require HTTPS, secure secret storage, protected administrative revocation endpoints, key rotation, rate limiting, and a distributed or blockchain-backed root registry.
