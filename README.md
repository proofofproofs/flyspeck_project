### Miner guide

Register your hotkey on netuid 125, mine by submitting valid proofs signed by your hotkey, and expect emissions at the start of the next 24-hour period after submission.

### Endpoints

- GET `/health`
  - Returns `{ "status": "ok" }`.

- GET `/download_db`
  - Returns the current in-memory theorem database (list of records). Use this to discover which theorem names are available to prove.

- POST `/submit_proof`
  - Body:
    - `hotkey` (string, SS58 address)
    - `name` (string; theorem name key)
    - `proof` (string; MUST start with `by ...`)
    - `signed_data` (string hex or object containing `signature`/`sig`/`signature_hex`)
    - `lemmas` (optional array of Lean declarations)
  - Response: on success, returns the updated theorem record (now `status: "proven"`).

### Message to sign

- You must sign the exact bytes of:
```
"{theorem_name}:::{hotkey_ss58}"
```

Pass that signature as `signed_data` (hex string like `0x...`). The server verifies using:
- `bittensor_wallet.Keypair.verify` if available
- else `substrate-interface` public `Keypair.verify`
- else sr25519/ed25519 libraries

### Example: signing with Substrate (sr25519)

```python
from substrateinterface import Keypair

hot = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
theorem_name = "Math.Test.myThm"
message = f"{theorem_name}:::{hot.ss58_address}".encode()
sig_hex = "0x" + hot.sign(message).hex()

# POST /submit_proof JSON
payload = {
  "hotkey": hot.ss58_address,
  "name": theorem_name,
  "proof": "by exact True.intro",
  "signed_data": sig_hex,
}
```

### Example: signing with Bittensor Wallet SDK

```python
from bittensor_wallet import Wallet

w = Wallet(name="mywallet", hotkey="miner")
hk = w.get_hotkey(password=None)
msg = f"{theorem_name}:::{hk.ss58_address}".encode()
sig_hex = "0x" + hk.sign(msg).hex()
```

### Theorem database format

Each record looks like:
```json
{
  "file": "FormalConjectures/Arxiv/2107.12475/CollatzLike.lean",
  "name": "CollatzLike",
  "attrs": ["@[category research open, AMS 5 11]"],
  "stmt": "theorem CollatzLike (n : ℕ) (hn : 8 < n) : 2 ∈ Nat.digits 3 (2^n)",
  "status": "unproven"
}
```

- When you submit a proof, the server constructs a Lean file as:
  - Namespace-wrapped from `name`
  - Uses `stmt` to extract the proposition and attaches your `by ...` proof
  - Optionally inserts your `lemmas` at the top (subject to sanitization)

### Security and constraints

- Proofs must start with `by`.
- Disallowed tokens (blocked in proofs, lemmas, and attributes):
  - `axiom`, `axioms`, `sorry`, `admit`, `unsafe`, `run_cmd`, `initialize`, `macro`, `elab`, `command`, `syntax`, `import`, `open System`, `Lean`, `IO.`, `#eval`, `#check`, `#print`, `#reduce`, `set_option`, `System`, `os.system`, `IO.Process`, `extern`.
- Unicode and whitespace are normalized before scanning.
- All lean is run in an unpriviledged container
- The Lean process runs with resource limits by default:
  - Wall/CPU timeout: `LEAN_TIMEOUT_SECS` (default 120s)
  - Memory cap: `LEAN_MEMORY_LIMIT_BYTES` (default 16 GiB)
  - Output is truncated to 1MB.

### Troubleshooting

- Signature rejected: ensure you sign exactly `"{theorem_name}:::{hotkey_ss58}"` and submit the same `hotkey_ss58`.
- Lean fails to import Mathlib: set `LAKE_PROJECT_DIR` to a Mathlib-enabled project or install Mathlib for your Lean.
- Disallowed token error: remove unsafe constructs. Only tactic/script proofs (`by ...`) are accepted.

Happy mining!


### Validator quick start

- Runs on nearly any hardware. Low CPU/memory; no GPU required.
- Uses the public API at `http://65.109.75.37:8000` by default (configurable) and the Bittensor chain to set weights.

Requirements (Ubuntu/Debian minimal):
- Python 3.10+ and pip
- Python packages: `bittensor`, `httpx` (PyPI). `torch` is optional (used to pass tensors to `set_weights`), the script falls back to plain lists if not present.

Install:
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip wheel
pip install bittensor httpx torch
```

Run the validator (uses defaults from `config.py`):
```bash
python3 validator.py \
  --wallet.name wallet \
  --wallet.hotkey validator
```

What it does:
- Every 360 blocks (configurable via `--interval-blocks`) it fetches recent proofs from the API (last 24 hours by default) and computes weights per UID based on solved proof weights.
- If no proofs were solved in the window, it assigns 100% weight to UID 0 by default.

Common options:
- `--api-base` (default `http://65.109.75.37:8000`) – proof server API
- `--hours` (default `24`) – lookback window for recent proofs
- `--interval-blocks` (default `360`) – how often to set weights
- `--netuid` (default `125`) – subnet to operate on
- `--network finney` or `--chain-endpoint wss://...` – Bittensor chain selection
- `--dry-run` – compute and print weights without submitting

