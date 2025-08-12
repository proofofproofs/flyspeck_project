#!/usr/bin/env python3
import argparse
import json
import os
import sys
import textwrap
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    from bittensor_wallet import Wallet, Keypair as BTKeypair  # type: ignore
except Exception:
    try:
        from btwallet.wallet import Wallet  # type: ignore
        BTKeypair = None  # type: ignore[assignment]
    except Exception:
        Wallet = None  # type: ignore[assignment]
        BTKeypair = None  # type: ignore[assignment]

import urllib.request
import urllib.error
from config import DEFAULT_API_BASE


DEFAULT_SERVER = DEFAULT_API_BASE


@dataclass
class Theorem:
    file: str
    name: str
    attrs: List[str]
    stmt: str
    status: str
    weight: int


def http_get_json(url: str, timeout: float = 30.0) -> Any:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        if not data:
            return None
        return json.loads(data.decode("utf-8"))


def http_post_json(url: str, payload: Dict[str, Any], timeout: float = 60.0) -> Tuple[int, Any, Dict[str, str]]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.getcode() or 200
            ct = resp.headers.get("content-type", "")
            parsed = json.loads(body.decode("utf-8")) if body and "json" in ct else body.decode("utf-8")
            return status, parsed, dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        ct = e.headers.get("content-type", "") if e.headers else ""
        parsed = json.loads(body.decode("utf-8")) if body and "json" in ct else body.decode("utf-8")
        return e.code, parsed, dict(e.headers or {})


def fetch_unsolved(server: str) -> List[Theorem]:
    url = server.rstrip("/") + "/download_db"
    obj = http_get_json(url)
    results: List[Theorem] = []
    if not isinstance(obj, list):
        return results
    for th in obj:
        try:
            status = str(th.get("status", "unproven")).lower()
            if status != "unproven":
                continue
            results.append(
                Theorem(
                    file=str(th.get("file", "")),
                    name=str(th.get("name", "")),
                    attrs=list(th.get("attrs", []) or []),
                    stmt=str(th.get("stmt", "")),
                    status=status,
                    weight=int(th.get("weight", 1) or 1),
                )
            )
        except Exception:
            continue
    return results


def wrap_lines(text: str, width: int = 100, indent: int = 2) -> str:
    prefix = " " * indent
    return textwrap.fill(text, width=width, subsequent_indent=prefix, initial_indent=prefix)


def print_unsolved(theorems: List[Theorem], limit: Optional[int] = None) -> None:
    if limit is not None:
        theorems = theorems[: max(0, limit)]
    if not theorems:
        print("No unproven theorems found.")
        return
    for idx, th in enumerate(theorems):
        attrs = ", ".join(th.attrs) if th.attrs else ""
        header = f"[{idx}] name: {th.name} | weight: {th.weight} | file: {th.file}"
        if attrs:
            header += f" | attrs: {attrs}"
        print(header)
        print(wrap_lines(f"stmt: {th.stmt}"))
        print()


def ensure_proof_format(proof_text: str) -> str:
    t = proof_text.strip()
    return t if t.startswith("by") else f"by\n{t}"


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def sign_with_wallet(message_bytes: bytes, wallet_name: str, wallet_hotkey_label: str, wallet_path: Optional[str], wallet_password: Optional[str]) -> Tuple[str, str]:
    if Wallet is None:
        raise RuntimeError("bittensor_wallet is required for wallet signing (or provide --signature-hex and --hotkey-ss58)")
    w = Wallet(name=wallet_name, hotkey=wallet_hotkey_label, path=wallet_path or "~/.bittensor/wallets/")  # type: ignore[arg-type]
    hk = w.get_hotkey(password=wallet_password)  # returns a Keypair-like object
    try:
        sig_bytes = hk.sign(message_bytes, wallet_password)
    except TypeError:
        sig_bytes = hk.sign(message_bytes)
    sig_hex = "0x" + sig_bytes.hex()
    ss58 = getattr(hk, "ss58_address", None)
    if not ss58:
        raise RuntimeError("Could not obtain ss58_address from wallet hotkey")
    return sig_hex, ss58


def collect_lemmas(lemma_files: List[str], lemma_inline: List[str]) -> List[str]:
    out: List[str] = []
    for p in lemma_files:
        out.append(read_file(p))
    out.extend(lemma_inline)
    return out


def submit(
    server: str,
    theorem_name: str,
    proof_text: str,
    hotkey_ss58: str,
    signature_hex: str,
    lemmas: Optional[List[str]],
    timeout: float = 120.0,
) -> Tuple[int, Any]:
    payload: Dict[str, Any] = {
        "hotkey": hotkey_ss58,
        "name": theorem_name,
        "proof": ensure_proof_format(proof_text),
        "signed_data": signature_hex,
    }
    if lemmas:
        payload["lemmas"] = lemmas
    url = server.rstrip("/") + "/submit_proof"
    status, resp, _ = http_post_json(url, payload, timeout=timeout)
    return status, resp


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="List and submit Lean proofs to the server.")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="Server base URL e.g. http://127.0.0.1:8000")
    parser.add_argument("--read", action="store_true", help="List unproven theorems and exit")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of theorems to display")

    parser.add_argument("--theorem-name", help="Full theorem name to submit (matches JSONL 'name')")
    parser.add_argument("--proof-file", help="Path to a file containing the proof text")
    parser.add_argument("--proof", help="Inline proof text (alternative to --proof-file)")

    parser.add_argument("--lemma-file", action="append", default=[], help="Path to lemma file(s)")
    parser.add_argument("--lemma", action="append", default=[], help="Inline lemma(s)")

    parser.add_argument("--wallet.name", dest="wallet_name", required=True, help="Bittensor wallet name")
    parser.add_argument("--wallet.hotkey", dest="wallet_hotkey", required=True, help="Bittensor wallet hotkey label (e.g., 'miner')")
    parser.add_argument("--wallet.path", dest="wallet_path", default=os.environ.get("BT_WALLET_PATH", "~/.bittensor/wallets/"), help="Wallet root path")
    parser.add_argument("--wallet.password", dest="wallet_password", default=os.environ.get("BT_WALLET_PASSWORD"), help="Wallet password (optional)")

    parser.add_argument("--signature-hex", help="Precomputed signature hex for message 'name:::hotkey' (use with --hotkey-ss58)")
    parser.add_argument("--hotkey-ss58", help="Override SS58 hotkey address; required if using --signature-hex without a wallet")

    parser.add_argument("--submit", action="store_true", help="Submit proof")
    parser.add_argument("--timeout", type=float, default=180.0, help="HTTP timeout seconds for submit")

    args = parser.parse_args(argv)

    server = args.server

    if args.read or not args.submit:
        try:
            theorems = fetch_unsolved(server)
        except Exception as e:
            print(f"Failed to fetch theorems: {e}", file=sys.stderr)
            return 2
        print_unsolved(theorems, limit=args.limit)
        if not args.submit:
            return 0

    if args.submit:
        if not args.theorem_name:
            print("--theorem-name is required for submission", file=sys.stderr)
            return 2
        proof_text = ""
        if args.proof_file:
            try:
                proof_text = read_file(args.proof_file)
            except Exception as e:
                print(f"Failed to read --proof-file: {e}", file=sys.stderr)
                return 2
        elif args.proof:
            proof_text = args.proof
        else:
            print("Provide --proof-file or --proof", file=sys.stderr)
            return 2

        lemmas = collect_lemmas(args.lemma_file or [], args.lemma or [])

        message_bytes: Optional[bytes] = None
        hotkey_ss58: Optional[str] = None
        sig_hex: Optional[str] = args.signature_hex

        if sig_hex:
            if args.hotkey_ss58:
                hotkey_ss58 = args.hotkey_ss58
            elif Wallet is not None:
                try:
                    w = Wallet(name=args.wallet_name, hotkey=args.wallet_hotkey, path=args.wallet_path)  # type: ignore[arg-type]
                    hk = w.get_hotkey(password=args.wallet_password)
                    hotkey_ss58 = getattr(hk, "ss58_address", None)
                except Exception:
                    hotkey_ss58 = None
            if not hotkey_ss58:
                print("Provide --hotkey-ss58 along with --signature-hex, or ensure wallet is available to derive ss58.", file=sys.stderr)
                return 2
            message_bytes = f"{args.theorem_name}:::{hotkey_ss58}".encode("utf-8")
        else:
            try:
                tmp_sig, tmp_ss58 = sign_with_wallet(b"", args.wallet_name, args.wallet_hotkey, args.wallet_path, args.wallet_password)
                message_bytes = f"{args.theorem_name}:::{tmp_ss58}".encode("utf-8")
                sig_hex, hotkey_ss58 = sign_with_wallet(message_bytes, args.wallet_name, args.wallet_hotkey, args.wallet_path, args.wallet_password)
            except Exception as e:
                print(f"Wallet signing failed: {e}", file=sys.stderr)
                return 2

        try:
            status, resp = submit(
                server=server,
                theorem_name=args.theorem_name,
                proof_text=proof_text,
                hotkey_ss58=hotkey_ss58,
                signature_hex=sig_hex,
                lemmas=lemmas if lemmas else None,
                timeout=args.timeout,
            )
        except Exception as e:
            print(f"Submission failed: {e}", file=sys.stderr)
            return 2

        if isinstance(resp, dict) and "detail" in resp and status >= 400:
            print(json.dumps(resp, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps(resp, ensure_ascii=False, indent=2))
        return 0 if status < 400 else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())



