from __future__ import annotations

import base64
from typing import Any, Dict, Tuple, Union

try:
    from bittensor_wallet import Wallet, Keypair as BTKeypair  # type: ignore
except Exception:
    Wallet = None  # type: ignore[assignment]
    BTKeypair = None  # type: ignore[assignment]

try:
    # Optional cross-verification helper
    from substrateinterface import Keypair as SubstrateKeypair  # type: ignore
except Exception:
    SubstrateKeypair = None  # type: ignore[assignment]


def _to_bytes_flexible(data: Union[str, bytes, bytearray, Dict[str, Any]]) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, dict):
        import json as _json
        return _json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if isinstance(data, str):
        s = data.strip()
        # hex (with or without 0x)
        try:
            if s.startswith("0x"):
                s = s[2:]
            return bytes.fromhex(s)
        except Exception:
            pass
        # base64
        try:
            return base64.b64decode(s)
        except Exception:
            pass
        # plain utf-8 text
        return s.encode("utf-8")
    raise TypeError(f"Unsupported data type: {type(data)}")


def verify_hotkey_signature(
    message: Union[str, bytes, bytearray, Dict[str, Any]],
    signature: Union[str, bytes, bytearray],
    hotkey_ss58: str,
) -> bool:
    msg = _to_bytes_flexible(message)
    sig = _to_bytes_flexible(signature)

    if BTKeypair is not None:
        try:
            verifier = BTKeypair(ss58_address=hotkey_ss58)
            if verifier.verify(msg, sig):
                return True
        except Exception:
            pass

    if SubstrateKeypair is not None:
        try:
            verifier = SubstrateKeypair(ss58_address=hotkey_ss58)
            if verifier.verify(msg, sig):
                return True
        except Exception:
            pass

    return False


def verify_signature(
    data: Union[str, bytes, bytearray, Dict[str, Any]],
    signature: Union[str, bytes, bytearray],
    hotkey_ss58: str,
) -> bool:
    return verify_hotkey_signature(data, signature, hotkey_ss58)


def load_wallet(wallet_name: str, wallet_hotkey: str, wallet_path: str = "~/.bittensor/wallets/") -> Wallet:  # type: ignore[override]
    if Wallet is None:
        raise ImportError("bittensor_wallet is required to load a wallet")
    return Wallet(name=wallet_name, hotkey=wallet_hotkey, path=wallet_path)  # type: ignore[arg-type]


def sign_with_hotkey(
    wallet_name: str,
    wallet_hotkey: str,
    data: Union[str, bytes, bytearray, Dict[str, Any]],
    wallet_path: str = "~/.bittensor/wallets/",
    password: str | None = None,
) -> Tuple[str, str]:
    if Wallet is None:
        raise ImportError("bittensor_wallet is required to sign data")
    w = load_wallet(wallet_name, wallet_hotkey, wallet_path)
    hk = w.get_hotkey(password)
    msg = _to_bytes_flexible(data)
    sig_bytes = hk.sign(msg, password) if password is not None else hk.sign(msg)
    return "0x" + sig_bytes.hex(), hk.ss58_address

