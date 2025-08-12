from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict, List, Tuple

import httpx
from config import DEFAULT_API_BASE, DEFAULT_NETUID


def log(msg: str) -> None:
    print(f"[validator] {msg}", flush=True)


def fetch_recent_proven(api_base: str, hours: int = 24, timeout: float = 15.0) -> List[dict]:
    url = api_base.rstrip("/") + f"/download_recent_proven?hours={hours}"
    with httpx.Client(timeout=timeout) as client:
        r = client.get(url)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError("Unexpected response shape from /download_recent_proven")
        return data


def uid_mapping_for_hotkeys(subtensor, netuid: int) -> Dict[str, int]:
    mtg = subtensor.metagraph(netuid)
    mapping: Dict[str, int] = {}
    for uid, hk in enumerate(mtg.hotkeys):
        mapping[str(hk)] = int(uid)
    return mapping


def build_uid_weights(records: List[dict], hotkey_to_uid: Dict[str, int]) -> Tuple[List[int], List[float]]:
    # Sum per-hotkey weights
    per_hotkey: Dict[str, float] = {}
    for rec in records:
        hk = rec.get("hotkey")
        if not hk:
            continue
        try:
            w = float(rec.get("weight", 1))
        except Exception:
            w = 1.0
        per_hotkey[hk] = per_hotkey.get(hk, 0.0) + max(0.0, w)

    # Map to UIDs
    uid_to_weight: Dict[int, float] = {}
    for hk, w in per_hotkey.items():
        uid = hotkey_to_uid.get(hk)
        if uid is None:
            continue
        uid_to_weight[uid] = uid_to_weight.get(uid, 0.0) + w

    if not uid_to_weight:
        return [], []

    # Normalize to sum to 1.0
    total = sum(uid_to_weight.values())
    if total <= 0:
        return [], []
    uids = sorted(uid_to_weight.keys())
    weights = [uid_to_weight[u] / total for u in uids]
    print("weights: ", weights)
    return uids, weights


def get_current_block(subtensor) -> int:
    try:
        return int(subtensor.block)
    except Exception:
        try:
            return int(subtensor.get_current_block())
        except Exception:
            return -1


def set_weights_on_chain(subtensor, wallet, netuid: int, uids: List[int], weights: List[float]) -> bool:
    if not uids:
        log("No UIDs to set weights for; skipping")
        return False
    try:
        import torch

        wts = torch.tensor(weights, dtype=torch.float32)
    except Exception:
        wts = weights  # type: ignore[assignment]
    try:
        ok = subtensor.set_weights(
            netuid=netuid,
            wallet=wallet,
            uids=uids,
            weights=wts,
            wait_for_finalization=True,
        )
        return bool(ok)
    except Exception as e:
        log(f"Failed to set weights: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Validator script to set subnet weights from recent proven theorems")
    parser.add_argument("--api-base", default=os.environ.get("APP_API_BASE", DEFAULT_API_BASE), help="Base URL of the proof server API")
    parser.add_argument("--hours", type=int, default=24, help="Window of recent proofs to consider (hours)")
    parser.add_argument("--interval-blocks", type=int, default=360, help="Recompute and set weights every N blocks")
    parser.add_argument("--netuid", type=int, default=int(os.environ.get("NETUID", str(DEFAULT_NETUID))), help="Subnet netuid")
    parser.add_argument("--network", default=os.environ.get("BT_NETWORK", "finney"), help="Bittensor network (e.g., finney)")
    parser.add_argument("--chain-endpoint", default=os.environ.get("BT_ENDPOINT"), help="Custom chain endpoint; overrides network if set")
    parser.add_argument("--wallet.name", dest="wallet_name", required=True, help="Wallet name")
    parser.add_argument("--wallet.hotkey", dest="wallet_hotkey", required=True, help="Wallet hotkey")
    parser.add_argument("--wallet.path", dest="wallet_path", default=os.environ.get("BT_WALLET_PATH", "~/.bittensor/wallets/"), help="Wallet path")
    parser.add_argument("--poll-secs", type=float, default=12.0, help="Polling interval for block height")
    parser.add_argument("--dry-run", action="store_true", help="Print computed weights without setting on-chain")
    args = parser.parse_args()

    try:
        import bittensor as bt
    except Exception as e:
        log(f"bittensor is required to run validator: {e}")
        sys.exit(1)

    wallet = bt.wallet(name=args.wallet_name, hotkey=args.wallet_hotkey, path=args.wallet_path)
    if args.chain_endpoint:
        subtensor = bt.subtensor(chain_endpoint=args.chain_endpoint)
    else:
        subtensor = bt.subtensor(network=args.network)

    last_set_block = -10**9
    while True:
        try:
            blk = get_current_block(subtensor)
            if blk < 0:
                log("Could not read current block; retrying")
                time.sleep(args.poll_secs)
                continue

            if blk - last_set_block >= args.interval_blocks:
                log(f"Building weights at block {blk}")
                records = fetch_recent_proven(args.api_base, hours=args.hours)
                mapping = uid_mapping_for_hotkeys(subtensor, args.netuid)
                uids, weights = build_uid_weights(records, mapping)

                # Fallback: if no proofs/weights, assign all weight to UID 0
                if not uids:
                    try:
                        mtg = subtensor.metagraph(args.netuid)
                        total = len(mtg.hotkeys)
                    except Exception:
                        total = 0
                    if total > 0:
                        uids, weights = [0], [1.0]
                        log("No eligible proofs in window; defaulting weights to UID 0")
                    else:
                        log("Metagraph empty; skipping set_weights")
                        time.sleep(args.poll_secs)
                        continue

                log(f"Setting weights for {len(uids)} uids; total weight = 1.0")
                if args.dry_run:
                    log(f"UIDs: {uids}")
                    log(f"Weights: {weights}")
                else:
                    ok = set_weights_on_chain(subtensor, wallet, args.netuid, uids, weights)
                    if ok:
                        last_set_block = blk
                        log("Weights set successfully")
                    else:
                        log("Weights set failed; will retry next interval")
            time.sleep(args.poll_secs)
        except KeyboardInterrupt:
            log("Exiting on Ctrl-C")
            break
        except Exception as e:
            log(f"Unexpected error: {e}")
            time.sleep(args.poll_secs)


if __name__ == "__main__":
    main()
