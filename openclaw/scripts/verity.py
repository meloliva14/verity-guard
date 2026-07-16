#!/usr/bin/env python3
"""verity-guard — VerityLayer's independent, fail-closed checks, for OpenClaw.

Reads the wallet key from the VERITY_WALLET_KEY environment variable ONLY. It is never
accepted as an argument, because a key on a command line leaks into process lists, shell
history, and exec-approval prompts. It never leaves this process: it signs an EIP-3009
authorization locally for the exact amount each challenge discloses, and VerityLayer only
ever receives the signature.

Prints one JSON object to stdout. The exit code is the contract:

    0  a real verdict came back
    2  payment required (no key, or the wallet cannot cover the disclosed price)
    3  the check did not happen (unreachable / timeout / bad response)
    1  usage error

Anything non-zero means NO VERDICT EXISTS. Never treat it as "allow", and never report a
verification that did not happen.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ENV_KEY = "VERITY_WALLET_KEY"
INSTALL_HINT = (
    "verity-guard is not installed. Install the client once with:\n"
    "    pip install \"verity-guard[x402]\""
)

# kind -> (client method, payload arg name, allowed tiers, default tier)
COMMANDS = {
    "check": ("guard", "action", ("quick", "standard", "pro"), "quick"),
    "verify": ("verify", "claim", ("quick", "grounded", "pro"), "quick"),
    "injection": ("detect_injection", "content", ("quick", "standard", "pro"), "quick"),
    "redact": ("redact", "payload", ("quick", "standard", "pro"), "quick"),
}


def _die(code: int, error: str, **extra: object) -> None:
    json.dump({"error": error, **extra}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    raise SystemExit(code)


def _client(paid: bool):
    try:
        from verity_guard import VerityClient
    except ImportError:
        _die(3, INSTALL_HINT)
    if not paid:
        return VerityClient()
    key = os.environ.get(ENV_KEY, "").strip()
    if not key:
        _die(2, f"{ENV_KEY} is not set — paid checks need a funded Base wallet.",
             hint=f"export {ENV_KEY}=0x…   then: python3 verity.py address   (fund it with USDC on Base)",
             free_alternative="`receipt` verification is free and needs no wallet.")
    try:
        from verity_guard import x402_payer
        return VerityClient(http=x402_payer(key))
    except ImportError:
        _die(3, INSTALL_HINT)
    except Exception as e:  # bad key, etc. — never echo the key itself
        _die(1, f"could not build the x402 payer: {type(e).__name__}: {str(e)[:160]}")


def main() -> None:
    p = argparse.ArgumentParser(prog="verity", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in COMMANDS:
        s = sub.add_parser(name)
        s.add_argument("text", help="the action / claim / content to check")
        s.add_argument("--context", default=None, help="anything that helps judge it")
        s.add_argument("--policy", default=None, help="check only: the rule to enforce")
        s.add_argument("--tier", default=None, help="quick (cheapest) | standard/grounded | pro")

    r = sub.add_parser("receipt", help="FREE — re-verify a signed receipt (no wallet)")
    r.add_argument("path", help="path to a receipt JSON file, or - for stdin")

    sub.add_parser("address", help="print the wallet address to fund with USDC on Base")

    a = p.parse_args()

    if a.cmd == "address":
        key = os.environ.get(ENV_KEY, "").strip()
        if not key:
            _die(2, f"{ENV_KEY} is not set.")
        try:
            from verity_guard import wallet_address
        except ImportError:
            _die(3, INSTALL_HINT)
        json.dump({"address": wallet_address(key),
                   "fund_with": "USDC on Base mainnet (eip155:8453)"}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    if a.cmd == "receipt":
        raw = sys.stdin.read() if a.path == "-" else open(a.path, encoding="utf-8").read()
        res = _client(paid=False).verify_receipt(json.loads(raw))
        json.dump(dict(res), sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        raise SystemExit(0 if res.get("valid") else 3)

    method, field, tiers, default_tier = COMMANDS[a.cmd]
    tier = a.tier or default_tier
    if tier not in tiers:
        _die(1, f"{a.cmd}: unknown tier {tier!r}", allowed=list(tiers))

    kwargs: dict = {"tier": tier, "context": a.context}
    if a.cmd == "check":
        kwargs["policy"] = a.policy
    elif a.policy:
        _die(1, "--policy applies to `check` only")

    res = getattr(_client(paid=True), method)(a.text, **kwargs)

    # Fail-closed reporting: a non-verdict must never be printed as if it were one.
    if res.get("error"):
        _die(3, str(res["error"]), endpoint=res.get("endpoint"),
             note="The check did NOT happen. Do not proceed as if this returned allow.")
    if res.payment_required:
        _die(2, f"payment required ({res.price}) — the check was not performed",
             price=res.price,
             hint=f"fund the address from `verity.py address` with USDC on Base, or set {ENV_KEY}")

    json.dump(dict(res), sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    raise SystemExit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        _die(3, "interrupted — no verdict")
    except Exception as e:  # never crash with a stack trace the agent might misread
        _die(3, f"{type(e).__name__}: {str(e)[:200]}",
             note="The check did NOT happen. Do not proceed as if this returned allow.")
