"""One-line x402 payers — the missing step between ``pip install`` and a real verdict.

VerityLayer's paid routes answer HTTP 402 until settled. This SDK deliberately holds no
key and never pays on your behalf: you hand it an HTTP client that *can* pay. Wiring that
up by hand (x402 client + EVM signer + scheme registration + a payment transport) is the
step where most people stopped — ``verity-guard[x402]`` shipped the dependencies and no
way to use them. This module closes that gap:

    import os
    from verity_guard import VerityClient
    from verity_guard.payer import x402_payer

    v = VerityClient(http=x402_payer(os.environ["VERITY_WALLET_KEY"]))
    print(v.guard("Wire $4,000 to 0x9a3f… (invoice #221)").decision)   # e.g. "block"

Async:

    from verity_guard import AsyncVerityClient
    from verity_guard.payer import async_x402_payer

    v = AsyncVerityClient(http=async_x402_payer(os.environ["VERITY_WALLET_KEY"]))

Key handling, stated plainly: the key stays in your process. It is used locally to sign an
EIP-3009 ``transferWithAuthorization`` for the exact disclosed amount; VerityLayer only ever
receives that signature. Nothing here transmits, logs, or persists the key — and a key
passed on a command line would leak into process lists and shell history, so read it from
the environment instead. Fund the address ``wallet_address(key)`` with USDC on Base.
"""
from __future__ import annotations

from typing import Any

BASE_MAINNET = "eip155:8453"

_INSTALL_HINT = (
    "The x402 payer needs two extra packages. Install them with:\n"
    "    pip install 'verity-guard[x402]'\n"
    "(pulls in x402 + eth-account; neither is required for the free receipt checks)"
)


def _account(private_key: str) -> Any:
    """Load an eth_account from a hex private key. Never logged, never transmitted."""
    try:
        from eth_account import Account
    except ImportError as e:  # pragma: no cover - depends on optional extra
        raise ImportError(_INSTALL_HINT) from e
    key = (private_key or "").strip()
    if not key:
        raise ValueError("empty private key — set VERITY_WALLET_KEY to a funded Base wallet")
    if not key.startswith("0x"):
        key = "0x" + key
    return Account.from_key(key)


def wallet_address(private_key: str) -> str:
    """Public address for ``private_key`` — fund THIS address with USDC on Base mainnet."""
    return _account(private_key).address


def x402_payer(private_key: str, *, network: str = BASE_MAINNET, **session_kwargs: Any) -> Any:
    """A ``requests.Session`` that transparently settles VerityLayer's 402 challenges.

    Hand it straight to :class:`~verity_guard.client.VerityClient` as ``http=``.
    Pays only the exact amount disclosed in each challenge, per call.
    """
    try:
        from x402 import x402ClientSync
        from x402.http.clients.requests import x402_requests
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact import register_exact_evm_client
    except ImportError as e:
        raise ImportError(_INSTALL_HINT) from e

    client = x402ClientSync()
    register_exact_evm_client(client, EthAccountSigner(_account(private_key)), networks=network)
    return x402_requests(client, **session_kwargs)


def async_x402_payer(private_key: str, *, network: str = BASE_MAINNET,
                     **httpx_kwargs: Any) -> Any:
    """An ``httpx.AsyncClient`` that transparently settles VerityLayer's 402 challenges.

    Hand it straight to :class:`~verity_guard.client.AsyncVerityClient` as ``http=``.
    """
    try:
        from x402 import x402Client
        from x402.http.clients.httpx import wrapHttpxWithPayment
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact import register_exact_evm_client
    except ImportError as e:
        raise ImportError(_INSTALL_HINT) from e

    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(_account(private_key)), networks=network)
    return wrapHttpxWithPayment(client, **httpx_kwargs)
