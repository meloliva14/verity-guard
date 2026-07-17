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

from decimal import Decimal
from typing import Any

BASE_MAINNET = "eip155:8453"
# Native USDC on Base — the only asset VerityLayer prices in, and the only one we sign for.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_DECIMALS = 6

# Hard ceiling on what a single call may pay, in USDC. Every VerityLayer tier is <= $0.35,
# so this is ~3x headroom and still refuses anything absurd.
#
# This exists because an x402 client with no policies pays WHATEVER the 402 challenge names,
# bounded only by the wallet balance. The endpoint is env-overridable (VERITY_ENGINE_URL /
# VERITY_SUITE_URL), so a typo, a hijacked DNS answer, or a compromised host could return a
# challenge for 9,999 USDC and the payer would sign it — while the caller was told the price
# was $0.02. A cap turns "drain the wallet" into "the payment is refused".
DEFAULT_MAX_PRICE_USDC = "1.00"

# Names the ACTUAL missing module. The old text said "install verity-guard[x402]" — which was
# the command the user had just run (the extra shipped bare `x402`, so web3 was never pulled
# in and every payer raised ImportError). An install hint that recommends the failing command
# turns a one-line fix into an unwinnable loop, so it repeats what the exception really said.
def _install_hint(err: BaseException) -> str:
    return (
        f"The x402 payer could not load its dependencies: {err}\n"
        "    pip install 'verity-guard[x402]'\n"
        "This extra pulls x402[evm] (which brings web3/eth-abi/eth-keys) + eth-account. None of\n"
        "them are needed for the free receipt checks — only for signing payments.\n"
        "If you installed verity-guard[x402] BEFORE 0.2.2, the extra was missing web3: upgrade\n"
        "with  pip install -U 'verity-guard[x402]'"
    )


def _atomic_usdc(price: str | float | Decimal) -> int:
    """Dollars -> USDC minor units (6dp), rounded down."""
    return int((Decimal(str(price)) * (10 ** USDC_DECIMALS)).to_integral_value(rounding="ROUND_FLOOR"))


def _chain_id(network: str) -> int | None:
    """CAIP-2 'eip155:8453' -> 8453."""
    try:
        return int(str(network).split(":")[-1])
    except (ValueError, TypeError):
        return None


def _spend_policies(network: str, max_price: str | float | Decimal,
                    assets: "set[str] | None" = None) -> list:
    """The three guards every payer must carry: a price ceiling, a network pin, an asset pin.

    NETWORK PIN — register_exact_evm_client(networks=...) pins only the x402 **v2** registry
    and then unconditionally registers the same signing key across all 19 legacy **v1**
    networks (base-sepolia, polygon, avalanche, sei, ...). A payer explicitly pinned to Base
    would still happily sign a v1 challenge naming polygon — and v1 challenges ride in the
    response BODY, so any endpoint can emit one. This policy rejects every requirement that
    is not on the pinned chain, for v1 and v2 alike.

    ASSET PIN — without it the ceiling is a number with no unit. ``max_amount`` compares raw
    minor units against a bound computed in USDC's 6 decimals, so a challenge on the PINNED
    chain naming a different EIP-3009 token slips a far larger transfer under the same
    integer: cbBTC has 8 decimals, so ``1000000`` reads as "$1.00" to the cap and means
    0.01 BTC. It only lands if the wallet actually holds that token (a USDC-only wallet is
    unaffected), but we state the guarantee unconditionally — "a hostile 402 can't name its
    own price" — and a ceiling the counterparty gets to denominate is not a ceiling.
    """
    from x402.client_base import max_amount
    from x402.mechanisms.evm import V1_NETWORK_CHAIN_IDS

    cid = _chain_id(network)
    allowed = {network}
    if cid is not None:  # the v1 aliases for the same chain (e.g. 8453 -> "base")
        allowed |= {n for n, c in V1_NETWORK_CHAIN_IDS.items() if int(c) == cid}

    allowed_assets = {a.lower() for a in (assets or {USDC_BASE})}

    def only_pinned_network(version: int, reqs: list) -> list:
        return [r for r in reqs if getattr(r, "network", None) in allowed]

    def only_pinned_asset(version: int, reqs: list) -> list:
        return [r for r in reqs
                if isinstance(getattr(r, "asset", None), str)
                and r.asset.lower() in allowed_assets]

    # Asset before amount: the cap only means anything once its unit is pinned.
    return [only_pinned_network, only_pinned_asset, max_amount(_atomic_usdc(max_price))]


def _account(private_key: str) -> Any:
    """Load an eth_account from a hex private key. Never logged, never transmitted."""
    try:
        from eth_account import Account
    except ImportError as e:  # pragma: no cover - depends on optional extra
        raise ImportError(_install_hint(e)) from e
    key = (private_key or "").strip()
    if not key:
        raise ValueError("empty private key — set VERITY_WALLET_KEY to a funded Base wallet")
    if not key.startswith("0x"):
        key = "0x" + key
    return Account.from_key(key)


def wallet_address(private_key: str) -> str:
    """Public address for ``private_key`` — fund THIS address with USDC on Base mainnet."""
    return _account(private_key).address


def x402_payer(private_key: str, *, network: str = BASE_MAINNET,
               max_price_usdc: str | float | Decimal = DEFAULT_MAX_PRICE_USDC,
               assets: "set[str] | None" = None,
               **session_kwargs: Any) -> Any:
    """A ``requests.Session`` that transparently settles VerityLayer's 402 challenges.

    Hand it straight to :class:`~verity_guard.client.VerityClient` as ``http=``.

    Capped by default: a call may never pay more than ``max_price_usdc`` (default $1.00),
    and may only pay on ``network``. A challenge that breaches either is refused rather than
    signed — the payment simply does not happen.
    """
    try:
        from x402 import x402ClientSync
        from x402.http.clients.requests import x402_requests
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact import register_exact_evm_client
    except ImportError as e:
        raise ImportError(_install_hint(e)) from e

    client = x402ClientSync()
    register_exact_evm_client(client, EthAccountSigner(_account(private_key)), networks=network,
                              policies=_spend_policies(network, max_price_usdc, assets))
    return x402_requests(client, **session_kwargs)


def async_x402_payer(private_key: str, *, network: str = BASE_MAINNET,
                     max_price_usdc: str | float | Decimal = DEFAULT_MAX_PRICE_USDC,
                     assets: "set[str] | None" = None,
                     **httpx_kwargs: Any) -> Any:
    """An ``httpx.AsyncClient`` that transparently settles VerityLayer's 402 challenges.

    Hand it straight to :class:`~verity_guard.client.AsyncVerityClient` as ``http=``.
    Same guards as :func:`x402_payer`: a price ceiling and a network pin.
    """
    try:
        from x402 import x402Client
        from x402.http.clients.httpx import wrapHttpxWithPayment
        from x402.mechanisms.evm import EthAccountSigner
        from x402.mechanisms.evm.exact import register_exact_evm_client
    except ImportError as e:
        raise ImportError(_install_hint(e)) from e

    client = x402Client()
    register_exact_evm_client(client, EthAccountSigner(_account(private_key)), networks=network,
                              policies=_spend_policies(network, max_price_usdc, assets))
    return wrapHttpxWithPayment(client, **httpx_kwargs)
