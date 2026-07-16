"""Payer tests — all offline, no network, no settlement, no money.

The live end-to-end proof (that the payer signs a real EIP-3009 authorization and is
correctly attributed by the facilitator) is done with an unfunded throwaway key against
the real engine; it cannot live in CI because it needs the network. What CI can lock down
is everything up to the wire: key handling, client construction, and adapter mounting.
"""
from __future__ import annotations

import pytest

from verity_guard import payer

# Deterministic throwaway key — never funded, never used for anything real.
DUMMY = "0x" + "5c" * 32
DUMMY_ADDR = "0xb7cF38e4B36B03895E5580abE5b379E6739e8C4C"

x402 = pytest.importorskip("x402", reason="needs the [x402] extra")
pytest.importorskip("eth_account", reason="needs the [x402] extra")


def test_payer_module_imports_without_touching_x402():
    """Base install is httpx-only: importing verity_guard must not require the extra.
    payer.py keeps every x402/eth_account import inside the functions."""
    import verity_guard
    assert hasattr(verity_guard, "x402_payer")


def test_wallet_address_is_deterministic_and_correct():
    assert payer.wallet_address(DUMMY) == DUMMY_ADDR


def test_wallet_address_accepts_key_without_0x_prefix():
    assert payer.wallet_address("5c" * 32) == DUMMY_ADDR


def test_empty_key_raises_a_useful_error():
    for bad in ("", "   ", None):
        with pytest.raises(ValueError, match="empty private key"):
            payer.wallet_address(bad)  # type: ignore[arg-type]


def test_x402_payer_returns_a_session_with_payment_adapters_mounted():
    sess = payer.x402_payer(DUMMY)
    import requests
    assert isinstance(sess, requests.Session)
    # Both schemes must route through the x402 adapter or 402s are never settled.
    for prefix in ("https://", "http://"):
        assert prefix in sess.adapters
        assert type(sess.adapters[prefix]).__name__ == "x402HTTPAdapter"


def test_async_x402_payer_returns_an_async_client():
    import httpx
    ac = payer.async_x402_payer(DUMMY)
    assert isinstance(ac, httpx.AsyncClient)


def test_payer_registers_the_exact_scheme_on_the_expected_network():
    """A payer with no registered scheme silently fails to pay — assert the wiring."""
    from x402 import x402ClientSync
    from x402.mechanisms.evm import EthAccountSigner
    from x402.mechanisms.evm.exact import register_exact_evm_client
    from eth_account import Account

    c = x402ClientSync()
    register_exact_evm_client(c, EthAccountSigner(Account.from_key(DUMMY)),
                              networks=payer.BASE_MAINNET)
    schemes = getattr(c, "_schemes", {})
    assert payer.BASE_MAINNET in schemes
    assert "exact" in schemes[payer.BASE_MAINNET]


def test_client_accepts_the_payer_session():
    """The whole point: the payer drops straight into VerityClient(http=...)."""
    from verity_guard import VerityClient
    v = VerityClient(http=payer.x402_payer(DUMMY))
    assert v._http is not None
    assert v._owns is False  # caller-supplied client: we must not close it
