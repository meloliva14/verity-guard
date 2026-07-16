"""VerityLayer client — the keyless verify-before-you-act core.

Doctrine (identical to the VerityLayer MCP server): this client holds NO private
key and makes NO payment. VerityLayer's paid routes answer HTTP 402 until settled;
you pass in an x402-capable HTTP client (one that wraps your wallet) and it settles
the disclosed USDC micro-payment transparently. If you pass no payer, a 402 is
surfaced as a structured ``payment_required`` result so your own layer can handle it.

Two clients, same surface:
    VerityClient        — synchronous (LangChain / CrewAI tools, scripts)
    AsyncVerityClient   — asyncio (LangGraph, OpenAI Agents SDK, async apps)

Every paid verdict carries an Ed25519-signed receipt; verify_receipt() checks one
for FREE against VerityLayer's published public key.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Union

ENGINE_DEFAULT = "https://api.veritylayer.dev"
SUITE_DEFAULT = "https://suite.veritylayer.dev"

# kind -> (host, {tier: (path, disclosed_price)}, default_tier). Prices are the
# disclosed defaults; the authoritative price is always the live x402 challenge.
_ROUTES: dict[str, tuple[str, dict[str, tuple[str, str]], str]] = {
    "verify": ("engine", {
        "quick": ("/verify/quick", "$0.02"),
        "grounded": ("/verify", "$0.25"),
        "pro": ("/verify/pro", "$0.35"),
    }, "grounded"),
    "guard": ("suite", {
        "quick": ("/check/quick", "$0.02"),
        "standard": ("/check", "$0.08"),
        "pro": ("/check/pro", "$0.20"),
    }, "quick"),
    "injection": ("suite", {
        "quick": ("/sentinel/quick", "$0.02"),
        "standard": ("/sentinel", "$0.06"),
        "pro": ("/sentinel/pro", "$0.15"),
    }, "quick"),
    "moderate": ("suite", {
        "quick": ("/sieve/quick", "$0.02"),
        "standard": ("/sieve", "$0.06"),
        "pro": ("/sieve/pro", "$0.15"),
    }, "quick"),
    "redact": ("suite", {
        "quick": ("/redact/quick", "$0.02"),
        "standard": ("/redact", "$0.06"),
        "pro": ("/redact/pro", "$0.15"),
    }, "quick"),
}


class VerityResult(dict):
    """The raw verdict dict plus typed convenience accessors.

    Subclasses ``dict`` so every field the service returns is always reachable,
    even ones added after this SDK was published — nothing is silently dropped.
    """

    @property
    def receipt(self) -> Optional[dict]:
        return self.get("receipt")

    @property
    def price(self) -> Optional[str]:
        return self.get("price")

    @property
    def payment_required(self) -> bool:
        return bool(self.get("payment_required"))

    @property
    def valid(self) -> Optional[bool]:  # verify_receipt()
        return self.get("valid")

    @property
    def decision(self) -> Optional[str]:
        return self.get("decision") or self.get("verdict")

    @property
    def risk(self) -> Optional[float]:
        r = self.get("risk")
        return r if r is not None else self.get("confidence")

    @property
    def reasons(self) -> list:
        return self.get("reasons") or []

    @property
    def concerns(self) -> list:
        return self.get("concerns") or []

    @property
    def safer_alternative(self) -> Optional[str]:
        return self.get("safer_alternative")

    @staticmethod
    def _norm(decision: Any) -> str:
        """Compare decisions case- and whitespace-insensitively.

        Exact matching is a live hazard here: ``blocked`` is what every gate consults, so a
        decision of ``"BLOCK"`` or ``" block"`` would compare unequal to ``"block"``, read
        as not-blocked, and execute the very action the verdict meant to stop.
        """
        return decision.strip().lower() if isinstance(decision, str) else ""

    @property
    def allowed(self) -> bool:
        """True for a clearly-safe verdict (allow / publish / clean / supported)."""
        return self._norm(self.decision) in ("allow", "publish", "clean", "supported")

    @property
    def blocked(self) -> bool:
        return self._norm(self.decision) == "block"

    @property
    def flagged(self) -> bool:
        """True if the verdict is anything other than clearly-safe (fail-closed default)."""
        return not self.allowed

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        if self.payment_required:
            return f"VerityResult(payment_required, price={self.price!r})"
        return (f"VerityResult(decision={self.decision!r}, risk={self.risk!r}, "
                f"receipt={'yes' if self.receipt else 'no'})")


class VerityError(RuntimeError):
    """Raised by the *_or_raise helpers when a call did not produce a verdict."""


@dataclass
class _Prepared:
    url: str
    body: dict
    price: str


def _prepare(kind: str, tier: Optional[str], engine: str, suite: str, fields: Mapping[str, Any]) -> _Prepared:
    host, tiers, default = _ROUTES[kind]
    t = tier or default
    if t not in tiers:
        raise ValueError(f"{kind}: unknown tier {t!r} (choose one of {sorted(tiers)})")
    path, price = tiers[t]
    base = (engine if host == "engine" else suite).rstrip("/")
    body = {k: v for k, v in fields.items() if v is not None}
    return _Prepared(url=base + path, body=body, price=price)


def _finish(price: str, status: int, text: str) -> VerityResult:
    if status == 402:
        try:
            challenge: Any = json.loads(text)
        except Exception:
            challenge = text[:1000]
        return VerityResult({
            "payment_required": True,
            "price": price,
            "currency": "USDC",
            "network": "Base mainnet (eip155:8453)",
            "detail": (f"This VerityLayer check is paid per call via x402 ({price} USDC on Base). "
                       "Settle the disclosed micro-payment with your x402-capable client and retry. "
                       "This SDK holds no key and never pays on your behalf."),
            "challenge": challenge,
        })
    try:
        data = json.loads(text)
    except Exception:
        return VerityResult({"error": f"unexpected_status_{status}", "body": text[:300], "price": price})
    if isinstance(data, dict):
        data.setdefault("price", price)
        return VerityResult(data)
    return VerityResult({"result": data, "price": price})


class _Base:
    def __init__(self, *, engine: str = ENGINE_DEFAULT, suite: str = SUITE_DEFAULT,
                 affiliate_id: Optional[str] = None) -> None:
        self.engine = engine.rstrip("/")
        self.suite = suite.rstrip("/")
        self.affiliate_id = affiliate_id

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.affiliate_id:
            # Pure routing metadata for a future referral program; never changes price/verdict.
            h["X-Verity-Ref"] = str(self.affiliate_id)
        return h


class VerityClient(_Base):
    """Synchronous VerityLayer client.

    Pass ``http`` = any x402-wrapped ``httpx.Client`` or ``requests.Session`` (it
    settles 402s for you). Pass nothing to get plain HTTP that surfaces 402s.
    """

    def __init__(self, http: Any = None, *, engine: str = ENGINE_DEFAULT, suite: str = SUITE_DEFAULT,
                 timeout: float = 90.0, affiliate_id: Optional[str] = None) -> None:
        super().__init__(engine=engine, suite=suite, affiliate_id=affiliate_id)
        if http is None:
            import httpx
            http = httpx.Client(timeout=timeout)
            self._owns = True
        else:
            self._owns = False
        self._http = http

    def _call(self, kind: str, tier: Optional[str], fields: Mapping[str, Any]) -> VerityResult:
        p = _prepare(kind, tier, self.engine, self.suite, fields)
        try:
            r = self._http.post(p.url, json=p.body, headers=self._headers())
        except Exception as e:  # network/timeout — fail honestly, never fabricate a verdict
            return VerityResult({"error": f"verity_unreachable: {str(e)[:160]}", "endpoint": p.url, "price": p.price})
        return _finish(p.price, r.status_code, r.text)

    # ── the checks ────────────────────────────────────────────────────────────
    def guard(self, action: str, *, context: Optional[str] = None, policy: Optional[str] = None,
              tier: Optional[str] = None) -> VerityResult:
        """THE FLAGSHIP. allow / review / block for a proposed action, with a signed receipt."""
        return self._call("guard", tier, {"action": action, "context": context, "policy": policy})

    def verify(self, claim: str, *, context: Optional[str] = None, tier: Optional[str] = None) -> VerityResult:
        return self._call("verify", tier, {"claim": claim, "context": context})

    def detect_injection(self, content: str, *, context: Optional[str] = None,
                         tier: Optional[str] = None) -> VerityResult:
        return self._call("injection", tier, {"content": content, "context": context})

    def moderate(self, content: str, *, policy: Optional[str] = None, context: Optional[str] = None,
                 tier: Optional[str] = None) -> VerityResult:
        return self._call("moderate", tier, {"content": content, "policy": policy, "context": context})

    def redact(self, payload: str, *, context: Optional[str] = None, tier: Optional[str] = None) -> VerityResult:
        return self._call("redact", tier, {"payload": payload, "context": context})

    def verify_receipt(self, receipt: Union[dict, str]) -> VerityResult:
        """FREE — verify an Ed25519 receipt against VerityLayer's public key."""
        body = json.loads(receipt) if isinstance(receipt, str) else receipt
        try:
            r = self._http.post(self.engine + "/receipt/verify", json=body, headers=self._headers())
        except Exception as e:
            return VerityResult({"valid": False, "error": f"verity_unreachable: {str(e)[:160]}"})
        return _finish("$0.00 (free)", r.status_code, r.text)

    def close(self) -> None:
        if self._owns:
            try:
                self._http.close()
            except Exception:
                pass

    def __enter__(self) -> "VerityClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncVerityClient(_Base):
    """Asyncio VerityLayer client. Pass ``http`` = an x402-wrapped ``httpx.AsyncClient``."""

    def __init__(self, http: Any = None, *, engine: str = ENGINE_DEFAULT, suite: str = SUITE_DEFAULT,
                 timeout: float = 90.0, affiliate_id: Optional[str] = None) -> None:
        super().__init__(engine=engine, suite=suite, affiliate_id=affiliate_id)
        if http is None:
            import httpx
            http = httpx.AsyncClient(timeout=timeout)
            self._owns = True
        else:
            self._owns = False
        self._http = http

    async def _call(self, kind: str, tier: Optional[str], fields: Mapping[str, Any]) -> VerityResult:
        p = _prepare(kind, tier, self.engine, self.suite, fields)
        try:
            r = await self._http.post(p.url, json=p.body, headers=self._headers())
        except Exception as e:
            return VerityResult({"error": f"verity_unreachable: {str(e)[:160]}", "endpoint": p.url, "price": p.price})
        return _finish(p.price, r.status_code, r.text)

    async def guard(self, action: str, *, context: Optional[str] = None, policy: Optional[str] = None,
                    tier: Optional[str] = None) -> VerityResult:
        return await self._call("guard", tier, {"action": action, "context": context, "policy": policy})

    async def verify(self, claim: str, *, context: Optional[str] = None,
                     tier: Optional[str] = None) -> VerityResult:
        return await self._call("verify", tier, {"claim": claim, "context": context})

    async def detect_injection(self, content: str, *, context: Optional[str] = None,
                               tier: Optional[str] = None) -> VerityResult:
        return await self._call("injection", tier, {"content": content, "context": context})

    async def moderate(self, content: str, *, policy: Optional[str] = None, context: Optional[str] = None,
                       tier: Optional[str] = None) -> VerityResult:
        return await self._call("moderate", tier, {"content": content, "policy": policy, "context": context})

    async def redact(self, payload: str, *, context: Optional[str] = None,
                     tier: Optional[str] = None) -> VerityResult:
        return await self._call("redact", tier, {"payload": payload, "context": context})

    async def verify_receipt(self, receipt: Union[dict, str]) -> VerityResult:
        body = json.loads(receipt) if isinstance(receipt, str) else receipt
        try:
            r = await self._http.post(self.engine + "/receipt/verify", json=body, headers=self._headers())
        except Exception as e:
            return VerityResult({"valid": False, "error": f"verity_unreachable: {str(e)[:160]}"})
        return _finish("$0.00 (free)", r.status_code, r.text)

    async def aclose(self) -> None:
        if self._owns:
            try:
                await self._http.aclose()
            except Exception:
                pass

    async def __aenter__(self) -> "AsyncVerityClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()
