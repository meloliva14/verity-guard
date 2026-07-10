"""Offline tests — no network, no x402, no spend. Run: python tests/test_client.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from verity_guard import VerityClient, VerityResult, format_verdict, guard, BlockedAction  # noqa: E402


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self.text = payload if isinstance(payload, str) else json.dumps(payload)
        self.headers = {}


class FakeHTTP:
    """Records requests and replays queued responses by URL suffix."""
    def __init__(self, routes):
        self.routes = routes            # {url_suffix: FakeResp}
        self.calls = []

    def post(self, url, json=None, headers=None):
        self.calls.append((url, json, headers))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return FakeResp(404, {"error": "no fake route"})


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    if not cond:
        raise AssertionError(name)


def test_guard_block_200():
    verdict = {"decision": "block", "risk": 0.9, "reasons": ["policy violation"],
               "concerns": ["irreversible"], "safer_alternative": "halt and verify",
               "receipt": {"receipt_id": "abc-123", "key_id": "ed25519:ea7c47db794239a8"}}
    http = FakeHTTP({"/check/quick": FakeResp(200, verdict)})
    v = VerityClient(http=http, affiliate_id="testref")
    r = v.guard("Wire $4,000 to 0x9a3f", policy="No new payees.")
    check("guard returns VerityResult", isinstance(r, VerityResult))
    check("decision=block", r.decision == "block")
    check("blocked property", r.blocked is True and r.allowed is False and r.flagged is True)
    check("risk surfaced", r.risk == 0.9)
    check("receipt present", r.receipt and r.receipt["receipt_id"] == "abc-123")
    check("safer_alternative", r.safer_alternative == "halt and verify")
    check("price defaulted", r.price == "$0.02")
    # routing + affiliate header
    url, body, headers = http.calls[-1]
    check("routed to suite /check/quick", url == "https://suite.veritylayer.dev/check/quick")
    check("body has action+policy, no None context", body == {"action": "Wire $4,000 to 0x9a3f", "policy": "No new payees."})
    check("affiliate header sent", headers.get("X-Verity-Ref") == "testref")


def test_guard_402_payment_required():
    http = FakeHTTP({"/check/quick": FakeResp(402, {"accepts": [{"scheme": "exact"}]})})
    v = VerityClient(http=http)
    r = v.guard("do a thing")
    check("payment_required flagged", r.payment_required is True)
    check("price on 402", r.price == "$0.02")
    check("challenge attached", isinstance(r.get("challenge"), dict))
    check("decision None on 402", r.decision is None)


def test_verify_tier_routing():
    http = FakeHTTP({"/verify": FakeResp(200, {"verdict": "supported", "confidence": 0.99}),
                     "/verify/quick": FakeResp(200, {"verdict": "uncertain", "confidence": 0.5})})
    v = VerityClient(http=http)
    r1 = v.verify("water boils at 100C")           # default grounded -> /verify
    check("default grounded routes to /verify", http.calls[-1][0].endswith("/verify"))
    check("verify verdict via .decision", r1.decision == "supported")
    check("supported => allowed", r1.allowed is True)
    r2 = v.verify("x", tier="quick")               # -> /verify/quick
    check("quick routes to /verify/quick", http.calls[-1][0].endswith("/verify/quick"))
    check("uncertain => not allowed (fail-closed)", r2.allowed is False)


def test_verify_receipt_free():
    http = FakeHTTP({"/receipt/verify": FakeResp(200, {"valid": True, "reason": "sig ok"})})
    v = VerityClient(http=http)
    r = v.verify_receipt({"receipt_id": "abc-123", "signature": "deadbeef"})
    check("verify_receipt valid", r.valid is True)
    check("free price label", r.price == "$0.00 (free)")
    check("hits engine /receipt/verify", http.calls[-1][0] == "https://api.veritylayer.dev/receipt/verify")
    # string receipt also accepted
    r2 = v.verify_receipt(json.dumps({"receipt_id": "x"}))
    check("string receipt parsed", r2.valid is True)


def test_unknown_tier_raises():
    v = VerityClient(http=FakeHTTP({}))
    try:
        v.guard("x", tier="nope")
        check("unknown tier should raise", False)
    except ValueError:
        check("unknown tier raises ValueError", True)


def test_network_error_is_honest():
    class Boom:
        def post(self, *a, **k):
            raise RuntimeError("connection refused")
    v = VerityClient(http=Boom())
    r = v.guard("x")
    check("network error => error field, no fabricated verdict", r.get("error") and r.decision is None)


def test_guard_decorator():
    verdict = {"decision": "block", "risk": 0.9, "safer_alternative": "don't"}
    http = FakeHTTP({"/check/quick": FakeResp(200, verdict)})
    v = VerityClient(http=http)

    @guard(v, policy="no payees")
    def wire(to, amount):
        return f"sent {amount} to {to}"

    try:
        wire("0xabc", 4000)
        check("blocked call should raise BlockedAction", False)
    except BlockedAction as e:
        check("BlockedAction raised on block", "blocked" in str(e).lower())

    # allow path runs the function
    http.routes["/check/quick"] = FakeResp(200, {"decision": "allow", "risk": 0.1})
    check("allow path runs fn", wire("0xabc", 5) == "sent 5 to 0xabc")


def test_format_verdict():
    r = VerityResult({"decision": "block", "risk": 0.9, "reasons": ["a", "b"],
                      "safer_alternative": "stop", "receipt": {"receipt_id": "rid1"}})
    s = format_verdict(r)
    check("format has decision", "decision=block" in s)
    check("format has receipt id", "rid1" in s)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    print(f"running {len(tests)} offline test groups...\n")
    for t in tests:
        print(t.__name__)
        t()
    print("\nALL OFFLINE TESTS PASSED")
